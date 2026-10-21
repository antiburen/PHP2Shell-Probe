# php2shell-probe.py

Defensive probe for the PHP multipart parser vulnerability

CVE-2026-109618 · CVSS 9.2 CVE-2026-109619 PHP \< 8.3.36 / 8.4.27

A single HTTP request can crash a PHP-FPM worker by sending thousands of fake MIME headers inside one multipart part. The vulnerable `multipart_buffer_headers()` in `rfc1867.c` stores every header without limit — 5 bytes on the wire become \~268 bytes in PHP memory, a \~53× amplification. Once the worker exceeds `memory_limit`, `zend_bailout()` fires a `longjmp` that corrupts state, opening the door to use-after-free and RCE.

X:y\\r\\n × N → N × 5 bytes on wire → N × \~268 bytes in PHP → OOM → bailout → UAF

This script probes **your own** PHP applications to determine whether the OOM threshold is reachable. It does not attempt exploitation — it confirms the preconditions.

⚠

**This tool is not weaponized.** It only confirms whether the OOM crash is reachable (steps 1–3 below). It does not perform heap manipulation, achieve code execution, or attempt any post-crash exploitation. A 502 from T9 means the preconditions for RCE are met — not that RCE has been demonstrated.

## Quick start

```
# Minimal — just a URL:
python3 -I php2shell-probe.py https://staging.example.com/

# With your app's limits:
python3 -I php2shell-probe.py https://staging.example.com/ \
    --nginx-max 14M --memory-limit 256M --aggressive

# Only the MIME header bomb (the real vector):
python3 -I php2shell-probe.py https://staging.example.com/ --only t9

# Dry run to preview the plan:
python3 -I php2shell-probe.py https://staging.example.com/ --dry-run
```

## Parameters

url

Target URL (base + POST endpoint). The probe sends multipart POSTs here and GETs to the health path.

--health

Health check path. Default: `/up`

--nginx-max

nginx `client_max_body_size`. Default: `14M`. Accepts K/M/G suffixes.

--memory-limit

PHP `memory_limit`. Default: `256M`. Used to estimate the OOM threshold.

--aggressive

Deeper nesting, more concurrency, larger MIME bombs. Pushes toward the OOM boundary.

--only

Comma-separated test IDs to run, e.g. `t6,t9`. Omit to run all.

--dry-run

Show the test plan without sending any payloads.

## Tests

| ID | Vector | What it confirms |
| --- | --- | --- |
| `t1` | Normal POST | Baseline response & latency |
| `t2` | Flat multipart | Many tiny parts → zval/HashTable overhead |
| `t3` | Nested arrays | Deep `a[0][1]...[n]` keys → HashTable tree per level |
| `t4` | upload_progress | Session init/flush callback pressure |
| `t5` | Duplicate headers | Fix deduplicates; vulnerable version stores all |
| `t6` | CL mismatch | `Content-Length < body` → `post_max_size` bypass |
| `t9` | **MIME header bomb** | **The actual PHP2Shell vector.** Fake headers in one part → OOM |
| `t7` | Concurrent | Parallel requests to stress the FPM worker pool |
| `t8` | State integrity | Rapid GETs after amplification → detect corruption |

## Interpreting results

✗

**HTTP 502 on a `mime_bomb_*` test** — OOM confirmed. The FPM worker died mid-request. The `zend_bailout()` path that leads to UAF/RCE is reachable. Patch immediately.

⚠

**CL-bypass confirmed (T6 returns 405/422)** — PHP processes the body beyond the declared `Content-Length`, bypassing the initial `post_max_size` check. The app is technically vulnerable; exploitation depends on whether a large enough body can reach PHP.

✓

**All tests return 4xx, no anomalies** — The OOM threshold wasn't reached with these payloads. This does *not* mean the app is safe — a lower `nginx_max_body` may simply be capping the wire size below what's needed. The only confirmed fix is PHP 8.3.36 / 8.4.27.

## The vulnerability

### Root cause

In PHP \< 8.3.36, `multipart_buffer_headers()` in `main/rfc1867.c` accepts and stores every MIME header in a multipart part without limit:

- No whitelist — any `Key:value` line is stored
- No deduplication — the same header can appear millions of times
- No count limit — only EOF stops the loop
- `fill_buffer()` doesn't recheck `post_max_size` after the initial pass

### Memory math

| Per header | Wire | PHP memory | Amplification |
| --- | --- | --- | --- |
| `X:y\r\n` | 5 bytes | \~268 bytes | \~53× |

The PHP-side cost comes from `estrdup()` + Zend allocator overhead (\~48 bytes), `smart_string` for the value, and `zend_llist_element` (\~24 bytes), plus allocator alignment and bookkeeping.

### What the fix does (8.3.36 / 8.4.27)

- `php_mime_should_save_hdr()` — whitelist: only `Content-Disposition` and `Content-Type` are stored
- `php_mime_get_hdr_value()` — deduplication: a header already present is skipped
- `ZEND_HAS_OOM()` checks after allocations — clean abort instead of `longjmp` corruption
- `post_max_size` recheck in `fill_buffer()` — closes the CL mismatch bypass

## Mitigation (before patching)

Lower `client_max_body_size` in nginx on routes that don't need large uploads. The OOM threshold depends on your `memory_limit`:

| memory_limit | Headers for OOM | Wire size | Safe nginx limit |
| --- | --- | --- | --- |
| `128M` | \~500K | \~2.4 MB | ≤ 2M |
| `256M` | \~950K | \~4.5 MB | ≤ 4M |
| `512M` | \~1.9M | \~9.1 MB | ≤ 8M |

⚠

This is a **band-aid**. A `Content-Length` mismatch can bypass `post_max_size`, though nginx still enforces `client_max_body_size` on the actual bytes received. The only real fix is PHP 8.3.36 / 8.4.27.

## Full attack chain (what an attacker would do next)

This script confirms steps 1–3. An attacker turning this into a working exploit would continue through steps 4–7. Understanding the full chain helps prioritize the urgency of patching.

| # | Step | Description | This tool |
| --- | --- | --- | --- |
| 1 | Bypass `post_max_size` | Send `Content-Length: 0` (or small) with a larger body. `fill_buffer()` doesn't recheck the limit after the initial `content_length` comparison, so PHP reads the full body. | T6 |
| 2 | Memory amplification | Pack hundreds of thousands of fake MIME headers (`X:y\r\n`) into a single multipart part. Each 5-byte header costs \~268 bytes in PHP memory due to `estrdup` + `zend_llist_element` + allocator overhead. | T9 |
| 3 | Trigger OOM | When cumulative allocations exceed `memory_limit`, PHP calls `zend_bailout()` which executes a `longjmp` back up the call stack, skipping destructors and cleanup code. | T9 (502) |
| 4 | Heap grooming | Before the OOM request, send carefully sized requests to arrange the Zend memory allocator's free lists into a predictable layout. The goal is to control which object occupies the memory freed by the corrupted `longjmp`. | Not tested |
| 5 | Type confusion via UAF | The `longjmp` skips `zval_ptr_dtor()` calls, leaving dangling pointers to freed memory. With groomed heap layout, the attacker reclaims that memory with a differently-typed object (e.g. a `zend_string` where a `zend_array` was), achieving type confusion. | Not tested |
| 6 | Arbitrary read/write primitive | The type-confused object lets the attacker read or write arbitrary memory. A common technique: overlap a `zend_string` header with a controlled buffer to fake its length field, gaining out-of-bounds read/write. | Not tested |
| 7 | Code execution | With arbitrary write: overwrite a function pointer in a `zend_class_entry`, a `php_stream_ops` table, or the `__destruct` handler of a still-live object. The next time PHP calls that pointer, the attacker's payload runs as the FPM worker's user. | Not tested |

Steps 4–7 require deep knowledge of the Zend Engine internals and are version-specific (heap layout varies between PHP builds, ASLR adds randomness). Public PoCs for similar `zend_bailout` UAF chains exist in PHP's security history. The gap between "OOM confirmed" and "working exploit" is engineering effort, not a fundamental barrier.

## Requirements

- Python 3.8+
- `requests` (`pip install requests`)

## License

Internal tool. Use exclusively against infrastructure you own and have authorization to test. The developer is not responsible for any damage caused by misuse.
