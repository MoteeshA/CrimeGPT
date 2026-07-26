"""Concurrent AppSail smoke/load harness.

Run only against an approved staging environment:
  TARGET_URL=https://staging.example REQUESTS=500 CONCURRENCY=25 python tests/load_test.py
The production acceptance run must use SCRB-approved representative data and
traffic for 1,100 stations; this script never claims approval by itself.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
import json
import os
import statistics
import time
from urllib.request import urlopen


TARGET = os.environ.get("TARGET_URL", "http://127.0.0.1:5000").rstrip("/")
REQUESTS = int(os.environ.get("REQUESTS", "200"))
CONCURRENCY = int(os.environ.get("CONCURRENCY", "20"))
P95_LIMIT_MS = int(os.environ.get("P95_LIMIT_MS", "1500"))


def hit(_index):
    started = time.perf_counter()
    try:
        with urlopen(f"{TARGET}/health", timeout=int(os.environ.get("REQUEST_TIMEOUT", "15"))) as response:
            body = json.loads(response.read())
            ok = response.status == 200 and body.get("status") == "ok"
        return (time.perf_counter() - started) * 1000, ok, None
    except Exception as exc:
        return (time.perf_counter() - started) * 1000, False, type(exc).__name__


if __name__ == "__main__":
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        results = [future.result() for future in as_completed([pool.submit(hit, index) for index in range(REQUESTS)])]
    latencies = sorted(item[0] for item in results)
    failures = sum(not item[1] for item in results)
    errors = dict(Counter(item[2] for item in results if item[2]))
    p95 = latencies[min(len(latencies) - 1, int(len(latencies) * .95))]
    report = {"target": TARGET, "requests": REQUESTS, "concurrency": CONCURRENCY, "failures": failures, "errors": errors, "average_ms": round(statistics.mean(latencies), 2), "p95_ms": round(p95, 2), "accepted": failures == 0 and p95 <= P95_LIMIT_MS}
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["accepted"] else 1)
