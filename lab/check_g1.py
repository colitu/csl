#!/usr/bin/env python3
"""Check the network G1 gate from cslbench JSON results."""

import json
import statistics
import sys
from pathlib import Path


def read(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not data.get("ok") or data.get("bytes", 0) == 0:
        raise ValueError(f"{path}: download failed: {data.get('error', 'no bytes')}")
    return data


def main(directory):
    root = Path(directory)
    direct = [read(root / f"direct-{n}.json") for n in range(1, 4)]
    csl = [read(root / f"csl-{n}.json") for n in range(1, 4)]
    baseline = statistics.median(x["mbps"] for x in direct)
    measured = statistics.median(x["mbps"] for x in csl)
    if baseline <= 0:
        raise ValueError("direct throughput is zero")
    ratio = measured / baseline
    print(f"Throughput: direct {baseline:.1f} Mbit/s, CSL {measured:.1f} Mbit/s, ratio {ratio:.3f}")
    failures = []
    if ratio < 0.90:
        failures.append("throughput loss exceeds 10%")
    for scenario in ("reset", "blackhole", "freeze"):
        result = read(root / f"{scenario}.json")
        stall = result["max_stall_ns"] / 1e9
        print(f"{scenario}: maximum stall {stall:.3f}s")
        if stall > 2:
            failures.append(f"{scenario} stall exceeds 2s")
    if failures:
        print("G1 FAIL: " + "; ".join(failures))
        return 1
    print("G1 PASS")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: check_g1.py RESULTS_DIRECTORY", file=sys.stderr)
        sys.exit(2)
    try:
        sys.exit(main(sys.argv[1]))
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"G1 FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
