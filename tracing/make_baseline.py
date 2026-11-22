#!/usr/bin/env python3
"""PERSON A - the deterministic trace-to-profile BASELINE.

Rule: allow exactly the syscalls that appear in the trace, deny everything else.
(Same idea as Minijail's generate_seccomp_policy.py, simplified to names only.)

Writes:
    policies/baseline/<program>/baseline__training.json   from the clean training trace
    policies/baseline/<program>/baseline__poisoned.json   from the poisoned trace - shows that
                                                          the baseline blindly copies injected calls

Runs anywhere (only reads summary_*.json files).
Usage:  python3 tracing/make_baseline.py [--data DIR]
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sandboxlab import paths, policy  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, default=paths.DATA)
    ap.add_argument("--out", type=Path, default=paths.POLICIES / "baseline")
    args = ap.parse_args()

    n = 0
    for prog_dir in sorted(p for p in args.data.iterdir() if p.is_dir() and p.name != "probe"):
        for trace_used in ("training", "poisoned"):
            summ_file = prog_dir / f"summary_{trace_used}.json"
            if not summ_file.exists():
                continue
            summ = json.loads(summ_file.read_text())
            doc = {
                "program": prog_dir.name,
                "source": "baseline",
                "prompt": None,
                "repeat": 0,
                "trace_used": trace_used,
                "allow": list(summ["counts"].keys()),
                "json_valid": True,
                "extraction": "n/a",
                "raw_output": "",
                "note": "allow exactly the syscalls seen in the trace (default deny)",
            }
            out = args.out / prog_dir.name / f"baseline__{trace_used}.json"
            policy.save_policy(doc, out)
            print(f"  {prog_dir.name:<11} {trace_used:<9} {len(doc['allow']):>3} syscalls -> {out.relative_to(paths.ROOT)}")
            n += 1
    print(f"wrote {n} baseline policies")


if __name__ == "__main__":
    main()
