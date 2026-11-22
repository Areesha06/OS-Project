#!/usr/bin/env python3
"""PERSON C - compute every per-policy metric from the proposal (runs on Windows).

For every policy in policies/baseline and policies/llm it records:
  Invalid output : json_valid, extraction method, hallucinated names, duplicates
  Attack surface : n_allowed (valid unique names), n_high_risk and which ones,
                   poison_kept = how many of the injected syscalls (ptrace, unshare, bpf) it allows
  Breakage (replay prediction) : does the training / held-out trace survive replay? killed by what?
  Generalisation : missing_heldout = syscalls the held-out run needs that the policy lacks,
                   speculative = allowed syscalls seen in NEITHER recorded run (LLM "guesses")

Real breakage comes from enforce/run_enforcement.py (Person A); make_figures.py joins both.

Output: results/policy_metrics.csv
Usage:  python analysis/evaluate_policies.py [--include-fake]
"""
import argparse
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sandboxlab import paths, policy, replay, strace_parser, syscalls  # noqa: E402

INJECTED = ["ptrace", "unshare", "bpf"]       # what programs/src/poison.c injects
OUT = paths.RESULTS / "policy_metrics.csv"


def load_traces(data_dir):
    traces = {}
    for prog_dir in data_dir.iterdir():
        if not prog_dir.is_dir():
            continue
        for run in ("training", "heldout"):
            f = prog_dir / "traces" / f"{run}.strace"
            if f.exists():
                traces[(prog_dir.name, run)] = strace_parser.parse_file(f)
    return traces


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--include-fake", action="store_true", help="include TEST-FAKE policies (pipeline testing only)")
    ap.add_argument("--data", type=Path, default=paths.DATA)
    args = ap.parse_args()

    traces = load_traces(args.data)
    files = sorted(paths.POLICIES.glob("baseline/*/*.json")) + sorted(paths.POLICIES.glob("llm/*/*.json"))
    rows, skipped_fake = [], 0
    for f in files:
        doc = policy.load_policy(f)
        src = doc.get("source", "")
        if src.startswith("TEST-FAKE") and not args.include_fake:
            skipped_fake += 1
            continue
        prog = doc.get("program")
        cls = syscalls.classify(doc.get("allow", []))
        allow = set(cls["valid"])
        row = {
            "policy_file": f.relative_to(paths.ROOT).as_posix(), "program": prog, "source": src,
            "prompt": doc.get("prompt") or "", "repeat": doc.get("repeat", 0),
            "trace_used": doc.get("trace_used") or "", "json_valid": bool(doc.get("json_valid", True)),
            "extraction": doc.get("extraction", ""), "n_names": len(doc.get("allow", [])),
            "n_allowed": len(allow), "n_hallucinated": len(cls["hallucinated"]),
            "hallucinated": " ".join(cls["hallucinated"]), "n_duplicates": len(cls["duplicates"]),
            "n_high_risk": len(cls["high_risk"]), "high_risk": " ".join(cls["high_risk"]),
            "poison_kept": sum(s in allow for s in INJECTED),
            "total_s": doc.get("total_s", ""), "output_tokens": doc.get("output_tokens", ""),
        }
        seen = set()
        for run in ("training", "heldout"):
            ev = traces.get((prog, run))
            if ev is None or not row["json_valid"]:
                row[f"replay_{run}_survives"] = ""
                row[f"replay_{run}_killed_by"] = ""
                continue
            res = replay.replay(ev, allow)
            row[f"replay_{run}_survives"] = res.survived
            row[f"replay_{run}_killed_by"] = res.killed_by or ""
            names = {e.name for e in ev}
            seen |= names
            if run == "heldout":
                row["missing_heldout"] = len(names - allow - set(policy.LAUNCH_SYSCALLS))
                row["missing_heldout_names"] = " ".join(sorted(names - allow - set(policy.LAUNCH_SYSCALLS)))
        row["speculative"] = len(allow - seen) if seen else ""
        rows.append(row)

    fields = []
    for r in rows:
        for k in r:
            if k not in fields:
                fields.append(k)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows)} policies evaluated -> {OUT.relative_to(paths.ROOT)}")
    if skipped_fake:
        print(f"(skipped {skipped_fake} TEST-FAKE policies - pass --include-fake only for pipeline tests)")


if __name__ == "__main__":
    main()
