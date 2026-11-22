#!/usr/bin/env python3
"""PERSON A - record strace traces for every test program (Linux only).

For each program in config/programs.json it records:
    data/<program>/traces/training.strace   normal use #1 (the policy is learned from this)
    data/<program>/traces/heldout.strace    normal use #2, different code path (never shown to anyone
                                            generating a policy; used to test generalisation)
    data/<program>/traces/poisoned.strace   training run with LD_PRELOAD=programs/bin/poison.so,
                                            i.e. a "compromised" run containing ptrace/unshare/bpf
and for the probe:
    data/probe/traces/attack.strace
plus a summary_<run>.json ({syscall: count}) and <run>.meta.json (pass/fail, kernel, versions).

Every run is first executed WITHOUT strace to make sure the program works.

Usage:
    python3 tracing/record_traces.py                     # all programs, all runs
    python3 tracing/record_traces.py --programs gzip worker --runs training heldout
"""
import argparse
import datetime
import json
import platform
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sandboxlab import paths, strace_parser, workload  # noqa: E402

POISON_ENV = {"LD_PRELOAD": "{BIN}/poison.so"}


def tool_version(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True).stdout.splitlines()[0]
    except Exception:
        return "unknown"


def env_info():
    return {
        "kernel": platform.release(),
        "machine": platform.machine(),
        "glibc": " ".join(platform.libc_ver()),
        "strace": tool_version(["strace", "-V"]),
        "recorded_at": datetime.datetime.now().isoformat(timespec="seconds"),
    }


def record(name, cfg, run_name, out_dir: Path):
    spec_run = "training" if run_name == "poisoned" else run_name
    env = POISON_ENV if run_name == "poisoned" else None

    sanity = workload.run(cfg, spec_run, env_extra=env)
    if not sanity["passed"]:
        print(f"  !! {name}/{run_name}: program FAILED without strace -> fix setup first\n     {sanity}")
        return False

    trace = out_dir / "traces" / f"{run_name}.strace"
    trace.parent.mkdir(parents=True, exist_ok=True)
    res = workload.run(cfg, spec_run, prefix=["strace", "-f", "-o", str(trace)], env_extra=env)
    summary = strace_parser.write_summary(trace, out_dir / f"summary_{run_name}.json", name, run_name)
    meta = {"program": name, "run": run_name, "passed_under_strace": res["passed"],
            "argv": cfg["runs"][spec_run]["argv"], "poisoned": run_name == "poisoned", **env_info()}
    (out_dir / "traces" / f"{run_name}.meta.json").write_text(json.dumps(meta, indent=2))
    print(f"  {name:<11} {run_name:<9} {summary['total_calls']:>6} calls  "
          f"{summary['unique_syscalls']:>3} unique  passed={res['passed']}")
    return True


def record_probe():
    out = paths.DATA / "probe" / "traces" / "attack.strace"
    out.parent.mkdir(parents=True, exist_ok=True)
    workload.run_probe(prefix=["strace", "-f", "-o", str(out)])
    s = strace_parser.write_summary(out, paths.DATA / "probe" / "summary_attack.json", "probe", "attack")
    print(f"  {'probe':<11} {'attack':<9} {s['total_calls']:>6} calls  {s['unique_syscalls']:>3} unique")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--programs", nargs="*", help="default: all")
    ap.add_argument("--runs", nargs="*", default=["training", "heldout", "poisoned"])
    ap.add_argument("--no-probe", action="store_true")
    args = ap.parse_args()

    progs = workload.programs()
    names = args.programs or list(progs)
    print(f"Recording traces into {paths.DATA}")
    for name in names:
        for run_name in args.runs:
            record(name, progs[name], run_name, paths.DATA / name)
    if not args.no_probe:
        record_probe()


if __name__ == "__main__":
    main()
