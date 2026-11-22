#!/usr/bin/env python3
"""PERSON B - run ONE generation per model (the longest prompt, style c) and
estimate how long the full grid will take. Run this BEFORE starting overnight
runs, then choose --repeats / --models / --prompts so it fits.

Usage:  python harness/timing_test.py [--models llama3.2:3b llama3.1:8b] [--program sqlite3]
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sandboxlab import paths, policy  # noqa: E402
import prompts  # noqa: E402
import ollama_client  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", default=["llama3.2:3b", "llama3.1:8b"])
    ap.add_argument("--program", default="sqlite3", help="sqlite3 has one of the longest prompts")
    ap.add_argument("--host", default=ollama_client.DEFAULT_HOST)
    ap.add_argument("--data", type=Path, default=paths.DATA)
    args = ap.parse_args()

    n_prog = len(prompts.load_programs())
    per_model_grid = n_prog * 3 + n_prog * 2           # training a,b,c + poisoned b,c (per repeat)
    user = prompts.build("c", args.program, "training", args.data)
    for model in args.models:
        print(f"\n{model}: warming up (first call loads the model into RAM)...")
        ollama_client.chat(model, prompts.SYSTEM, "Reply with {}", num_predict=5, host=args.host)
        r = ollama_client.chat(model, prompts.SYSTEM, user, seed=0, host=args.host)
        names, how = policy.extract_allow_list(r["text"])
        tps = r["output_tokens"] / r["gen_s"] if r["gen_s"] else 0
        print(f"  one style-c generation: {r['total_s']}s  ({r['prompt_tokens']} prompt tok, "
              f"{r['output_tokens']} output tok, {tps:.1f} tok/s), json={how}, {len(names or [])} names")
        for reps in (1, 3, 5):
            hours = r["total_s"] * per_model_grid * reps / 3600
            print(f"  full grid with {reps} repeat(s): {per_model_grid * reps} generations ~ {hours:.1f} h (upper estimate)")


if __name__ == "__main__":
    main()
