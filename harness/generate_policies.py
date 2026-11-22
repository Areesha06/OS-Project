#!/usr/bin/env python3
"""PERSON B (and A for the second model) - generate LLM policies with Ollama.

Grid:  programs x prompt styles (a,b,c) x models x repeats, on the TRAINING trace,
       plus the POISONED-trace experiment (styles b,c only - style a never sees a trace).

Each generation is saved as
    policies/llm/<program>/<model>__<trace_used>__p<style>__r<repeat>.json
with the raw model output, the extracted allow-list, json_valid, extraction
method and timing. Existing files are SKIPPED, so an interrupted overnight
run can just be started again with the same command.

Sampling: temperature 0.7 with seed = repeat number. At temperature 0 every
repeat would be identical and "repeats" would measure nothing; with a fixed
seed per repeat the whole grid is still reproducible. (docs/METHODOLOGY.md, D3)

Examples:
    python harness/generate_policies.py --dry-run                          # show plan + one prompt
    python harness/generate_policies.py --models llama3.1:8b               # Person B, overnight
    python harness/generate_policies.py --models llama3.2:3b               # Person A, overnight
    python harness/generate_policies.py --backend fake --repeats 1         # pipeline test, no Ollama
"""
import argparse
import csv
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sandboxlab import paths, policy  # noqa: E402
import prompts  # noqa: E402
import ollama_client  # noqa: E402
import fake_backend  # noqa: E402

LOG = paths.RESULTS / "generation_log.csv"
LOG_FIELDS = ["model", "program", "trace_used", "prompt", "repeat", "total_s", "load_s",
              "prompt_tokens", "output_tokens", "gen_s", "json_valid", "extraction", "n_names"]


def safe(model):
    return model.replace(":", "-").replace("/", "_")


def plan(args):
    jobs = []
    for model in args.models:
        for rep in range(args.repeats):
            for prog in args.programs:
                for trace_used in args.traces:
                    styles = args.prompts if trace_used == "training" else [p for p in args.prompts if p != "a"]
                    for style in styles:
                        jobs.append((model, rep, prog, trace_used, style))
    return jobs


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--models", nargs="+", default=["llama3.2:3b", "llama3.1:8b"])
    ap.add_argument("--prompts", nargs="+", default=["a", "b", "c"], choices=["a", "b", "c"])
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--programs", nargs="+", default=None, help="default: all in config/programs.json")
    ap.add_argument("--traces", nargs="+", default=["training", "poisoned"], choices=["training", "poisoned"])
    ap.add_argument("--temperature", type=float, default=0.7)
    ap.add_argument("--json-mode", action="store_true", help="force JSON with Ollama format=json (default off)")
    ap.add_argument("--backend", choices=["ollama", "fake"], default="ollama")
    ap.add_argument("--host", default=ollama_client.DEFAULT_HOST)
    ap.add_argument("--data", type=Path, default=paths.DATA, help="where summaries are (examples/data for testing)")
    ap.add_argument("--out", type=Path, default=paths.POLICIES / "llm")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    args.programs = args.programs or list(prompts.load_programs())

    jobs = plan(args)
    todo = []
    for job in jobs:
        model, rep, prog, trace_used, style = job
        src = model if args.backend == "ollama" else f"TEST-FAKE-{model}"
        out = args.out / prog / f"{safe(src)}__{trace_used}__p{style}__r{rep}.json"
        if not out.exists():
            todo.append((job, src, out))
    print(f"{len(jobs)} generations in plan, {len(jobs) - len(todo)} already done, {len(todo)} to run")

    if args.dry_run:
        print("\n--- example prompt ---\n" + prompts.SYSTEM + "\n\n" +
              prompts.build("c", args.programs[0], "training", args.data))
        return
    if args.backend == "ollama":
        have = ollama_client.list_models(args.host)
        missing = [m for m in args.models if m not in have and m + ":latest" not in have]
        if missing:
            sys.exit(f"models not pulled: {missing}. Run: ollama pull {missing[0]}")

    LOG.parent.mkdir(parents=True, exist_ok=True)
    new_log = not LOG.exists()
    with open(LOG, "a", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=LOG_FIELDS)
        if new_log:
            w.writeheader()
        t_start = time.time()
        for i, ((model, rep, prog, trace_used, style), src, out) in enumerate(todo, 1):
            user = prompts.build(style, prog, trace_used, args.data)
            call = ollama_client.chat if args.backend == "ollama" else fake_backend.chat
            t0 = time.time()
            try:
                r = call(model, prompts.SYSTEM, user, temperature=args.temperature, seed=rep,
                         json_mode=args.json_mode, host=args.host)
            except ollama_client.OllamaError as e:
                sys.exit(str(e))
            wall = round(time.time() - t0, 2)
            names, how = policy.extract_allow_list(r["text"])
            doc = {
                "program": prog, "source": src, "prompt": style, "repeat": rep, "trace_used": trace_used,
                "allow": names or [], "json_valid": names is not None, "extraction": how,
                "raw_output": r["text"], "temperature": args.temperature, "seed": rep,
                "json_mode": args.json_mode, "wall_s": wall, **{k: r[k] for k in
                ("total_s", "load_s", "prompt_tokens", "output_tokens", "gen_s")},
                "system_prompt": prompts.SYSTEM, "user_prompt": user,
            }
            policy.save_policy(doc, out)
            w.writerow({"model": src, "program": prog, "trace_used": trace_used, "prompt": style, "repeat": rep,
                        **{k: r[k] for k in ("total_s", "load_s", "prompt_tokens", "output_tokens", "gen_s")},
                        "json_valid": doc["json_valid"], "extraction": how, "n_names": len(doc["allow"])})
            fh.flush()
            eta = (time.time() - t_start) / i * (len(todo) - i)
            print(f"[{i}/{len(todo)}] {src:<16} {prog:<10} {trace_used:<8} p{style} r{rep}  "
                  f"{wall:6.1f}s  valid={doc['json_valid']!s:<5} n={len(doc['allow']):<3} ETA {eta/60:5.1f} min")


if __name__ == "__main__":
    main()
