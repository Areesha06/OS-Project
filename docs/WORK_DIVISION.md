# Work division

Deadline: **November 26, 2026, 11:59 PM**.

The roles from the proposal (Member 1, 2, 3) are mapped to laptops, because seccomp and strace only work
on Linux and long LLM runs need 16 GB of RAM.

| Person | Laptop | Proposal role | Owns |
|---|---|---|---|
| **A** | 16 GB Ubuntu | Member 1 (tracing and baseline) + the enforcement part of Member 3 | `programs/`, `tracing/`, `enforce/`, `sandboxlab/strace_parser.py`, `sandboxlab/workload.py`, `config/programs.json`, `config/syscalls_x86_64.json`, `scripts/` |
| **B** | 16 GB Windows | Member 2 (LLM side) | `harness/`, `sandboxlab/policy.py`, `sandboxlab/syscalls.py`, `config/syscall_descriptions.json`, `config/high_risk.txt`, `docs/METHODOLOGY.md` (D3–D5, D10) |
| **C** | 8 GB Windows | Evaluation, plots and README part of Member 3 | `analysis/`, `visualizer/`, `sandboxlab/replay.py`, `README.md`, `docs/REPORT_DRAFT.md`, slides |

**C never runs a model.** Nothing C owns needs more than a few hundred MB of RAM. The two long
generation runs are split between A (3B model) and B (8B model).

Git rule: only touch the folders you own. If you need a change in someone else's file, ask them.
This avoids merge conflicts in the last 4 days.

---

## Person A: Ubuntu 16 GB (tracing and enforcement)

### Files you own

| File | What it does |
|---|---|
| `programs/src/worker.c` | Multithreaded test program. `worker 0` = no threads (training), `worker 4` = 4 threads (held-out). This is the **concurrency** element. |
| `programs/src/mini_httpd.c` | One-request HTTP server. Training serves a file with `sendfile`; held-out lists a directory with `getdents64`. |
| `programs/src/escape_probe.c` | Harmless jailbreak probe. Tries 10 dangerous syscalls with invalid arguments and prints BLOCKED or REACHED_KERNEL for each. |
| `programs/src/poison.c` | `LD_PRELOAD` library that injects `ptrace`/`unshare`/`bpf` calls, used to record the poisoned trace. |
| `programs/workloads/*.sql` | The sqlite3 training (insert) and held-out (query/VACUUM) workloads. |
| `programs/Makefile`, `Makefile` | Build the programs and the launcher (`make`). |
| `config/programs.json` | Defines the 6 programs: setup commands, training/held-out command, correctness check. |
| `config/syscalls_x86_64.json` | Syscall name → number table. Regenerate it with `tracing/gen_syscall_table.py`. |
| `sandboxlab/strace_parser.py` | Parses `strace -f` output into events and `{syscall: count}` summaries. |
| `sandboxlab/workload.py` | Runs a program run in a fresh scratch directory: plain, under strace, or under the launcher. |
| `tracing/record_traces.py` | Records training/held-out/poisoned traces for every program, plus the probe trace. |
| `tracing/make_baseline.py` | Baseline = allow exactly what the trace shows. Writes `policies/baseline/`. |
| `tracing/gen_syscall_table.py` | Rebuilds the syscall table from this machine's kernel headers. |
| `enforce/src/seccomp_launcher.c` | The bouncer: builds the BPF filter, sets NO_NEW_PRIVS, installs seccomp, `exec`s the program. |
| `enforce/run_enforcement.py` | Runs every program under every policy for real, and finds the blocked syscall on a SIGSYS kill. Writes `results/enforcement.csv`. |
| `enforce/run_containment.py` | Runs the probe under every policy (errno mode). Writes `results/containment.csv` (validation). |
| `scripts/setup_ubuntu.sh` | One-time setup. |
| `scripts/run_pipeline.sh` | Runs every Linux step in order. |

### Steps

**Today, Nov 22**
1. Clone the repo.
2. Run `bash scripts/setup_ubuntu.sh`.
3. Run `python3 tracing/record_traces.py`.
4. Check that every line says `passed=True`. Push `data/`.
5. Install Ollama and run `ollama pull llama3.2:3b`.

**Nov 23**
1. Run `python3 tracing/make_baseline.py`, then `python3 enforce/run_enforcement.py --sources baseline`.
2. You should see every baseline PASS on training and BREAK on held-out. That is hypothesis H1. Push `policies/baseline/` and `results/`.

**Nov 23 night**
1. Overnight: `python3 harness/generate_policies.py --models llama3.2:3b`. It resumes if interrupted.
2. Push `policies/llm/` in the morning.

**Nov 24–25**
1. Pull B's 8B policies.
2. Run `python3 enforce/run_enforcement.py` (it skips what is done), then `python3 enforce/run_containment.py`.
3. Push `results/enforcement.csv` and `results/containment.csv`.

**Nov 26**
1. Clone the repo fresh into a new folder and follow the README exactly. Fix anything that fails.
2. Write report sections 2 (background), 5.1–5.3 and 5.5 (programs, tracing, baseline, enforcement).

### Things to understand for the viva
- How seccomp-BPF works, line by line in `seccomp_launcher.c`.
- Why NO_NEW_PRIVS is needed.
- What `strace -f` shows.
- Why the baseline breaks on held-out runs.

---

## Person B: Windows 16 GB (LLM side)

### Files you own

| File | What it does |
|---|---|
| `harness/prompts.py` | The system message and the three prompt styles: a (name only), b (trace summary), c (summary + syscall descriptions). Run `python harness/prompts.py gzip c --examples` to preview. |
| `harness/ollama_client.py` | Standard-library client for Ollama's `/api/chat`: temperature, seed, `num_ctx=4096`, timing. |
| `harness/generate_policies.py` | Runs the whole grid (programs × prompts × models × repeats, plus poisoned) and saves one JSON per generation, with raw output and timing. Resumable. |
| `harness/timing_test.py` | One generation per model, then an estimate of the total time. Run this before deciding repeats. |
| `harness/fake_backend.py` | Fake model for testing the pipeline without Ollama. Its outputs are labelled TEST-FAKE and are **never reported**. |
| `sandboxlab/policy.py` | Policy file format, JSON extraction from LLM text (direct/embedded/list-fallback/failed), names → numbers. |
| `sandboxlab/syscalls.py` | Valid-name check (hallucination), the high-risk list and descriptions. |
| `config/syscall_descriptions.json` | One-line meaning per syscall, used in prompt style c. |
| `config/high_risk.txt` | The high-risk list, with a reason for each entry. |

### Steps

**Today, Nov 22**
1. Install Python, Git and Ollama for Windows.
2. Run `ollama pull llama3.1:8b` and `ollama pull llama3.2:3b`.
3. Run `pip install -r requirements.txt`.
4. Test the pipeline with no model: `python harness/generate_policies.py --backend fake --data examples/data --programs gzip worker --repeats 1 --out test_out`, then delete `test_out`.

**Nov 23**
1. Pull A's `data/`.
2. Run `python harness/timing_test.py` and note the seconds per generation.
3. Pick `--repeats` so the 8B grid finishes in about 8 hours (3 is the default; use 5 if it fits).
4. Read 3–4 real outputs by hand. Do the prompts produce sensible JSON?

**Nov 23 night**
1. Overnight: `python harness/generate_policies.py --models llama3.1:8b`.
2. Keep the laptop on the charger and set Settings → Power → Sleep to **Never**.
3. Push `policies/llm/` and `results/generation_log.csv`.

**Nov 24–25**
1. Do the LLM analysis:
   - Pick examples of hallucinated names.
   - Look at which syscalls each model forgets (see `results/summary.md` once A and C have run their steps).
   - Did either model drop the injected `ptrace` from the poisoned trace?
   - Is model latency (from `generation_log.csv`) acceptable?
2. Choose 3–4 raw outputs for the slides.

**Nov 26**
1. Write report sections 5.4 (LLM method), 6.3 (invalid output), 6.4 (poisoned trace) and the H2/H3 discussion.

### Things to understand for the viva
- Why temperature is 0.7 and not 0.
- Why `format=json` is off.
- What counts as hallucinated.
- Why the program description is in every prompt.
- The difference between prompts b and c.

---

## Person C: Windows 8 GB (replay, analysis, visualizer, documentation)

### Files you own

| File | What it does |
|---|---|
| `sandboxlab/replay.py` | The bouncer logic in Python: replays a trace against a policy and returns where the program would die and what got through. This is the proposal's fallback method. |
| `analysis/replay_check.py` | CLI for one trace and one policy, e.g. "gzip held-out vs baseline: killed at getrandom". |
| `analysis/evaluate_policies.py` | Per-policy metrics: invalid output, hallucinated names, allowed count, high-risk count, poison kept, replay predictions, syscalls missing for held-out, speculative extras. Writes `results/policy_metrics.csv`. |
| `analysis/make_figures.py` | Figures 1–5 and `results/summary.md`: all numbers, replay-vs-real agreement, H3 check, containment validation. |
| `visualizer/syscall_jail.py` | The pygame demo: two bouncers, the same trace, real policies, and a jailbreak scene. |
| `README.md` | Main documentation (marks depend on it). |
| `docs/REPORT_DRAFT.md` | Report skeleton with method written. Fill in the results and match the Part 4 sample format when it arrives. |
| `docs/VIVA_NOTES.md` | Questions and answers for all three of you. |

### Steps

**Today, Nov 22**
1. Run `pip install -r requirements.txt`.
2. Run `python visualizer/syscall_jail.py --examples`.
3. Play with every scene so you can present it.

**Nov 23**
1. Pull A's traces and baselines.
2. Run `python analysis/evaluate_policies.py`, then `python analysis/make_figures.py`.
3. You should already see the baseline result (H1).

**Nov 24**
1. Write report sections 1, 3 and 4 (intro, related work, research question).
2. Prepare the 3 demo scenes:
   - held-out breakage: Baseline vs best LLM
   - poisoned: Baseline poisoned vs LLM poisoned
   - jailbreak

**Nov 25**
1. Pull everything (LLM policies plus `results/enforcement.csv`).
2. Re-run both analysis scripts. Final figures.
3. Record a backup screen video of the visualizer (Windows: Win+Alt+R with Xbox Game Bar).

**Nov 26**
1. Merge the report.
2. Make the slides (plain text plus figures plus the demo).
3. Polish the README.
4. Lead the 1-hour walkthrough where everyone explains their part.

### Things to understand for the viva
- What each figure shows.
- Why replay is only an approximation (D8).
- What the visualizer does and does not show (it is a replay, not live enforcement).

---

## Day plan

| Date | A (Ubuntu) | B (Windows 16 GB) | C (Windows 8 GB) |
|---|---|---|---|
| Sun Nov 22 | Setup, record traces, push | Install Ollama and models, fake-backend test | Setup, explore the visualizer with examples |
| Mon Nov 23 | Baselines + baseline enforcement; 3B overnight | Timing test, check prompts; 8B overnight | First analysis run (baseline only), report sections 1, 3, 4 |
| Tue Nov 24 | Enforce 3B policies | Push 8B policies; LLM analysis | Demo scenes; report drafting |
| Wed Nov 25 | Enforce 8B policies, containment, push results | Examples for slides | Final figures, summary, backup video |
| Thu Nov 26 (due 11:59 PM) | Fresh-clone test, report sections | Report sections | Merge report, slides, README, team walkthrough |

**If you're behind on the evening of Nov 24, cut in this order:**
1. Repeats: 3 → 2.
2. Programs 5–6 for the 8B model.
3. Visualizer polish.

Never cut enforcement or the README.
