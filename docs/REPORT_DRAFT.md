# Can Local LLMs Write Syscall Sandboxes?

Operating Systems L4. Instructor: Zafar Iqbal.
Areesha Kashif, Alishbah Saleem Kath, Noor E Hira.

> **Draft skeleton.**
> - Re-shape it to the "Project - Part 4 (sample)" format once it is shared.
> - Text in [brackets] is a placeholder to fill from `results/summary.md` and `results/figures/`.
> - Sections already written describe exactly what the code does. Keep them in sync if you change the code.

## Abstract
[3–4 sentences: problem, what we built, the headline numbers for H1–H3 and the poisoned trace, and one-line conclusion.]

## 1. Introduction
Every program reaches the kernel through system calls. Linux x86_64 has about 370 of them, but a typical
program uses a few dozen. seccomp-BPF lets a process restrict itself to an allow-list, so a compromised
program cannot use dangerous calls such as `ptrace`, `mount` or `bpf`.

Writing these lists by hand is tedious. Generating them from traces is precise but brittle: anything the
trace did not exercise is missing. Local LLMs know a lot about programs and could fill those gaps.
They can also hallucinate names, forget essential calls, or allow dangerous ones.

We measure this on real programs, with real enforcement, against a deterministic baseline.

## 2. Background
- **System calls and strace.** [What a syscall is; what `strace -f` records, including threads and children.]
- **seccomp-BPF.** A filter program runs on every syscall. It reads the architecture and syscall number from
  `struct seccomp_data` and returns ALLOW, KILL_PROCESS, TRAP, ERRNO or LOG.
  Installing a filter without root requires `PR_SET_NO_NEW_PRIVS`. Filters survive `execve` and are inherited
  by threads and children. Describe our filter from `enforce/src/seccomp_launcher.c`:
  - architecture check
  - x32 rejection
  - one compare-and-allow pair per allowed syscall
  - default action
- **Local LLMs.** Ollama, quantised Llama 3.2 3B and Llama 3.1 8B on a CPU-only laptop (as in Project Parts 1–3).

## 3. Related work
- Trace-to-policy generation is established. Google's Minijail ships `generate_seccomp_policy.py`,
  which builds a filter from strace output
  (https://android.googlesource.com/platform/external/minijail/+/refs/tags/linux-v13/tools/).
- Chestnut generates strict syscall filters for Linux userspace applications (https://arxiv.org/abs/2012.02554).
- Confine generates restrictive policies for containers
  (https://www3.cs.stonybrook.edu/~mikepo/papers/confine.cose23.pdf).
- Abhaya synthesises sandboxing policies from C/C++ programs by static analysis
  (https://www.cs.utexas.edu/~isil/abhaya.pdf).
- Recent work uses LLMs to generate *test cases* that widen trace coverage before profiling (Seccomp profiling
  with ChatGPT-assisted test code generation, Kyungpook National University / Cisco; NDSS 2026 poster
  "Hybrid Seccomp Profiling with LLM Assistance for Container Security",
  https://www.ndss-symposium.org/wp-content/uploads/ndss26-poster-42.pdf).
- **Our difference:** a small *local* model writes the *policy itself*. We test whether its prior knowledge
  generalises beyond the trace, and whether it rejects suspicious calls a trace-copying tool would accept.
- **Contrast with Project Part 3:** there the LLM was a reactive defender acting *inside* a sandbox. Here the LLM
  is the *architect* of the sandbox, offline, before anything runs (prevention, not detection).

## 4. Research question and hypotheses
RQ (from the proposal): Can local LLMs synthesize seccomp-style syscall policies from strace traces of normal
program runs, and how does the result compare with a deterministic trace-to-profile baseline in attack
surface removed versus legitimate behaviour broken?

- **H1:** The baseline never breaks the training run but may break held-out runs.
- **H2:** LLM policies will sometimes include dangerous or hallucinated syscalls, and sometimes omit essential ones.
- **H3:** More information (trace + descriptions) improves results more than a larger model.
- **Extension (poisoned trace):** When the trace contains injected suspicious calls, the baseline copies them.
  Do LLMs remove them?

## 5. Methodology
See `docs/METHODOLOGY.md` for every decision and its reason. Summarise D1–D14 here.

### 5.1 Test programs
6 programs; table from METHODOLOGY D6. They cover the I/O element (file, socket, sendfile, getdents64) and the
concurrency element (worker, 0 vs 4 threads).

### 5.2 Tracing
`strace -f`, fresh scratch directory per run, `LC_ALL=C`, every run checked for correctness first.
[Table: calls and unique syscalls per program/run, from `data/*/summary_*.json`.]

### 5.3 Baseline
Allow exactly the syscalls in the training trace, default deny.

### 5.4 LLM policies
- Ollama, models llama3.2:3b and llama3.1:8b.
- Prompt styles a, b and c (quote the system prompt from `harness/prompts.py`).
- Temperature 0.7, seed = repeat, 3 repeats.
- JSON extraction tiers.
- [N] generations total.

### 5.5 Enforcement
Real seccomp via our launcher, KILL_PROCESS. Pass = exit 0 and correctness check.
The blocked syscall is identified by re-running in TRAP mode under strace.

### 5.6 Metrics
Breakage rate; attack surface (allowed count, high-risk count); invalid output (unparseable, hallucinated);
poison kept; containment validation; replay-vs-real agreement.

## 6. Results
- **6.1 Breakage (Fig. 1).** [Baseline: 0% training, X% held-out. LLMs: ...] Name the syscalls that killed each held-out run.
- **6.2 Attack surface (Fig. 2, Fig. 5).** [Mean allowed and high-risk per condition. What did LLMs add that no run used ("speculative")?]
- **6.3 Invalid output (Fig. 3).** [Unparseable %, hallucinated %, examples of invented names.]
- **6.4 Poisoned trace (Fig. 4).** [Baseline kept 3/3 injected calls in every program. LLMs: ...]
- **6.5 Containment and replay validation.** [All N probe outcomes matched; replay agreed with real enforcement in X%.]
- **6.6 Cost.** [Seconds per generation per model, from `results/generation_log.csv`.]

## 7. Discussion
- H1, H2, H3: supported or not, and why.
- The size-vs-breakage trade-off (bigger lists break less but expose more).
- Which syscalls are "invisible" to traces (e.g. `getrandom` from glibc's malloc initialisation, thread setup calls).
- Practical recommendation, e.g. "LLM suggestions as a review aid on top of a trace, not a replacement".

## 8. Limitations
- 6 programs and one machine/libc.
- The held-out run is one alternative path, not full coverage.
- Names only: no argument filtering.
- Replay approximation.
- Small quantised models on CPU.
- The poisoned trace is simulated with LD_PRELOAD.
- A syscall filter is one defence layer, not complete security.

## 9. Conclusion
[2–3 sentences.]

## 10. Contributions
A: tracing, baseline, enforcement. B: LLM harness and analysis. C: evaluation, visualizer, documentation.

## References
[The related-work links above, plus the man pages: seccomp(2), prctl(2), strace(1), and the Ollama docs.]
