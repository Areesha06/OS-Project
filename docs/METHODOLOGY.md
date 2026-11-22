# Methodology decisions (read before the viva)

Every choice below changes the numbers, so each one is written down with its reason.
If an examiner asks "why did you do X?", the answer is here.

## Pipeline in one paragraph

Each test program is run twice in normal ways: a **training run** and a different **held-out run**.
The training run is recorded with `strace -f`. Two kinds of policy are made from it.
The **baseline** allows exactly the syscalls in the trace. The **LLM policies** come from a local model (Ollama),
which gets one of three prompts and answers with a JSON allow-list.

Every policy is then **enforced for real** with seccomp-BPF. Our launcher installs the filter
(default action KILL_PROCESS) and `exec`s the program on both runs. A run is **broken** if the program
is killed or fails its correctness check. Static metrics (size, high-risk syscalls, hallucinated names,
invalid JSON) are computed from the policy files.

## Decisions

**D1. `execve` is always added at enforcement time.**
The launcher installs the filter and then calls `execve` to start the program, so `execve` must be
allowed or nothing can start. It is added by `sandboxlab/policy.py` (`LAUNCH_SYSCALLS`) when the
numbers file is written. It is **not** counted in attack-surface metrics. No other "startup set"
is added. Forgetting `brk`, `mmap` or `arch_prctl` breaks the program, and that is a real policy error we
want to measure.

**D2. Default action.**
- `KILL_PROCESS` for the main experiment, because it gives a clear pass/fail.
- `TRAP` is used only for diagnosis. The program is re-run under strace, which prints
  `si_syscall=__NR_x` and tells us which call was blocked.
- `ERRNO(1234)` is used for the containment probe, so every attempt reports back instead of killing the probe.

**D3. Temperature 0.7, seed = repeat number.**
At temperature 0 the repeats would be identical and measure nothing. A fixed seed per repeat keeps the
whole grid reproducible. The proposal said 5 repeats. We default to 3 because of CPU time; run
`harness/timing_test.py` and use 5 if there is time (the risk plan in the proposal allows fewer repeats).

**D4. JSON handling.**
Ollama's `format=json` is **off** by default, because invalid output is one of our metrics.
Extraction tiers:
- `direct` (whole output is JSON)
- `embedded` (JSON inside extra text or code fences)
- `list-fallback` (only an array found)
- `failed` = **invalid output**

Failed policies are not enforced and are reported separately.

**D5. Hallucination.**
After trivial normalisation (case, `sys_`/`__NR_` prefix, quotes, `()`), a name that is not in the
x86_64 syscall table (`config/syscalls_x86_64.json`, from `asm/unistd_64.h`) is hallucinated.
Spelling mistakes are not corrected.

**D6. Held-out runs differ on purpose.**

| Program | Training | Held-out | New kernel paths |
|---|---|---|---|
| gzip | `gzip -c` to stdout | in-place `gzip -f` | unlinkat, fchmod, fchown, utimensat |
| sqlite3 | bulk insert | index, GROUP BY, DELETE, VACUUM | temp files, truncation, writes to stdout |
| cp | one file | `cp -rp` directory | mkdirat, getdents64, metadata syscalls |
| tar | create | extract | mkdirat, fchownat, utimensat |
| mini_httpd | serve a file (sendfile) | directory listing | getdents64, and getrandom (glibc malloc initialisation) |
| worker | 0 threads | 4 threads (**concurrency**) | clone3, futex |

**D7. Poisoned trace (extension of the proposal's attack-surface question).**
The training run is repeated with `LD_PRELOAD=programs/bin/poison.so`. Its constructor makes
`ptrace`, `unshare` and `bpf` calls with invalid arguments. They are harmless, but they appear in the trace like
injected attack code would. A trace-copying baseline must copy them. The question is whether the LLM leaves them out.
Only prompt styles b and c are used, since style a never sees a trace.

**D8. Replay is an approximation, validated against reality.**
`sandboxlab/replay.py` assumes the program makes the same calls in the same order under the filter.
`analysis/make_figures.py` reports how often the replay prediction matched real enforcement.
This is the proposal's fallback method, and it powers the visualizer.

**D9. One machine for traces and enforcement.**
Syscall names differ between glibc and kernel versions (`clone` vs `clone3`, `stat` vs `newfstatat`).
All tracing and enforcement happen on Person A's Ubuntu laptop. `LC_ALL=C` is set for every run,
so locale files do not change the trace.

**D10. Program description in every prompt.**
Our own programs (worker, mini_httpd) mean nothing to a model by name alone, so every prompt style
includes a one-line description from `config/programs.json`. Style a is therefore "name + one-line
description, no trace".

**D11. Attack surface.**
Attack surface = number of valid, unique syscall names allowed. High-risk syscalls are counted
separately, using `config/high_risk.txt` (mostly what Docker's default profile blocks, plus io_uring and
known container-escape calls).

**D12. Containment is a validation, not a finding.**
Whether the probe's `ptrace` gets through is fully determined by whether `ptrace` is in the list.
`run_containment.py` proves our enforcement does what the policy says (every row should match).
It is also the jailbreak demo.

**D13. Scale vs proposal.**
The proposal said 8–10 programs, 3 prompts, 2 models and 5 repeats (300 generations).

We use:
- 6 programs × (3 training prompts + 2 poisoned prompts) × 2 models × 3 repeats = **180 generations**, plus 12 baselines.

To add programs, add an entry to `config/programs.json`. No code changes are needed.

**D14. Launcher.**
The proposal mentioned Docker's profile or libseccomp. We wrote a ~100-line C launcher that builds the
BPF filter directly. It has no dependencies, and every instruction can be explained:
- non-x86_64 architecture → kill
- x32 range → default action
- `nr == N` → allow
- otherwise → default action
