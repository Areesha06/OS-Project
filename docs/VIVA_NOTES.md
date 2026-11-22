# Viva notes: everyone should be able to answer all of these

**1. What is a system call?**
The only way a user program can ask the kernel to do something privileged: open a file, get memory,
create a thread, send a packet. Each one has a number; on x86_64 the number goes in the `rax` register before the `syscall` instruction.

**2. What does `strace -f` do?**
It uses `ptrace` to stop the program at every syscall entry and exit and print the call with its arguments and return value.
`-f` follows threads and child processes too. Without it, the 4-thread worker would be missing its thread syscalls.

**3. What is seccomp-BPF?**
A filter attached to a process. On every syscall the kernel runs a small BPF program over `struct seccomp_data`
(syscall number, architecture, arguments). The return value decides the outcome: ALLOW, KILL_PROCESS, TRAP, ERRNO or LOG.
The filter is inherited across `fork`/`clone` and survives `execve`, and it can only be made stricter, never removed.

**4. Walk through your filter.**
1. Load `arch`. If it isn't x86_64, kill. This blocks the 32-bit ABI bypass, where the same number means a different syscall.
2. Load `nr`. If it is in the x32 range, take the default action.
3. For each allowed number: if equal, return ALLOW.
4. Otherwise, take the default action.

**5. Why `PR_SET_NO_NEW_PRIVS`?**
Without root, the kernel only accepts a filter if the process promises never to gain privileges.
Otherwise a filtered process could exec a setuid binary and trick it into misbehaving by denying it syscalls.

**6. Why does the launcher need `execve` in every policy?**
The filter is installed before `exec`, so `exec` itself goes through the filter (D1).
`execve` is not counted in attack surface.

**7. Why does the baseline break on held-out runs?**
It only knows what it saw.
- In-place gzip needs `unlinkat`, `fchmod`, `fchown` and `utimensat`, which `gzip -c` never calls.
- 4 threads need `clone3` and `futex`.
- Even hidden library behaviour differs between runs, like glibc calling `getrandom` when malloc first initialises.

**8. What are the trade-offs?**
- A bigger list means fewer breakages but more attack surface.
- A tight list means less attack surface but more breakage.
- The interesting question is whether an LLM adds the *right* extras (the held-out ones) without adding *dangerous* ones.

**9. What do the three prompt styles test?**
- a: prior knowledge only.
- b: knowledge plus evidence (the trace).
- c: evidence plus a meaning for each syscall.

H3 asks whether moving from a to c helps more than moving from 3B to 8B.

**10. Why temperature 0.7?**
At 0, repeats are identical and add nothing. A seed per repeat keeps the experiment reproducible.

**11. What counts as a hallucination?**
A name not in the x86_64 table after trivial clean-up, e.g. `open_file` or `readfile`.
`open` or `stat` are real (old) syscalls and are *not* hallucinations.

**12. What is the poisoned trace and is it realistic?**
We inject code with `LD_PRELOAD` (a real attack technique) that calls `ptrace`, `unshare` and `bpf` with invalid arguments, so nothing actually happens.
The trace looks like a compromised run. The baseline must copy these calls; an LLM might notice they don't belong to gzip.

**13. Is the escape probe safe?**
Yes. Every call uses invalid arguments (NULL pointers, bad flags, PID -1), so even if it reaches the kernel it fails.
seccomp checks the syscall number before the kernel looks at arguments, so blocking is unaffected.

**14. Why is containment "validation" rather than a result?**
Whether `ptrace` reaches the kernel is decided entirely by whether `ptrace` is on the list.
The check proves our enforcement matches the policy. All rows should match.

**15. What is replay and why trust it?**
Replay re-checks a recorded trace against a policy without running anything. It can be wrong if the program
behaves differently once a call is blocked. We measured how often it agrees with real seccomp: [X%].

**16. How is this different from Project Part 3?**
In Part 3 the AI was a live defender reacting to malware, sitting *inside* a sandbox that filtered its commands.
Here the AI *writes* the sandbox before the program runs. That is prevention versus detection, and the syscall interface versus scheduler telemetry.

**17. Which OS rubric elements do you cover?**
- **Security:** least privilege, privilege-escalation prevention (NO_NEW_PRIVS, blocking `ptrace`/`unshare`).
- **I/O:** system call interception (seccomp, strace).
- **Concurrency:** thread-creation and futex syscalls in the multithreaded worker, `strace -f` across threads, and KILL_PROCESS killing all threads.

**18. Why `KILL_PROCESS` and not `KILL_THREAD`?**
Killing one thread of a multithreaded program leaves it half-alive and in an undefined state. Killing the whole thread group is the safe choice.

**19. Limitations?**
See report §8. The most important: one machine, names-only filtering (no argument checks), and 6 programs.

**20. What would you do next?**
- An agentic repair loop: feed SIGSYS feedback back to the LLM, and measure whether it "fixes" policies by over-permitting.
- Argument-level filters.
- More programs.
- Comparison with Docker's default profile (`load_policy` already reads that format).
