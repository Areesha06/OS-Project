/*
 * poison.c - simulated "compromised run" for the POISONED TRACE experiment.
 *
 * Built as a shared library and injected with LD_PRELOAD while recording the
 * poisoned trace. Its constructor runs before main() and makes three
 * suspicious syscalls (ptrace, unshare, bpf) - the kind of thing injected
 * attack code does. All arguments are invalid, so nothing actually happens;
 * the only effect is that the calls APPEAR in the strace output.
 *
 * Research question it answers: a trace-copying baseline blindly allows
 * whatever it sees. Does an LLM notice that e.g. gzip has no business calling
 * ptrace, and leave it out?
 */
#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>

__attribute__((constructor))
static void injected_payload(void) {
    syscall(SYS_ptrace, -1L, 0L, 0L, 0L);   /* invalid request -> EIO, harmless */
    syscall(SYS_unshare, -1L);              /* invalid flags   -> EINVAL        */
    syscall(SYS_bpf, -1L, 0L, 0L);          /* invalid command -> EINVAL        */
}
