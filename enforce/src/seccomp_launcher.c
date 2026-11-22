/*
 * seccomp_launcher.c - runs a program inside a seccomp allow-list ("the bouncer").
 *
 * Usage:
 *   seccomp_launcher [--mode kill|trap|log|errno:N] NUMBERS_FILE -- /abs/path/program [args...]
 *
 * NUMBERS_FILE contains one x86_64 syscall NUMBER per line (blank lines and
 * lines starting with '#' are ignored). Python (sandboxlab/policy.py) converts
 * policy JSON names -> numbers, so this C file never needs a name table.
 *
 * What it does, step by step:
 *   1. Builds a classic-BPF program:
 *        - if the architecture is not x86_64            -> kill  (blocks 32-bit ABI tricks)
 *        - if the syscall number has the x32 bit set     -> default action
 *        - for each allowed number:  if nr == N          -> ALLOW
 *        - otherwise                                     -> default action
 *   2. prctl(PR_SET_NO_NEW_PRIVS, 1)  - required to install a filter without root,
 *      and guarantees the program can never gain privileges (e.g. via setuid binaries).
 *   3. prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) - install the filter.
 *   4. execv(program) - the filter survives exec and applies to the program and
 *      to every thread/child it creates. execve itself must therefore be in the
 *      allow-list (the Python runner adds it; see docs/METHODOLOGY.md).
 *
 * Default actions (--mode):
 *   kill     SECCOMP_RET_KILL_PROCESS : whole process dies with SIGSYS   (main experiment)
 *   trap     SECCOMP_RET_TRAP         : SIGSYS delivered; strace shows which syscall (diagnosis)
 *   log      SECCOMP_RET_LOG          : allowed but logged by the kernel (audit/dmesg)
 *   errno:N  SECCOMP_RET_ERRNO|N      : the call fails with errno N     (containment probe)
 */
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#define MAX_ALLOWED 1024
#define X32_SYSCALL_BIT 0x40000000U

static unsigned int parse_mode(const char *m) {
    if (strcmp(m, "kill") == 0) return SECCOMP_RET_KILL_PROCESS;
    if (strcmp(m, "trap") == 0) return SECCOMP_RET_TRAP;
    if (strcmp(m, "log") == 0) return SECCOMP_RET_LOG;
    if (strncmp(m, "errno:", 6) == 0) return SECCOMP_RET_ERRNO | (atoi(m + 6) & SECCOMP_RET_DATA);
    fprintf(stderr, "launcher: unknown mode '%s'\n", m);
    exit(2);
}

int main(int argc, char **argv) {
    unsigned int default_action = SECCOMP_RET_KILL_PROCESS;
    int i = 1;
    if (i + 1 < argc && strcmp(argv[i], "--mode") == 0) { default_action = parse_mode(argv[i + 1]); i += 2; }
    if (i + 2 >= argc || strcmp(argv[i + 1], "--") != 0) {
        fprintf(stderr, "usage: %s [--mode kill|trap|log|errno:N] NUMBERS_FILE -- /abs/program [args]\n", argv[0]);
        return 2;
    }
    const char *numbers_file = argv[i];
    char **prog_argv = &argv[i + 2];

    /* ---- read allowed syscall numbers ---- */
    unsigned int allowed[MAX_ALLOWED];
    int n = 0;
    FILE *f = fopen(numbers_file, "r");
    if (!f) { perror("launcher: open numbers file"); return 2; }
    char line[64];
    while (fgets(line, sizeof line, f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        if (n >= MAX_ALLOWED) { fprintf(stderr, "launcher: too many syscalls\n"); return 2; }
        allowed[n++] = (unsigned int)strtoul(line, NULL, 10);
    }
    fclose(f);

    /* ---- build the BPF program ---- */
    int len = 5 + 2 * n + 1;
    struct sock_filter *filter = calloc(len, sizeof *filter);
    int k = 0;
    /* load architecture; kill anything that is not native x86_64 */
    filter[k++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
    filter[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);
    filter[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    /* load syscall number; reject the x32 ABI range */
    filter[k++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
    filter[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 2 * n, 0);
    /* allow-list: "if nr == N then ALLOW, else fall through to the next check" */
    for (int j = 0; j < n; j++) {
        filter[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, allowed[j], 0, 1);
        filter[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    }
    /* nothing matched: default action */
    filter[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, default_action);

    struct sock_fprog prog = { .len = (unsigned short)k, .filter = filter };

    /* ---- install and exec ---- */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) { perror("launcher: PR_SET_NO_NEW_PRIVS"); return 2; }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) { perror("launcher: PR_SET_SECCOMP"); return 2; }

    execv(prog_argv[0], prog_argv);
    /* only reached if execve itself was allowed but failed (e.g. wrong path) */
    perror("launcher: execv");
    return 127;
}
