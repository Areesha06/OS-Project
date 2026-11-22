"""PERSON B - the three prompt styles from the proposal.

  (a) program name only      -> tests the model's prior knowledge alone
  (b) trace summary          -> name + one recorded strace run (syscall: count)
  (c) trace summary + syscall descriptions -> (b) plus a one-line meaning per syscall

Every style uses the same SYSTEM message and asks for the same JSON format,
so the only thing that changes between styles is the information given.
The program description (one line from config/programs.json) is included in
all styles because our own programs (worker, mini_httpd) are unknown to the
model by name alone.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sandboxlab import paths, syscalls  # noqa: E402

SYSTEM = """You are a Linux security engineer who writes seccomp allow-lists.
A seccomp allow-list is the set of system calls a program is permitted to make.
Every system call NOT on the list is blocked and the program is killed if it makes one.

Rules:
1. Use exact Linux x86_64 system call names as in <asm/unistd_64.h>, for example: openat, newfstatat, exit_group.
2. The program must keep working in ALL of its normal uses, not only the one described.
3. Do NOT include system calls the program does not need for normal operation. Every extra system call is attack surface.
4. Reply with JSON only, in exactly this form:
{"allow": ["syscall_1", "syscall_2"], "notes": "one short sentence"}"""

STYLES = {
    "a": "program name only",
    "b": "trace summary",
    "c": "trace summary + syscall descriptions",
}


def load_programs():
    with open(paths.PROGRAMS_CONFIG, encoding="utf-8") as f:
        return json.load(f)["programs"]


def load_summary(program, trace_used, data_dir=paths.DATA):
    f = Path(data_dir) / program / f"summary_{trace_used}.json"
    with open(f, encoding="utf-8") as fh:
        return json.load(fh)


def _command(prog_cfg, trace_used):
    run = "training" if trace_used == "poisoned" else trace_used
    return " ".join(prog_cfg["runs"][run]["argv"]).replace("{BIN}/", "")


def build(style, program, trace_used="training", data_dir=paths.DATA):
    """Return the user message for one generation."""
    cfg = load_programs()[program]
    head = f"Program: {program}\nWhat it does: {cfg['description']}\n"
    if style == "a":
        return head + "\nWrite the seccomp allow-list for this program."

    summ = load_summary(program, trace_used, data_dir)
    lines = []
    for name, count in summ["counts"].items():
        if style == "c":
            lines.append(f"- {name} ({count} call{'' if count == 1 else 's'}): {syscalls.describe(name)}")
        else:
            lines.append(f"- {name}: {count}")
    body = (
        f"\nThe following system calls were recorded with `strace -f` during ONE normal run "
        f"of the command `{_command(cfg, trace_used)}`"
        + (" (syscall: number of calls)" if style == "b" else "")
        + ":\n" + "\n".join(lines)
        + "\n\nThis recording may not cover every normal use of the program."
        "\nWrite the seccomp allow-list for this program."
    )
    return head + body


if __name__ == "__main__":
    # quick preview: python harness/prompts.py gzip c [training|poisoned] [--examples]
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    data = paths.EXAMPLES / "data" if "--examples" in sys.argv else paths.DATA
    prog = args[0] if args else "gzip"
    style = args[1] if len(args) > 1 else "c"
    trace = args[2] if len(args) > 2 else "training"
    print("=== SYSTEM ===\n" + SYSTEM + "\n\n=== USER ===\n" + build(style, prog, trace, data))
