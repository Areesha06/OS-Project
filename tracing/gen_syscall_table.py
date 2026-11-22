#!/usr/bin/env python3
"""PERSON A - regenerate config/syscalls_x86_64.json from the kernel headers on
the Ubuntu laptop (the file in the repo was generated the same way; regenerate
so it matches YOUR machine exactly).

Needs: sudo apt install linux-libc-dev   (provides asm/unistd_64.h)
Usage: python3 tracing/gen_syscall_table.py
"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sandboxlab import paths  # noqa: E402

CANDIDATES = [
    "/usr/include/x86_64-linux-gnu/asm/unistd_64.h",
    "/usr/include/asm/unistd_64.h",
]


def main():
    header = next((p for p in CANDIDATES if Path(p).exists()), None)
    if not header:
        sys.exit("unistd_64.h not found - install linux-libc-dev")
    table = {}
    for line in open(header):
        m = re.match(r"#define __NR_(\w+)\s+(\d+)", line)
        if m:
            table[m.group(1)] = int(m.group(2))
    table = dict(sorted(table.items(), key=lambda kv: kv[1]))
    paths.SYSCALL_TABLE.write_text(json.dumps(table, indent=1))
    print(f"{len(table)} syscalls from {header} -> {paths.SYSCALL_TABLE.relative_to(paths.ROOT)}")


if __name__ == "__main__":
    main()
