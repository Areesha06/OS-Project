#!/usr/bin/env bash
# PERSON A - one-time setup on the Ubuntu laptop (also works on WSL2 Ubuntu).
set -euo pipefail
cd "$(dirname "$0")/.."
sudo apt update
sudo apt install -y build-essential strace sqlite3 linux-libc-dev python3-venv python3-pip curl
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
make                                   # builds programs/bin/* and enforce/bin/seccomp_launcher
python3 tracing/gen_syscall_table.py   # syscall table from THIS machine's headers
grep -q 'Seccomp' /proc/self/status && echo "seccomp available: OK"
echo "Setup done. Activate the venv in every new terminal:  source .venv/bin/activate"
