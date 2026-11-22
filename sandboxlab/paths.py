"""Central place for folder locations. Everything is relative to the repo root,
so scripts work the same on Windows (Persons B and C) and Ubuntu (Person A)."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CONFIG = ROOT / "config"
PROGRAMS_CONFIG = CONFIG / "programs.json"
SYSCALL_TABLE = CONFIG / "syscalls_x86_64.json"
HIGH_RISK = CONFIG / "high_risk.txt"
DESCRIPTIONS = CONFIG / "syscall_descriptions.json"

PROGRAMS_DIR = ROOT / "programs"
PROGRAMS_BIN = PROGRAMS_DIR / "bin"
WORKLOADS = PROGRAMS_DIR / "workloads"
LAUNCHER = ROOT / "enforce" / "bin" / "seccomp_launcher"

DATA = ROOT / "data"                 # data/<program>/traces/<run>.strace and summaries
POLICIES = ROOT / "policies"         # policies/baseline/... and policies/llm/...
RESULTS = ROOT / "results"           # csv results and figures
FIGURES = RESULTS / "figures"
EXAMPLES = ROOT / "examples"         # small sample data so B and C can start before A's traces exist


def trace_path(program: str, run: str, data_dir: Path = DATA) -> Path:
    return data_dir / program / "traces" / f"{run}.strace"


def summary_path(program: str, run: str, data_dir: Path = DATA) -> Path:
    return data_dir / program / f"summary_{run}.json"
