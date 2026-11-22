"""Syscall knowledge used everywhere: the valid x86_64 names/numbers, the
high-risk list, short descriptions, and name normalisation.

A name counts as HALLUCINATED if, after trivial normalisation (case, a "sys_"
or "__NR_" prefix, surrounding spaces), it is not in the x86_64 syscall table.
"""
import json
import re
from functools import lru_cache

from . import paths


@lru_cache(maxsize=1)
def table() -> dict:
    """{name: number} for x86_64, generated from <asm/unistd_64.h>."""
    with open(paths.SYSCALL_TABLE, encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def high_risk() -> dict:
    """{name: reason} from config/high_risk.txt."""
    out = {}
    with open(paths.HIGH_RISK, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name, _, reason = line.partition("#")
            out[name.strip()] = reason.strip()
    return out


@lru_cache(maxsize=1)
def descriptions() -> dict:
    with open(paths.DESCRIPTIONS, encoding="utf-8") as f:
        return json.load(f)


def describe(name: str) -> str:
    return descriptions().get(name, "No description available.")


def is_valid(name: str) -> bool:
    return name in table()


def is_high_risk(name: str) -> bool:
    return name in high_risk()


_PREFIX = re.compile(r"^(sys_|__nr_|nr_)", re.IGNORECASE)


def normalize(raw) -> str:
    """Trivial clean-up only. 'SYS_Read ' -> 'read'. We do NOT fix spelling
    mistakes: 'opent' stays 'opent' and is counted as hallucinated."""
    if not isinstance(raw, str):
        return str(raw)
    name = raw.strip().strip("'\"`").strip()
    name = name.split("(")[0].strip()      # "read()" -> "read"
    name = _PREFIX.sub("", name)
    return name.lower()


def classify(names) -> dict:
    """Split a list of names into valid / hallucinated / normalized / duplicates."""
    seen, valid, hallucinated, normalized, duplicates = set(), [], [], [], []
    for raw in names:
        n = normalize(raw)
        if n != raw:
            normalized.append(raw)
        if n in seen:
            duplicates.append(n)
            continue
        seen.add(n)
        (valid if is_valid(n) else hallucinated).append(n)
    return {
        "valid": valid,
        "hallucinated": hallucinated,
        "normalized": normalized,
        "duplicates": duplicates,
        "high_risk": [n for n in valid if is_high_risk(n)],
    }
