"""PERSON B - FAKE model for testing the pipeline WITHOUT Ollama.

!!! NEVER report results from this backend. !!!
It produces random, LLM-like outputs (drops some syscalls, adds others,
sometimes invents a name or breaks the JSON) so that the harness, enforcement,
analysis and visualizer can be tested end to end on any laptop in seconds.
Policies it writes have source "TEST-FAKE-<model>" and the analysis scripts
refuse to include them unless --include-fake is given.
"""
import json
import random
import re

GENERIC = ["read", "write", "openat", "close", "fstat", "newfstatat", "mmap", "munmap", "mprotect", "brk",
           "rt_sigaction", "rt_sigprocmask", "exit_group", "lseek", "ioctl", "getrandom", "futex",
           "unlinkat", "fchmod", "utimensat", "getdents64", "clone3", "mkdirat"]
INVENTED = ["open_file", "readfile", "sys_exit", "fopen", "malloc", "writefile"]


def chat(model, system, user, *, seed=0, **_):
    rng = random.Random(f"{model}|{seed}|{hash(user) & 0xffff}")
    seen = re.findall(r"^- ([a-z0-9_]+)", user, re.M)
    base = seen if seen else rng.sample(GENERIC, 14)
    keep_rate = 0.9 if "8b" in model else 0.8
    allow = [s for s in base if rng.random() < keep_rate or s in ("execve", "exit_group")]
    if any(s in ("ptrace", "unshare", "bpf") for s in allow) and rng.random() < (0.6 if "8b" in model else 0.3):
        allow = [s for s in allow if s not in ("ptrace", "unshare", "bpf")]       # "noticed" the poison
    allow += rng.sample(GENERIC, 4)
    if rng.random() < 0.3:
        allow.append(rng.choice(INVENTED))
    text = json.dumps({"allow": sorted(set(allow)), "notes": "fake backend output"})
    if rng.random() < 0.08:
        text = text[:-3]                                   # broken JSON
    elif rng.random() < 0.3:
        text = "Here is the allow-list:\n```json\n" + text + "\n```"
    return {"text": text, "total_s": 0.0, "load_s": 0.0, "prompt_tokens": len(user) // 4,
            "output_tokens": len(text) // 4, "gen_s": 0.0}
