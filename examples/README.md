# examples/ - sample data so Persons B and C can start before the real traces exist

**Do not report anything from this folder.** It exists only so the harness, analysis
and visualizer can be developed and tested on Windows on day 1.

| Path | What it is |
|---|---|
| `data/gzip/`, `data/worker/` | Real strace traces (training, held-out, poisoned) + summaries, recorded on a test Ubuntu 24.04 machine. Person A re-records ALL traces on the team's Ubuntu laptop; only those go in the report. |
| `data/probe/` | Trace of the harmless escape probe (used by the visualizer's jailbreak scene). |
| `policies/baseline/` | Baseline policies built from those traces. |
| `policies/llm/` | **TEST-FAKE** policies from `harness/fake_backend.py` - random, not from any model. |

Use it with:
```
python visualizer/syscall_jail.py --examples
python harness/prompts.py gzip c --examples
python harness/generate_policies.py --backend fake --data examples/data --programs gzip worker --repeats 1 --out examples_test_out
```
