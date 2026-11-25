# Results summary

Column guide: invalid = no allow-list could be extracted; needed_json_rescue = valid list found only inside extra text; hallucinated = policies with >=1 non-existent syscall name; missing_heldout = syscalls the held-out run needs that the policy lacks; speculative = allowed syscalls seen in neither recorded run.

## Main table (training-trace policies; breakage from real seccomp enforcement)

| condition   |   policies |   invalid_pct |   needed_json_rescue_pct |   hallucinated_pct |   mean_allowed |   mean_high_risk |   mean_missing_heldout |   mean_speculative |   break_pct_training |   break_pct_heldout |
|:------------|-----------:|--------------:|-------------------------:|-------------------:|---------------:|-----------------:|-----------------------:|-------------------:|---------------------:|--------------------:|
| Baseline    |          6 |           0   |                      0   |                0   |           25.2 |             0    |                    4.8 |                0   |                  0   |                 100 |
| 3B / a      |         18 |          33.3 |                     16.7 |               66.7 |           16.5 |             0.11 |                   20.3 |               16.2 |                100   |                 100 |
| 3B / b      |         18 |           0   |                     33.3 |               22.2 |           19.3 |             0    |                   10.6 |                0.7 |                100   |                 100 |
| 3B / c      |         18 |           0   |                     33.3 |               11.1 |           19.1 |             0    |                   10.7 |                0.6 |                100   |                 100 |
| 8B / a      |         18 |           5.6 |                      0   |               38.9 |           14   |             0.06 |                   19.9 |                6.3 |                100   |                 100 |
| 8B / b      |         18 |           0   |                      0   |                0   |           22.5 |             0    |                    7.6 |                0.1 |                 77.8 |                 100 |
| 8B / c      |         18 |           0   |                     11.1 |                0   |           20.4 |             0    |                    9.4 |                0   |                 88.9 |                 100 |

## Syscalls that killed programs most often (what each source forgets)

| model    | blocked_syscall   |   times |
|:---------|:------------------|--------:|
| 3B       | arch_prctl        |      26 |
| 3B       | brk               |      24 |
| 3B       | mprotect          |      12 |
| 3B       | access            |      10 |
| 3B       | fstat             |      10 |
| 3B       | close             |       6 |
| 3B       | exit_group        |       3 |
| 3B       | prlimit64         |       2 |
| 8B       | brk               |      30 |
| 8B       | read              |      24 |
| 8B       | arch_prctl        |      10 |
| 8B       | prlimit64         |      10 |
| 8B       | geteuid           |       4 |
| 8B       | mkdirat           |       4 |
| 8B       | ioctl             |       3 |
| 8B       | rt_sigaction      |       3 |
| Baseline | rt_sigaction      |       2 |
| Baseline | getdents64        |       1 |
| Baseline | geteuid           |       1 |
| Baseline | mkdirat           |       1 |
| Baseline | mremap            |       1 |

## Replay vs real enforcement

Replay predicted the real outcome in **100.0%** of 214 runs (disagreements = paths where the program behaves differently under the filter).

## Poisoned trace (policies built from the compromised run)

| condition   |   pct_policies_keeping_injected |   mean_injected_kept_of_3 |
|:------------|--------------------------------:|--------------------------:|
| Baseline    |                           100   |                       3   |
| 3B / b      |                            66.7 |                       1.7 |
| 3B / c      |                            94.4 |                       2.6 |
| 8B / b      |                            11.1 |                       0.3 |
| 8B / c      |                             5.6 |                       0.1 |

## H3: more information vs bigger model (held-out breakage %)

By prompt style (averaged over models): a=100.0%, b=100.0%, c=100.0%

By model (averaged over prompts): 3B=100.0%, 8B=100.0%

Prompt effect (a -> c): +0.0 points; model effect (spread): 0.0 points. H3 is supported if the prompt effect is larger than the model effect.

## Containment validation

1850/1850 probe outcomes matched the policy (enforcement works as specified). Dangerous calls that reached the kernel: 101.
