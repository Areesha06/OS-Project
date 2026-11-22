#!/usr/bin/env python3
"""PERSON C - figures and summary tables for the report (runs on Windows).

Inputs : results/policy_metrics.csv  (analysis/evaluate_policies.py)
         results/enforcement.csv     (enforce/run_enforcement.py, Person A) - optional:
                                     if missing, breakage falls back to REPLAY predictions
         results/containment.csv     (enforce/run_containment.py)           - optional
Outputs: results/figures/fig1_breakage.png        H1: breakage on training vs held-out run
         results/figures/fig2_attack_surface.png  allowed syscalls and high-risk syscalls
         results/figures/fig3_invalid_output.png  H2: invalid JSON and hallucinated names
         results/figures/fig4_poisoned_trace.png  extension: does anyone copy injected syscalls?
         results/figures/fig5_heatmap_<prog>.png  which syscalls each condition allows
         results/summary.md                       every number the report needs, incl. H3 check

"Condition" = baseline, or model + prompt style (e.g. "8B / c").
Usage: python analysis/make_figures.py [--include-fake] [--heatmap-program gzip]
"""
import argparse
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sandboxlab import paths, strace_parser, syscalls  # noqa: E402

# Categorical slots (validated palette): blue, orange, aqua. Text stays neutral.
C1, C2, C3 = "#2a78d6", "#eb6834", "#1baf7a"
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e4e3df"
SEQ = "Blues"

plt.rcParams.update({
    "font.size": 10, "axes.edgecolor": MUTED, "axes.labelcolor": INK, "xtick.color": MUTED,
    "ytick.color": MUTED, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "axes.grid.axis": "y", "grid.color": GRID, "grid.linewidth": 0.8,
    "axes.axisbelow": True, "legend.frameon": False, "figure.dpi": 150,
})


def short_model(src):
    s = str(src)
    if s == "baseline":
        return "Baseline"
    for tag in ("1b", "3b", "7b", "8b", "13b"):
        if tag in s.lower():
            return ("FAKE " if s.startswith("TEST-FAKE") else "") + tag.upper()
    return s


def condition(row):
    m = short_model(row["source"])
    return m if m == "Baseline" else f"{m} / {row['prompt']}"


def order(conds):
    def key(c):
        return (0, "", "") if c == "Baseline" else (1, c.split(" / ")[0], c.split(" / ")[-1])
    return sorted(conds, key=key)


def bar(ax, labels, values, color, fmt="{:.0f}", offset=0.0, width=0.8, label=None):
    xs = [i + offset for i in range(len(labels))]
    bars = ax.bar(xs, values, width=width, color=color, label=label, edgecolor="white", linewidth=1)
    for x, v in zip(xs, values):
        if pd.notna(v):
            ax.text(x, v, fmt.format(v), ha="center", va="bottom", fontsize=8, color=INK)
    return bars


def save(fig, name):
    paths.FIGURES.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(paths.FIGURES / name, bbox_inches="tight")
    plt.close(fig)
    print(f"  figure -> results/figures/{name}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--include-fake", action="store_true")
    ap.add_argument("--heatmap-program", default="gzip")
    args = ap.parse_args()

    pm = pd.read_csv(paths.RESULTS / "policy_metrics.csv")
    if not args.include_fake:
        pm = pm[~pm["source"].astype(str).str.startswith("TEST-FAKE")]
    if pm.empty:
        sys.exit("no policies to analyse")
    pm["condition"] = pm.apply(condition, axis=1)
    md = ["# Results summary", ""]
    if pm["source"].astype(str).str.startswith("TEST-FAKE").any():
        md += ["> **WARNING: contains TEST-FAKE policies. These numbers are NOT results.**", ""]

    # ---------------- breakage: real enforcement if available, else replay
    enf_file = paths.RESULTS / "enforcement.csv"
    clean = pm[pm["trace_used"] == "training"]
    if enf_file.exists():
        enf = pd.read_csv(enf_file)
        enf = enf[enf["status"] == "ran"].merge(clean[["policy_file", "condition"]], on="policy_file")
        enf["broke"] = ~enf["passed"].astype(str).str.lower().eq("true")
        brk = enf.pivot_table(index="condition", columns="run_tested", values="broke", aggfunc="mean") * 100
        brk_n = enf.groupby("condition")["policy_file"].nunique()
        method = "real seccomp enforcement"
    else:
        enf = None
        v = clean[clean["json_valid"]]
        surv = lambda col: v.groupby("condition")[col].apply(lambda x: x.astype(str).str.lower().eq("true").mean())
        brk = pd.DataFrame({"training": 100 * (1 - surv("replay_training_survives")),
                            "heldout": 100 * (1 - surv("replay_heldout_survives"))})
        brk_n = v.groupby("condition")["policy_file"].nunique()
        method = "replay prediction (enforcement.csv not found)"
    conds = order(brk.index)
    brk = brk.reindex(conds)

    fig, ax = plt.subplots(figsize=(max(6, 1.0 * len(conds) + 2), 3.8))
    bar(ax, conds, brk.get("training", pd.Series(index=conds)).fillna(0).values, C1, offset=-0.2, width=0.38, label="Training run (seen)")
    bar(ax, conds, brk.get("heldout", pd.Series(index=conds)).fillna(0).values, C2, offset=0.2, width=0.38, label="Held-out run (unseen)")
    ax.set_xticks(range(len(conds)), conds)
    ax.set_ylabel("Runs broken (%)")
    ax.set_ylim(0, 110)
    ax.set_title(f"Fig. 1  Breakage rate by policy source  ({method}; valid policies only)", fontsize=10, loc="left")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.12), ncols=2)
    save(fig, "fig1_breakage.png")

    # ---------------- attack surface (two separate panels, no dual axis)
    v = pm[(pm["trace_used"] == "training") & pm["json_valid"]]
    att = v.groupby("condition").agg(n_allowed=("n_allowed", "mean"), n_high_risk=("n_high_risk", "mean"),
                                     speculative=("speculative", "mean")).reindex(order(v["condition"].unique()))
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(max(8, 1.6 * len(att) + 2), 3.6))
    bar(a1, att.index, att["n_allowed"].values, C1, "{:.1f}")
    a1.set_xticks(range(len(att)), att.index, rotation=30, ha="right")
    a1.set_title("Allowed syscalls per policy (mean)", fontsize=10, loc="left")
    bar(a2, att.index, att["n_high_risk"].values, C1, "{:.2f}")
    a2.set_xticks(range(len(att)), att.index, rotation=30, ha="right")
    a2.set_title("High-risk syscalls allowed (mean)", fontsize=10, loc="left")
    fig.suptitle("Fig. 2  Attack surface (lower is better, if nothing breaks)", fontsize=10, x=0.01, ha="left")
    save(fig, "fig2_attack_surface.png")

    # ---------------- invalid output (LLM only)
    llm = pm[pm["source"] != "baseline"]
    if not llm.empty:
        inv = llm.groupby("condition").agg(
            invalid_pct=("json_valid", lambda s: 100 * (1 - s.astype(bool).mean())),
            halluc_pct=("n_hallucinated", lambda s: 100 * (s > 0).mean()),
            halluc_mean=("n_hallucinated", "mean")).reindex(order(llm["condition"].unique()))
        fig, (a1, a2) = plt.subplots(1, 2, figsize=(max(8, 1.6 * len(inv) + 2), 3.6))
        bar(a1, inv.index, inv["invalid_pct"].values, C3, "{:.0f}%")
        a1.set_xticks(range(len(inv)), inv.index, rotation=30, ha="right")
        a1.set_ylim(0, 105)
        a1.set_title("Unparseable output (% of generations)", fontsize=10, loc="left")
        bar(a2, inv.index, inv["halluc_pct"].values, C3, "{:.0f}%")
        a2.set_xticks(range(len(inv)), inv.index, rotation=30, ha="right")
        a2.set_ylim(0, 105)
        a2.set_title("Policies with >=1 hallucinated syscall name (%)", fontsize=10, loc="left")
        fig.suptitle("Fig. 3  Invalid output from the LLMs", fontsize=10, x=0.01, ha="left")
        save(fig, "fig3_invalid_output.png")

    # ---------------- poisoned trace
    poi = pm[(pm["trace_used"] == "poisoned") & pm["json_valid"]]
    if not poi.empty:
        pz = poi.groupby("condition").agg(any_kept=("poison_kept", lambda s: 100 * (s > 0).mean()),
                                          mean_kept=("poison_kept", "mean")).reindex(order(poi["condition"].unique()))
        fig, ax = plt.subplots(figsize=(max(6, 1.1 * len(pz) + 2), 3.6))
        bar(ax, pz.index, pz["any_kept"].values, C2, "{:.0f}%")
        ax.set_xticks(range(len(pz)), pz.index)
        ax.set_ylim(0, 110)
        ax.set_ylabel("Policies allowing an injected call (%)")
        ax.set_title("Fig. 4  Poisoned trace: who copies ptrace / unshare / bpf into the allow-list?", fontsize=10, loc="left")
        save(fig, "fig4_poisoned_trace.png")

    # ---------------- heatmap for one program
    prog = args.heatmap_program
    hp = pm[(pm["program"] == prog) & (pm["trace_used"] == "training") & pm["json_valid"]]
    if not hp.empty:
        from sandboxlab import policy as pol
        tr = set(strace_parser.summarize(strace_parser.parse_file(paths.trace_path(prog, "training"))))
        ho = set(strace_parser.summarize(strace_parser.parse_file(paths.trace_path(prog, "heldout"))))
        frac = {}
        for c, grp in hp.groupby("condition"):
            counts = {}
            for f in grp["policy_file"]:
                for s in syscalls.classify(pol.load_policy(paths.ROOT / f)["allow"])["valid"]:
                    counts[s] = counts.get(s, 0) + 1
            frac[c] = {s: n / len(grp) for s, n in counts.items()}
        rows_ = sorted(tr | ho | {s for d in frac.values() for s in d},
                       key=lambda s: (0 if s in tr else 1 if s in ho else 2, s))
        cols = order(frac)
        mat = pd.DataFrame([[frac[c].get(s, 0.0) for c in cols] for s in rows_], index=rows_, columns=cols)
        fig, ax = plt.subplots(figsize=(1.0 * len(cols) + 3, 0.22 * len(rows_) + 1.5))
        im = ax.imshow(mat.values, aspect="auto", cmap=SEQ, vmin=0, vmax=1)
        ax.set_xticks(range(len(cols)), cols, rotation=30, ha="right")
        labels = [f"{s}  {'T' if s in tr else ('H' if s in ho else '-')}{' !' if syscalls.is_high_risk(s) else ''}" for s in rows_]
        ax.set_yticks(range(len(rows_)), labels, fontsize=7)
        ax.grid(False)
        cb = fig.colorbar(im, ax=ax, fraction=0.04)
        cb.set_label("Share of policies allowing it")
        ax.set_title(f"Fig. 5  {prog}: T = in training trace, H = only needed by held-out run, - = in neither, ! = high risk",
                     fontsize=9, loc="left")
        save(fig, f"fig5_heatmap_{prog}.png")

    # ---------------- summary.md
    tab = pm[pm["trace_used"] == "training"].groupby("condition").agg(
        policies=("policy_file", "count"),
        invalid_pct=("json_valid", lambda s: round(100 * (1 - s.astype(bool).mean()), 1)),
        needed_json_rescue_pct=("extraction", lambda s: round(100 * s.isin(["embedded", "list-fallback"]).mean(), 1)),
        hallucinated_pct=("n_hallucinated", lambda s: round(100 * (s > 0).mean(), 1)),
        mean_allowed=("n_allowed", lambda s: round(s.mean(), 1)),
        mean_high_risk=("n_high_risk", lambda s: round(s.mean(), 2)),
        mean_missing_heldout=("missing_heldout", lambda s: round(pd.to_numeric(s, errors="coerce").mean(), 1)),
        mean_speculative=("speculative", lambda s: round(pd.to_numeric(s, errors="coerce").mean(), 1)),
    ).reindex(order(pm[pm["trace_used"] == "training"]["condition"].unique()))
    tab = tab.join(brk.reindex(columns=[c for c in ("training", "heldout") if c in brk.columns]).round(1).add_prefix("break_pct_"))
    md += ["Column guide: invalid = no allow-list could be extracted; needed_json_rescue = valid list found only "
           "inside extra text; hallucinated = policies with >=1 non-existent syscall name; missing_heldout = syscalls "
           "the held-out run needs that the policy lacks; speculative = allowed syscalls seen in neither recorded run.", ""]
    md += [f"## Main table (training-trace policies; breakage from {method})", "", tab.to_markdown(), ""]

    if enf is not None and not enf.empty:
        miss = enf[enf["broke"] & enf["blocked_syscall"].notna()]
        if not miss.empty:
            top = (miss.assign(model=miss["condition"].str.split(" / ").str[0])
                   .groupby(["model", "blocked_syscall"]).size().rename("times").reset_index()
                   .sort_values(["model", "times"], ascending=[True, False]).groupby("model").head(8))
            md += ["## Syscalls that killed programs most often (what each source forgets)", "", top.to_markdown(index=False), ""]
        rp = enf.merge(pm[["policy_file", "replay_training_survives", "replay_heldout_survives"]], on="policy_file")
        rp["replay_pass"] = rp.apply(lambda r: str(r[f"replay_{r['run_tested']}_survives"]).lower() == "true", axis=1)
        agree = 100 * (rp["replay_pass"] == ~rp["broke"]).mean()
        md += ["## Replay vs real enforcement", "",
               f"Replay predicted the real outcome in **{agree:.1f}%** of {len(rp)} runs "
               "(disagreements = paths where the program behaves differently under the filter).", ""]

    if not poi.empty:
        md += ["## Poisoned trace (policies built from the compromised run)", "",
               pz.round(1).rename(columns={"any_kept": "pct_policies_keeping_injected", "mean_kept": "mean_injected_kept_of_3"}).to_markdown(), ""]

    llm_t = pm[(pm["source"] != "baseline") & (pm["trace_used"] == "training") & pm["json_valid"]].copy()
    if enf is not None and not llm_t.empty:
        held = enf[enf["run_tested"] == "heldout"][["policy_file", "broke"]]
        llm_t = llm_t.merge(held, on="policy_file")
        llm_t["model"] = llm_t["source"].map(short_model)
        if llm_t["model"].nunique() > 1 and llm_t["prompt"].nunique() > 1:
            by_prompt = llm_t.groupby("prompt")["broke"].mean() * 100
            by_model = llm_t.groupby("model")["broke"].mean() * 100
            md += ["## H3: more information vs bigger model (held-out breakage %)", "",
                   "By prompt style (averaged over models): " + ", ".join(f"{k}={v:.1f}%" for k, v in by_prompt.items()),
                   "", "By model (averaged over prompts): " + ", ".join(f"{k}={v:.1f}%" for k, v in by_model.items()),
                   "", f"Prompt effect (a -> c): {by_prompt.get('a', float('nan')) - by_prompt.get('c', float('nan')):+.1f} points; "
                   f"model effect (spread): {by_model.max() - by_model.min():.1f} points. "
                   "H3 is supported if the prompt effect is larger than the model effect.", ""]

    cont = paths.RESULTS / "containment.csv"
    if cont.exists():
        c = pd.read_csv(cont)
        if not args.include_fake:
            c = c[~c["source"].astype(str).str.startswith("TEST-FAKE")]
        md += ["## Containment validation", "",
               f"{int(c['matches'].sum())}/{len(c)} probe outcomes matched the policy "
               f"(enforcement works as specified). Dangerous calls that reached the kernel: "
               f"{int((c['outcome'] == 'REACHED_KERNEL').sum())}.", ""]

    (paths.RESULTS / "summary.md").write_text("\n".join(md), encoding="utf-8")
    print("  summary -> results/summary.md")


if __name__ == "__main__":
    main()
