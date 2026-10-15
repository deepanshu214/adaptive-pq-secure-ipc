"""Draws the evaluation figures from the CSV files written by `aspe all`.

Usage (from the project root):
    python scripts/plot_results.py [--results results] [--out results/figures]
"""
import argparse
import csv
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

# Reference palette (light mode): categorical slots in fixed order + neutrals.
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"
YELLOW, MAGENTA = "#eda100", "#e87ba4"
INK, INK_2, INK_3 = "#0b0b0b", "#52514e", "#8a8984"
GRID, NEUTRAL_BAR, SURFACE = "#e4e3df", "#b9b8b2", "#fcfcfb"
PHASE_FILL = "#f1f0ec"

LEVELS = ["L1-BASIC", "L2-CLASSICAL", "L3-HYBRID", "L4-PQ", "L5-STRONG-PQ"]


def style():
    plt.rcParams.update({
        "figure.facecolor": SURFACE, "axes.facecolor": SURFACE,
        "savefig.facecolor": SURFACE, "font.size": 9,
        "axes.edgecolor": GRID, "axes.labelcolor": INK_2,
        "axes.titlesize": 10, "axes.titleweight": "bold", "axes.titlecolor": INK,
        "axes.titlelocation": "left", "axes.grid": True, "grid.color": GRID,
        "grid.linewidth": 0.6, "axes.axisbelow": True,
        "xtick.color": INK_2, "ytick.color": INK_2,
        "axes.spines.top": False, "axes.spines.right": False,
        "legend.frameon": False, "lines.linewidth": 2,
    })


def read_csv(path):
    with open(path, newline="") as handle:
        return list(csv.DictReader(handle))


def save(fig, out_dir, name):
    path = os.path.join(out_dir, name)
    fig.savefig(path, dpi=200, bbox_inches="tight")
    plt.close(fig)
    print("  wrote", path)


def fig_static_vs_adaptive(results, out_dir):
    rows = read_csv(os.path.join(results, "static_vs_adaptive.csv"))
    names = [r["strategy"] for r in rows]
    cpu = [float(r["mean_cpu_us"]) for r in rows]
    viol = [100 * float(r["floor_violations"]) for r in rows]
    colors = [BLUE if n.startswith("Adaptive") else NEUTRAL_BAR for n in names]

    fig, (a, b) = plt.subplots(1, 2, figsize=(9, 3.4), sharey=True)
    y = range(len(names))
    a.barh(y, viol, color=colors, height=0.6)
    a.set_title("Security failures (below mandatory floor)")
    a.set_xlabel("messages, %")
    for i, v in enumerate(viol):
        a.text(v + 1, i, f"{v:.1f}%", va="center", color=INK, fontsize=8)
    a.set_xlim(0, max(viol) * 1.2 + 1)
    b.barh(y, cpu, color=colors, height=0.6)
    b.set_xscale("log")
    b.set_title("Mean crypto CPU per message (log scale)")
    b.set_xlabel("microseconds, embedded platform")
    for i, v in enumerate(cpu):
        b.text(v * 1.15, i, f"{v:,.0f} us", va="center", color=INK, fontsize=8)
    b.set_xlim(10, max(cpu) * 6)
    a.set_yticks(list(y))
    a.set_yticklabels(names)
    a.invert_yaxis()
    a.grid(axis="y", visible=False)
    b.grid(axis="y", visible=False)
    fig.suptitle("Static vs adaptive security on 5000 IPC messages", x=0.01, ha="left",
                 fontweight="bold", color=INK)
    fig.tight_layout()
    save(fig, out_dir, "fig_static_vs_adaptive.png")


def shade_phases(ax, rows):
    phases, start, current = [], 0, rows[0]["phase"]
    for r in rows:
        if r["phase"] != current:
            phases.append((current, start, int(r["second"])))
            current, start = r["phase"], int(r["second"])
    phases.append((current, start, int(rows[-1]["second"]) + 1))
    for i, (_, s, e) in enumerate(phases):
        if i % 2 == 1:
            ax.axvspan(s, e, color=PHASE_FILL, zorder=0)
    return phases


def fig_timeseries(results, out_dir):
    rows = read_csv(os.path.join(results, "simulation_timeseries.csv"))
    series = [("Static POST_QUANTUM", ORANGE), ("Adaptive (risk only)", AQUA),
              ("Adaptive (full)", BLUE)]
    by = {name: [r for r in rows if r["strategy"] == name] for name, _ in series}

    fig, axes = plt.subplots(3, 1, figsize=(9, 7), sharex=True)
    panels = [("total_cpu_percent", "Total CPU utilisation, %", None),
              ("mean_latency_ms", "Mean IPC latency, ms (log)", "log"),
              ("mean_level", "Mean security level (1 = BASIC ... 5 = STRONG-PQ); "
                             "both adaptive variants overlap", None)]
    for ax, (key, title, scale) in zip(axes, panels):
        phases = shade_phases(ax, by["Adaptive (full)"])
        for name, color in series:
            t = [int(r["second"]) for r in by[name]]
            v = [max(float(r[key]), 1e-3) for r in by[name]]
            ax.plot(t, v, color=color, label=name, linewidth=1.6)
        ax.set_title(title)
        if scale:
            ax.set_yscale(scale)
    for name, s, e in phases:
        axes[0].text((s + e) / 2, 103, name, ha="center", va="bottom", fontsize=7.5, color=INK_2)
    axes[0].set_ylim(0, 112)
    axes[2].set_xlabel("time, s")
    axes[0].legend(loc="upper left", bbox_to_anchor=(0, -0.08), ncol=3, fontsize=8)
    fig.tight_layout()
    save(fig, out_dir, "fig_simulation_timeseries.png")


def fig_monitors(results, out_dir):
    rows = [r for r in read_csv(os.path.join(results, "simulation_timeseries.csv"))
            if r["strategy"] == "Adaptive (full)"]
    t = [int(r["second"]) for r in rows]
    fig, (a, b) = plt.subplots(2, 1, figsize=(9, 3.8), sharex=True)
    shade_phases(a, rows)
    shade_phases(b, rows)
    a.step(t, [int(r["estimated_threat"]) for r in rows], where="post", color=BLUE)
    a.set_yticks([0, 1, 2, 3])
    a.set_yticklabels(["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    a.set_title("Threat level estimated by the threat monitor")
    b.plot(t, [float(r["compromised_trust"]) for r in rows], color=BLUE)
    b.axhline(0.4, color=INK_3, linewidth=1, linestyle="--")
    b.text(2, 0.42, "LOW-trust boundary (0.40)", fontsize=7.5, color=INK_2)
    b.set_ylim(0, 1)
    b.set_title("Trust of the compromised process (prior 0.85)")
    b.set_xlabel("time, s")
    fig.tight_layout()
    save(fig, out_dir, "fig_runtime_monitors.png")


def fig_resource_sweep(results, out_dir):
    rows = read_csv(os.path.join(results, "resource_sweep.csv"))
    scenarios = ["Status", "Gaze", "Profile", "Emergency", "Alert"]
    colors = [BLUE, ORANGE, AQUA, YELLOW, MAGENTA]
    fig, ax = plt.subplots(figsize=(9, 3.6))
    for x0, x1 in [(30, 70), (85, 100)]:
        ax.axvspan(x0, x1, color=PHASE_FILL, zorder=0)
    for label, x in [("IDLE", 18), ("NORMAL", 50), ("ELEVATED", 77.5), ("CONSTRAINED", 92)]:
        ax.text(x, 9000, label, ha="center", fontsize=7.5, color=INK_2)
    for name, color in zip(scenarios, colors):
        pts = [r for r in rows if r["scenario"] == name]
        x = [float(r["cpu_percent"]) for r in pts]
        y = [float(r["cpu_us"]) for r in pts]
        ax.plot(x, y, color=color, marker="o", markersize=3.5, label=name)
    ax.set_yscale("log")
    ax.set_ylim(3, 15000)
    ax.set_xlim(8, 100)
    ax.set_xlabel("CPU utilisation, %")
    ax.set_ylabel("crypto cost per message, us")
    ax.set_title("Phase 5: per-message protection cost chosen as CPU load rises")
    ax.legend(loc="upper left", bbox_to_anchor=(0, -0.18), ncol=5, fontsize=8)
    fig.tight_layout()
    save(fig, out_dir, "fig_resource_sweep.png")


def fig_confusion(results, out_dir):
    rows = read_csv(os.path.join(results, "classification.csv"))
    m = [[0] * 5 for _ in range(5)]
    for r in rows:
        m[int(r["required_level"]) - 1][int(r["engine_level"]) - 1] += 1
    fig, ax = plt.subplots(figsize=(5.4, 4.2))
    ax.imshow(m, cmap="Blues")
    ax.grid(False)
    peak = max(max(row) for row in m)
    for i in range(5):
        for j in range(5):
            ax.text(j, i, m[i][j], ha="center", va="center", fontsize=9,
                    color="white" if m[i][j] > peak * 0.55 else INK)
    ax.set_xticks(range(5))
    ax.set_yticks(range(5))
    ax.set_xticklabels([level.split("-", 1)[1] for level in LEVELS], fontsize=8)
    ax.set_yticklabels([level.split("-", 1)[1] for level in LEVELS], fontsize=8)
    ax.set_xlabel("engine level")
    ax.set_ylabel("reference level")
    ax.set_title("Phase 3: classification vs reference policy")
    fig.tight_layout()
    save(fig, out_dir, "fig_confusion_matrix.png")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--results", default="results")
    parser.add_argument("--out", default=os.path.join("results", "figures"))
    args = parser.parse_args()

    needed = ["static_vs_adaptive.csv", "simulation_timeseries.csv", "resource_sweep.csv",
              "classification.csv"]
    missing = [n for n in needed if not os.path.exists(os.path.join(args.results, n))]
    if missing:
        sys.exit("missing " + ", ".join(missing) + " - run `aspe all` first")

    os.makedirs(args.out, exist_ok=True)
    style()
    fig_static_vs_adaptive(args.results, args.out)
    fig_timeseries(args.results, args.out)
    fig_monitors(args.results, args.out)
    fig_resource_sweep(args.results, args.out)
    fig_confusion(args.results, args.out)


if __name__ == "__main__":
    main()
