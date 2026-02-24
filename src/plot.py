"""Scatter plot generation — VDR vs OI comparison with CTFBench leaderboard."""

import json
from pathlib import Path

import matplotlib.pyplot as plt

from src.config import LEADERBOARD, RESULTS_DIR

# Anthropic brand red
ANTHROPIC_RED = "#D97757"


def generate_plot(scores_path: Path, output_path: Path | None = None) -> Path:
    """Generate a VDR vs OI scatter plot comparing Claude to CTFBench leaderboard.

    Args:
        scores_path: Path to scores.json from the judge step.
        output_path: Where to save the PNG. Defaults to results/plot.png.

    Returns:
        Path to the saved plot.
    """
    scores = json.loads(scores_path.read_text(encoding="utf-8"))
    claude_vdr = scores["vdr"]
    claude_oi = scores["oi"]
    label = scores["label"]

    fig, ax = plt.subplots(figsize=(10, 7))

    # Plot existing leaderboard entries
    for name, vdr, oi in LEADERBOARD:
        ax.scatter(oi, vdr, c="gray", s=50, alpha=0.7, zorder=2)
        ax.annotate(
            name,
            (oi, vdr),
            textcoords="offset points",
            xytext=(6, 4),
            fontsize=7,
            color="gray",
        )

    # Plot Claude result as a star
    ax.scatter(
        claude_oi,
        claude_vdr,
        c=ANTHROPIC_RED,
        s=200,
        marker="*",
        zorder=3,
        edgecolors="black",
        linewidths=0.5,
        label=label,
    )
    ax.annotate(
        label,
        (claude_oi, claude_vdr),
        textcoords="offset points",
        xytext=(8, 6),
        fontsize=9,
        fontweight="bold",
        color=ANTHROPIC_RED,
    )

    # Axes
    ax.set_xlabel("OI (Overreporting Index) — lower is better", fontsize=11)
    ax.set_ylabel("VDR (Vulnerability Detection Rate) — higher is better", fontsize=11)
    ax.set_title("CTFBench: AI Smart Contract Auditor Comparison", fontsize=13)
    ax.set_xlim(-0.005, max(oi for _, _, oi in LEADERBOARD) + 0.02)
    ax.set_ylim(-0.05, 1.05)
    ax.grid(True, alpha=0.3)

    # Ideal zone annotation
    ax.annotate(
        "ideal",
        (0.0, 1.0),
        textcoords="offset points",
        xytext=(8, -12),
        fontsize=8,
        fontstyle="italic",
        color="green",
        alpha=0.6,
    )

    fig.tight_layout()

    out = output_path or RESULTS_DIR / "plot.png"
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"Plot saved to {out}")
    return out
