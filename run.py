"""CLI entry point for CTFBench Claude reproduction.

Usage:
    uv run python run.py audit --model claude-sonnet-4-6
    uv run python run.py judge --label claude-sonnet-4-6
    uv run python run.py plot  --label claude-sonnet-4-6
    uv run python run.py all   --model claude-opus-4-6
"""

import argparse
import asyncio
from pathlib import Path

from src.config import RESULTS_DIR


def _results_dir_for(label: str) -> Path:
    return RESULTS_DIR / label


async def cmd_audit(args: argparse.Namespace) -> Path:
    from src.agent import run_all_audits

    return await run_all_audits(model=args.model)


async def cmd_judge(args: argparse.Namespace) -> Path:
    from src.judge import run_judge

    label = args.label or args.model.replace("/", "_")
    reports_dir = _results_dir_for(label)
    if not reports_dir.exists():
        raise FileNotFoundError(
            f"No results found at {reports_dir}. Run 'audit' first."
        )
    return await run_judge(reports_dir, label)


def cmd_plot(args: argparse.Namespace) -> Path:
    from src.plot import generate_plot

    label = args.label or args.model.replace("/", "_")
    scores_path = _results_dir_for(label) / "scores.json"
    if not scores_path.exists():
        raise FileNotFoundError(f"No scores found at {scores_path}. Run 'judge' first.")
    return generate_plot(scores_path)


async def cmd_all(args: argparse.Namespace) -> None:
    from src.agent import run_all_audits
    from src.judge import run_judge
    from src.plot import generate_plot

    label = args.model.replace("/", "_")

    print("=" * 60)
    print("STEP 1: Running audits")
    print("=" * 60)
    reports_dir = await run_all_audits(model=args.model)

    print("\n" + "=" * 60)
    print("STEP 2: Running judge")
    print("=" * 60)
    scores_path = await run_judge(reports_dir, label)

    print("\n" + "=" * 60)
    print("STEP 3: Generating plot")
    print("=" * 60)
    generate_plot(scores_path)

    print("\n" + "=" * 60)
    print("DONE")
    print("=" * 60)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CTFBench Claude reproduction benchmark"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # audit
    p_audit = sub.add_parser("audit", help="Run Claude agents on all 11 contracts")
    p_audit.add_argument(
        "--model",
        default="claude-sonnet-4-6",
        help="Claude model to use (default: claude-sonnet-4-6)",
    )

    # judge
    p_judge = sub.add_parser("judge", help="Score reports with LLM judge")
    p_judge.add_argument(
        "--model",
        default="claude-sonnet-4-6",
        help="Model whose reports to score (default: claude-sonnet-4-6)",
    )
    p_judge.add_argument("--label", help="Override results directory label")

    # plot
    p_plot = sub.add_parser("plot", help="Generate comparison scatter plot")
    p_plot.add_argument(
        "--model",
        default="claude-sonnet-4-6",
        help="Model whose scores to plot (default: claude-sonnet-4-6)",
    )
    p_plot.add_argument("--label", help="Override results directory label")

    # all
    p_all = sub.add_parser("all", help="Run full pipeline: audit -> judge -> plot")
    p_all.add_argument(
        "--model",
        default="claude-sonnet-4-6",
        help="Claude model to use (default: claude-sonnet-4-6)",
    )

    args = parser.parse_args()

    if args.command == "audit":
        asyncio.run(cmd_audit(args))
    elif args.command == "judge":
        asyncio.run(cmd_judge(args))
    elif args.command == "plot":
        cmd_plot(args)
    elif args.command == "all":
        asyncio.run(cmd_all(args))


if __name__ == "__main__":
    main()
