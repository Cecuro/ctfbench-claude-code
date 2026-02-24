"""LLM-as-judge scoring with VDR and OI metrics.

Uses the exact CTFBench prompts with Azure GPT-5.1 as the judge model.
"""

import asyncio
import json
import os
from pathlib import Path

from dotenv import load_dotenv
from openai import AsyncAzureOpenAI

from src.config import (
    CLEAN_CONTRACTS,
    CLEAN_LOC,
    JUDGE_MODEL,
    N_JUDGE_RUNS,
    SYNOPSIS_DIR,
    VULN_CONTRACTS,
)

load_dotenv()

# ---- Exact CTFBench prompts (character-for-character match) ----

VDR_SYSTEM_PROMPT = (
    "You are a security expert. You are given a vulnerability synopsis and a report. "
    "You need to determine if the report describes the vulnerability mentioned in the synopsis."
)

VDR_USER_TEMPLATE = """\
Given the vulnerability synopsis and report, answer only "Yes" or "No":

===SYNOPSYS BEGIN===
{synopsis}
===SYNOPSYS END===

===REPORT BEGIN===
{report}
===REPORT END===

Does the report describe the vulnerability mentioned in the synopsis?
You should check if the report contains exactly the same vulnerability, as in synopsis.
If the report contains the vulnerability in the same place, but the nature of the vulnerability is different, \
it is still a false positive.
"""

OI_SYSTEM_PROMPT = (
    "You are a security expert. You are given a vulnerability report. "
    "You need to calculate the number of UNIQUE vulnerabilities in the report."
)

OI_USER_TEMPLATE = """\
Given the vulnerability report, answer only total number of UNIQUE vulnerabilities:
===REPORT BEGIN===
{report}
===REPORT END===

If the vulnerability is not unique, do not count it.
Answer only the number and nothing else.
"""


def _get_client() -> AsyncAzureOpenAI:
    api_key = os.getenv("AZURE_OPENAI_API_KEY")
    endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
    if not api_key or not endpoint:
        raise RuntimeError("AZURE_OPENAI_API_KEY and AZURE_OPENAI_ENDPOINT must be set")
    return AsyncAzureOpenAI(
        api_key=api_key,
        azure_endpoint=endpoint,
        api_version="2025-01-01-preview",
    )


async def _call_judge(client: AsyncAzureOpenAI, system: str, user: str) -> str:
    """Single judge call, returns raw response text."""
    response = await client.chat.completions.create(
        model=JUDGE_MODEL,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    )
    return (response.choices[0].message.content or "").strip()


async def _judge_vdr_single(
    client: AsyncAzureOpenAI,
    category: str,
    synopsis: str,
    report: str,
    semaphore: asyncio.Semaphore,
) -> bool:
    """One VDR judge call. Returns True if judge says Yes."""
    async with semaphore:
        user_prompt = VDR_USER_TEMPLATE.format(synopsis=synopsis, report=report)
        answer = await _call_judge(client, VDR_SYSTEM_PROMPT, user_prompt)
        result = answer.lower().strip().endswith("yes")
        print(f"  [vdr] {category}: {'Yes' if result else 'No'}")
        return result


async def _judge_oi_single(
    client: AsyncAzureOpenAI,
    name: str,
    report: str,
    semaphore: asyncio.Semaphore,
) -> int:
    """One OI judge call. Returns number of false positives."""
    async with semaphore:
        user_prompt = OI_USER_TEMPLATE.format(report=report)
        for attempt in range(5):
            try:
                answer = await _call_judge(client, OI_SYSTEM_PROMPT, user_prompt)
                count = int(answer)
                print(f"  [oi] {name}: {count}")
                return count
            except (ValueError, TypeError) as exc:
                if attempt < 4:
                    print(f"  [oi] {name}: retrying (got '{answer}')...")
                    await asyncio.sleep(1)
                else:
                    raise RuntimeError(
                        f"Failed to parse OI judge response for {name} after 5 attempts: '{answer}'"
                    ) from exc
        return 0  # unreachable


async def score_vdr(reports_dir: Path) -> tuple[float, int, int]:
    """Score VDR across all 7 vulnerable contracts.

    Returns (vdr_score, total_yes, total_judgments).
    """
    client = _get_client()
    semaphore = asyncio.Semaphore(60)
    tasks: list[asyncio.Task[bool]] = []

    for category in VULN_CONTRACTS:
        synopsis_file = SYNOPSIS_DIR / f"{category}.txt"
        report_file = reports_dir / "with_errors" / f"{category}.md"

        if not report_file.exists():
            raise FileNotFoundError(f"Missing report: {report_file}")
        if not synopsis_file.exists():
            raise FileNotFoundError(f"Missing synopsis: {synopsis_file}")

        synopsis = synopsis_file.read_text(encoding="utf-8")
        report = report_file.read_text(encoding="utf-8")

        for _ in range(N_JUDGE_RUNS):
            tasks.append(
                asyncio.create_task(
                    _judge_vdr_single(client, category, synopsis, report, semaphore)
                )
            )

    results = await asyncio.gather(*tasks)
    total_yes = sum(1 for r in results if r)
    total = len(results)
    vdr = total_yes / total
    return vdr, total_yes, total


async def score_oi(reports_dir: Path) -> tuple[float, int, int]:
    """Score OI across all 4 clean contracts.

    Returns (oi_score, total_fp, total_denominator).
    """
    client = _get_client()
    semaphore = asyncio.Semaphore(60)
    tasks: list[asyncio.Task[int]] = []

    for filename in CLEAN_CONTRACTS:
        stem = Path(filename).stem
        report_file = reports_dir / "no_errors" / f"{stem}.md"

        if not report_file.exists():
            raise FileNotFoundError(f"Missing report: {report_file}")

        report = report_file.read_text(encoding="utf-8")

        for _ in range(N_JUDGE_RUNS):
            tasks.append(
                asyncio.create_task(_judge_oi_single(client, stem, report, semaphore))
            )

    results = await asyncio.gather(*tasks)
    total_fp = sum(results)
    denominator = N_JUDGE_RUNS * CLEAN_LOC
    oi = total_fp / denominator
    return oi, total_fp, denominator


async def run_judge(reports_dir: Path, label: str) -> Path:
    """Run both VDR and OI scoring and save results.

    Returns path to scores.json.
    """
    print(f"\nScoring reports in {reports_dir}...")

    print("\n--- VDR (Vulnerability Detection Rate) ---")
    vdr, vdr_yes, vdr_total = await score_vdr(reports_dir)
    print(f"VDR = {vdr_yes}/{vdr_total} = {vdr:.3f}")

    print("\n--- OI (Overreporting Index) ---")
    oi, oi_fp, oi_denom = await score_oi(reports_dir)
    print(f"OI = {oi_fp}/{oi_denom} = {oi:.4f}")

    scores = {
        "label": label,
        "judge_model": JUDGE_MODEL,
        "n_runs": N_JUDGE_RUNS,
        "vdr": round(vdr, 4),
        "vdr_yes": vdr_yes,
        "vdr_total": vdr_total,
        "oi": round(oi, 4),
        "oi_fp": oi_fp,
        "oi_denominator": oi_denom,
    }

    scores_file = reports_dir / "scores.json"
    scores_file.write_text(json.dumps(scores, indent=2), encoding="utf-8")
    print(f"\nScores saved to {scores_file}")
    return scores_file
