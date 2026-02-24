"""Claude Agent SDK runner — one agent per contract."""

import asyncio
import os
from pathlib import Path

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    TextBlock,
    query,
)

from src.config import (
    CLEAN_CONTRACTS,
    CONTRACTS_DIR,
    RESULTS_DIR,
    VULN_CONTRACTS,
)

SYSTEM_PROMPT_APPEND = """\
You are an expert smart contract security auditor. You will be given a single \
Solidity file to audit. Carefully analyze the code for vulnerabilities \
including but not limited to: reentrancy, access control issues, arithmetic \
errors, flash loan attacks, gas limit issues, data structure misuse, \
cryptographic weaknesses, and boundary condition bugs.

Produce a detailed security report. For each vulnerability found, include:
- Severity (Critical / High / Medium / Low / Informational)
- Title
- Location (function name and line numbers)
- Description of the vulnerability
- Proof of concept or attack scenario
- Recommended fix

If the contract is secure, state that no vulnerabilities were found and \
briefly explain why the key security properties hold."""


async def audit_contract(contract_path: Path, model: str) -> tuple[str, float | None]:
    """Run a single Claude agent on one contract file.

    Returns (report_text, cost_usd).
    """
    # Allow spawning sub-agents even when run from inside a Claude Code session
    os.environ.pop("CLAUDECODE", None)

    options = ClaudeAgentOptions(
        model=model,
        system_prompt={
            "type": "preset",
            "preset": "claude_code",
            "append": SYSTEM_PROMPT_APPEND,
        },
        allowed_tools=["Read", "Glob", "Grep"],
        permission_mode="bypassPermissions",
        cwd=str(contract_path.parent),
        max_turns=10,
    )

    prompt = (
        f"Audit the Solidity file `{contract_path.name}` in the current directory. "
        "Read the file first, then produce your security report."
    )

    report_parts: list[str] = []
    cost: float | None = None

    async for message in query(prompt=prompt, options=options):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    report_parts.append(block.text)
        elif isinstance(message, ResultMessage):
            cost = message.total_cost_usd

    return "\n".join(report_parts), cost


async def _audit_and_save(
    contract_path: Path, output_file: Path, label: str, model: str
) -> float:
    """Audit one contract and write the report. Returns cost."""
    print(f"[audit] {label}...")
    report, cost = await audit_contract(contract_path, model)
    output_file.write_text(report, encoding="utf-8")
    cost_str = f"${cost:.4f}" if cost else "unknown"
    print(f"  -> {output_file.name}  ({cost_str})")
    return cost or 0.0


async def run_all_audits(
    output_dir: Path | None = None, model: str = "claude-sonnet-4-6"
) -> Path:
    """Run audits on all 11 contracts in parallel and save reports.

    Returns the output directory containing the reports.
    """
    label = model.replace("/", "_")
    out = (output_dir or RESULTS_DIR) / label
    out_vuln = out / "with_errors"
    out_clean = out / "no_errors"
    out_vuln.mkdir(parents=True, exist_ok=True)
    out_clean.mkdir(parents=True, exist_ok=True)

    tasks: list[asyncio.Task[float]] = []

    # --- Vulnerable contracts ---
    for category, (subdir, filename) in VULN_CONTRACTS.items():
        contract_path = CONTRACTS_DIR / "with_errors" / subdir / filename
        report_file = out_vuln / f"{category}.md"
        tasks.append(
            asyncio.create_task(
                _audit_and_save(
                    contract_path, report_file, f"{category} ({filename})", model
                )
            )
        )

    # --- Clean contracts ---
    for filename in CLEAN_CONTRACTS:
        contract_path = CONTRACTS_DIR / "no_errors" / filename
        stem = Path(filename).stem
        report_file = out_clean / f"{stem}.md"
        tasks.append(
            asyncio.create_task(
                _audit_and_save(contract_path, report_file, f"clean/{filename}", model)
            )
        )

    costs = await asyncio.gather(*tasks)
    total_cost = sum(costs)

    print(f"\nAll 11 reports saved to {out}")
    print(f"Total cost: ${total_cost:.4f}")
    return out
