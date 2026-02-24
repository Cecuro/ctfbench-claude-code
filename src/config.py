"""Constants, contract mappings, and leaderboard data for CTFBench."""

from pathlib import Path

# --- Paths ---
ROOT_DIR = Path(__file__).resolve().parent.parent
BENCHMARK_DIR = ROOT_DIR / "benchmark_data"
CONTRACTS_DIR = BENCHMARK_DIR / "contracts"
SYNOPSIS_DIR = BENCHMARK_DIR / "synopsis"
RESULTS_DIR = ROOT_DIR / "results"

# --- Benchmark parameters ---
# Number of judge runs per item (matches CTFBench default)
N_JUDGE_RUNS = 3

# Total lines of code across 4 clean contracts (used as OI denominator)
CLEAN_LOC = 282

# --- 7 vulnerable contracts: category -> (subdirectory, contract filename) ---
VULN_CONTRACTS: dict[str, tuple[str, str]] = {
    "access_control": ("access_control", "Voting.sol"),
    "arithmetic_security": ("arithmetic_security", "Lending.sol"),
    "boundary_condition": ("boundary_condition", "SuperToken.sol"),
    "cryptoeconomic_security": ("cryptoeconomic_security", "OracleFlashLoan.sol"),
    "data_structure_security": ("data_structure_security", "Vesting.sol"),
    "gas_security": ("gas_security", "Airdrop.sol"),
    "privacy_crypto_security": ("privacy_crypto_security", "MerkleDrop.sol"),
}

# --- 4 clean contracts (no vulnerabilities) ---
CLEAN_CONTRACTS: list[str] = [
    "Lending.sol",
    "MerkleDrop.sol",
    "Vesting.sol",
    "Voting.sol",
]

# --- Judge model (Azure GPT-5.1) ---
JUDGE_MODEL = "gpt-5.1"

# --- Leaderboard data (from ctfbench.com, February 2026) ---
# Each entry: (name, VDR, OI)
LEADERBOARD: list[tuple[str, float, float]] = [
    ("savant.chat v0.2", 0.952, 0.027),
    ("savant.chat v0.1", 0.857, 0.033),
    ("grok 3 thinking", 0.524, 0.037),
    ("ARMUR", 0.524, 0.090),
    ("o3-mini-high", 0.429, 0.056),
    ("o3-mini", 0.429, 0.064),
    ("deepseek r1", 0.429, 0.070),
    ("Code Genie AI", 0.333, 0.023),
    ("slither", 0.238, 0.130),
    ("QuillShield", 0.143, 0.009),
    ("Aegis", 0.143, 0.118),
    ("AuditOne", 0.095, 0.028),
    ("SCAU", 0.000, 0.051),
]
