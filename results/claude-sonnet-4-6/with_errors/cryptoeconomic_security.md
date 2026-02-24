## Security Audit Report — `OracleFlashLoan.sol`

---

### Contract Summary

`OracleFlashToken` is an ERC-20 token (extending OpenZeppelin's `ERC20Burnable`) with two key mechanisms:
1. **`mint()`** — users send ETH, and tokens are minted according to a Uniswap V1 spot-price oracle.
2. **`flashLoan()`** — uncollateralized flash loans that temporarily mint tokens to a target and require repayment by end of the call.

---

## Findings

---

### [CRITICAL-1] Flash Loan Enables Oracle Manipulation in `mint()`

**Location:** `mint()` (lines 17–22), `flashLoan()` (lines 25–33)

**Description:**
`mint()` uses `uniswapOracle.getEthToTokenInputPrice()` — a Uniswap V1 **spot price** — to determine how many tokens to mint per ETH. This is the canonical flash-loan oracle manipulation target. The contract's own `flashLoan()` function supplies the capital needed to manipulate that pool within a single transaction.

**Attack Scenario:**
1. Attacker calls `flashLoan(largeAmount, attackerContract, calldata)`.
2. `largeAmount` OFT tokens are minted to `attackerContract`.
3. Inside the callback, attacker dumps those tokens into the OFT/ETH Uniswap pool, crashing the OFT price (i.e., the oracle now reports vastly more OFT per ETH).
4. Attacker calls `mint()` with a small ETH value and receives a massively inflated token amount at the manipulated price.
5. Attacker buys back OFT on Uniswap to restore the pool (or simply repays via the inflated minted tokens).
6. Attacker repays the flash loan by sending `largeAmount` tokens to the contract.
7. Net result: attacker keeps the excess minted tokens at near-zero cost.

**Recommended Fix:**
- Replace the spot-price oracle with a **time-weighted average price (TWAP)** from Uniswap V2/V3, which cannot be manipulated within a single block.
- Use a dedicated price feed (e.g., Chainlink) instead of an on-chain DEX oracle.
- At minimum, add a `maxSlippage` / `minTokensOut` sanity check so implausibly high quotes are rejected.

---

### [CRITICAL-2] ETH Permanently Locked — No Withdrawal Mechanism

**Location:** `mint()` (lines 17–22)

**Description:**
`mint()` is `payable` and accumulates ETH in the contract, but there is no `withdraw()` function, no `receive` / `fallback`, and no other mechanism to retrieve that ETH. Every wei sent by every user is irretrievably locked in the contract.

**Proof of Concept:**
```solidity
token.mint{value: 1 ether}(); // 1 ETH is now forever trapped
```

**Recommended Fix:**
Add an owner-controlled or proportional ETH withdrawal function, or re-architect so ETH is immediately forwarded to a treasury:
```solidity
function withdraw(address payable to) external onlyOwner {
    to.transfer(address(this).balance);
}
```

---

### [HIGH-1] Spot-Price Oracle Manipulable Without Flash Loans

**Location:** `mint()` (line 19)

**Description:**
Even ignoring the flash loan, `getEthToTokenInputPrice` returns the **current marginal price** of the Uniswap V1 pool. Any sufficiently capitalised attacker can manipulate this with a normal swap in the same block (sandwich attack). A single large trade before calling `mint()` inflates the reported token amount.

**Recommended Fix:**
Use a TWAP oracle (Uniswap V2 `consult()` with a meaningful window, e.g., 30 minutes) or an off-chain price feed with on-chain staleness checks.

---

### [HIGH-2] Flash Loan Has No Reentrancy Guard

**Location:** `flashLoan()` (lines 25–33)

**Description:**
The function mints tokens to an arbitrary `target`, then performs an unconstrained external call (`target.call(data)`) before burning repaid tokens. There is no reentrancy guard. A malicious target can reenter `flashLoan()` recursively, creating nested layers of outstanding minted supply before any repayment check executes. While each layer must satisfy its own `balanceAfter >= balanceBefore + amount` check, the interaction with other state (oracle manipulation, minting) inside nested calls is unpredictable and opens complex attack surfaces.

**Recommended Fix:**
Add OpenZeppelin's `ReentrancyGuard` and annotate `flashLoan()` with `nonReentrant`:
```solidity
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
// ...
function flashLoan(...) external nonReentrant { ... }
```

---

### [HIGH-3] Uncapped Flash Loan Amount — Unbounded Token Inflation

**Location:** `flashLoan()` (line 27)

**Description:**
`_mint(target, amount)` is called with a caller-supplied `amount` that has no upper bound. An attacker can flash-loan `type(uint256).max` tokens, temporarily inflating the total supply to its theoretical maximum. While repayment burns the tokens, the inflated supply is real during the callback window and can be used to manipulate AMMs, pricing systems, or governance mechanisms that snapshot balances.

**Recommended Fix:**
Enforce a maximum flash loan size:
```solidity
uint256 public constant MAX_FLASH_LOAN = 1_000_000 * 1e18;
require(amount <= MAX_FLASH_LOAN, "Exceeds flash loan limit");
```

---

### [MEDIUM-1] Flash Loan Charges No Fee

**Location:** `flashLoan()` (lines 25–33)

**Description:**
There is no fee mechanism. Flash loans are entirely free, which (a) provides no revenue to the protocol and (b) makes oracle manipulation attacks strictly cheaper — the attacker bears zero loan cost and only needs to cover gas and AMM swap fees.

**Recommended Fix:**
Charge a fee (e.g., 0.09%) and require the repayment to cover principal + fee:
```solidity
uint256 fee = (amount * 9) / 10000;
require(balanceAfter >= balanceBefore + amount + fee, "Flashloan not repaid");
```

---

### [MEDIUM-2] Arbitrary External Call in `flashLoan()` — Potential for Target Contract Abuse

**Location:** `flashLoan()` (line 28)

**Description:**
`target.call(data)` executes arbitrary calldata against an arbitrary address with no access controls. If `target` is set to another token, protocol contract, or governance contract, the flash-loaned OFT tokens can be used within that call for voting, collateral, or other balance-sensitive operations. There is no whitelist or callback interface enforcement (e.g., ERC-3156).

**Recommended Fix:**
Adopt a standard callback interface (ERC-3156 `IFlashBorrower`) and validate the return value:
```solidity
bytes32 public constant CALLBACK_SUCCESS = keccak256("ERC3156FlashBorrower.onFlashLoan");
require(IFlashBorrower(target).onFlashLoan(...) == CALLBACK_SUCCESS, "Invalid callback");
```

---

### [LOW-1] Oracle Address Set Only at Construction — No Update Mechanism

**Location:** Constructor (lines 13–15)

**Description:**
`uniswapOracle` is set once in the constructor and cannot be changed. If the oracle contract is deprecated, exploited, or returns incorrect data, the protocol has no recourse.

**Recommended Fix:**
Add an `onlyOwner` function to update the oracle address, with appropriate timelock and event emission.

---

### [INFORMATIONAL-1] Use of Uniswap V1-style Interface

**Location:** Interface declaration (lines 6–8)

**Description:**
`getEthToTokenInputPrice` is a Uniswap **V1** function signature. Uniswap V1 is deprecated and offers weaker liquidity and security guarantees than V2/V3. Any deployment would inherit these limitations.

---

## Summary Table

| ID | Severity | Title |
|---|---|---|
| CRITICAL-1 | Critical | Flash loan enables oracle manipulation in `mint()` |
| CRITICAL-2 | Critical | ETH permanently locked — no withdrawal mechanism |
| HIGH-1 | High | Spot-price oracle manipulable without flash loans |
| HIGH-2 | High | No reentrancy guard on `flashLoan()` |
| HIGH-3 | High | Uncapped flash loan allows unbounded token inflation |
| MEDIUM-1 | Medium | Flash loan charges no fee |
| MEDIUM-2 | Medium | Arbitrary external call with no interface enforcement |
| LOW-1 | Low | Oracle address immutable after deployment |
| INFO-1 | Informational | Uniswap V1 interface is deprecated |

---

## Overall Assessment

This contract has **two critical and three high-severity vulnerabilities**. The most dangerous is the self-referential attack: the contract's own flash loan mechanism directly supplies the capital needed to exploit its own oracle, making profitable attacks trivially accessible with zero upfront capital. The ETH lock bug means every user loses funds immediately upon minting. The contract should not be deployed in its current form.