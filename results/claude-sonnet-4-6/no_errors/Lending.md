## Security Audit Report: `MinimalLending.sol`

---

### Finding 1 — Critical: Contract Compilation Error (Premature Closing Brace)

**Location:** Line 89  
**Severity:** Critical

**Description:**  
An extra `}` at line 89 closes the `MinimalLending` contract immediately after `repayLoan`. As a result, `isLiquidatable` (line 91) and `liquidate` (line 100) are emitted as file-level free functions outside the contract scope. Free functions cannot access contract state variables (`loans`, `oracle`, `token`), so the compiler will reject them. The orphaned `}` at line 111 then adds a second syntax error.

**Proof of Concept:**
```
contract MinimalLending {       // opens line 11
    ...
    function repayLoan() { ... }  // closes line 88
}                               // closes CONTRACT at line 89  ← EXTRA brace
                                // everything below is outside the contract
function isLiquidatable(...) { // references `loans`, `oracle` — compile error
function liquidate(...) { ...  // same
}                              // orphaned brace at line 111
```

**Fix:**  
Remove the extra `}` at line 89 so that all five functions belong to `MinimalLending`, and ensure a single `}` closes the contract at the end of the file.

---

### Finding 2 — High: Unvalidated / Manipulable Price Oracle

**Location:** `borrow()` line 48, `isLiquidatable()` line 95, `liquidate()` line 103  
**Severity:** High

**Description:**  
The contract unconditionally calls `oracle.getPrice()` with no staleness check, no circuit breaker, and no TWAP. If the oracle is a DEX spot price (or any other manipulable feed), an attacker can exploit it in two ways:

1. **Under-collateralised borrowing** – Inflate the ETH price via a flash loan, borrow far more tokens than the real collateral value supports, let the price recover, leaving the protocol with a bad loan.
2. **Forced liquidation** – Deflate the ETH price to push a healthy loan below the liquidation threshold, liquidate it, and profit from the seized collateral.

**Attack Scenario (under-collateralisation):**
1. Flash-loan a large amount of the asset used by the oracle's pricing pool.
2. Move the spot price so `oracle.getPrice()` returns an inflated ETH value.
3. Call `borrow()` with a small `msg.value`; `collateralValue * 100 >= borrowAmount * 150` passes.
4. Repay flash loan. The protocol now holds an under-collateralised position.

**Fix:**  
- Use a manipulation-resistant oracle (e.g., Chainlink with a freshness / sanity check, or a Uniswap V3 TWAP over ≥30 min).  
- Add a maximum acceptable price deviation check and a price-feed staleness guard (`require(updatedAt >= block.timestamp - MAX_STALENESS, ...)`).

---

### Finding 3 — High: No Liquidity Withdrawal Function for Owner

**Location:** `depositLiquidity()` line 40  
**Severity:** High

**Description:**  
`depositLiquidity` lets the owner deposit ERC-20 tokens, but there is no corresponding `withdrawLiquidity` function. Once deposited, tokens can only leave the contract through borrower repayments or liquidations. If an emergency arises (oracle compromise, discovered bug, market closure), the owner cannot recover protocol funds.

**Fix:**  
Add an owner-only withdrawal function:
```solidity
function withdrawLiquidity(uint256 amount) external onlyOwner {
    require(token.transfer(owner, amount), "Transfer failed");
}
```

---

### Finding 4 — Medium: Taylor Series Interest Approximation Loses Accuracy for Long-Duration Loans

**Location:** `getCurrentDebt()` lines 67–74  
**Severity:** Medium

**Description:**  
The contract approximates `e^x` using only three terms: `1 + x + x²/2 + x³/6`. At `INTEREST_RATE_PER_SECOND = 3170979198` (≈10 % APY), `x ≈ 0.1` for one year—accurate to < 0.01 %. However, for loans lasting several years `x` grows and the truncation error compounds, causing the debt to be *underestimated*, which favours borrowers and harms the protocol.

| Duration | True e^x | Approx | Error |
|----------|----------|--------|-------|
| 1 year   | 1.10517  | 1.10517| ~0%   |
| 5 years  | 1.6487   | 1.6042 | ~2.7% |
| 10 years | 2.7183   | 2.2667 | ~17%  |

**Fix:**  
Use a higher-order approximation, a stored per-checkpoint compounding model, or an on-chain fixed-point exponentiation library (e.g., PRBMath `exp`).

---

### Finding 5 — Low: No Ownership Transfer Mechanism

**Location:** `constructor` line 34, `onlyOwner` modifier line 29  
**Severity:** Low

**Description:**  
`owner` is set once in the constructor and can never be changed. If the owner's private key is lost or compromised, administrative functions (`depositLiquidity`) are permanently blocked or permanently accessible to an attacker.

**Fix:**  
Implement a two-step ownership transfer (à la OpenZeppelin `Ownable2Step`):
```solidity
function transferOwnership(address newOwner) external onlyOwner { ... }
function acceptOwnership() external { ... }
```

---

### Finding 6 — Informational: `getCurrentDebt` Called Twice in `liquidate`

**Location:** `isLiquidatable()` line 94, `liquidate()` line 103  
**Severity:** Informational

**Description:**  
`liquidate` first calls `isLiquidatable`, which internally calls `getCurrentDebt`, and then calls `getCurrentDebt` a second time. Within the same block the values are identical, so this wastes gas without benefit.

**Fix:**  
Inline the liquidation check inside `liquidate` using a single `getCurrentDebt` call and reuse the result.

---

### Summary Table

| # | Severity | Title |
|---|----------|-------|
| 1 | **Critical** | Extra `}` at line 89 — contract does not compile |
| 2 | **High** | Unvalidated price oracle enables flash-loan manipulation |
| 3 | **High** | No owner liquidity withdrawal — funds locked permanently |
| 4 | **Medium** | 3rd-order Taylor approximation undercharges interest on long loans |
| 5 | **Low** | No ownership transfer mechanism |
| 6 | **Informational** | Redundant `getCurrentDebt` call in `liquidate` |

The most urgent issue is **Finding 1**: the contract cannot be deployed as written. After fixing the brace error, **Finding 2** (oracle manipulation) and **Finding 3** (locked liquidity) should be addressed before any mainnet deployment.