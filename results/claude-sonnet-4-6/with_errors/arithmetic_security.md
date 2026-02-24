# Security Audit Report — `MinimalLending.sol`

---

## Finding 1 — [Critical] Misplaced Closing Brace Leaves `isLiquidatable` and `liquidate` Outside the Contract

**Location:** Line 89 (extra `}`) / Lines 91–111

**Description:**  
Line 88 closes `repayLoan()`, and line 89 closes the `MinimalLending` contract itself. The functions `isLiquidatable()` and `liquidate()` are therefore defined **outside** the contract scope as free functions. In Solidity 0.8.x, free functions:
- Cannot be `public` or `external` (only `internal`)
- Cannot access state variables (`loans`, `oracle`, `token`)

This causes a **compilation failure** — the contract cannot be deployed at all.

**Proof of concept:**
```
Compiled with solc:
> Error: Free functions cannot have visibility.   (line 91)
> Error: Identifier not found or not unique.      (oracle, loans, token references)
```

**Recommended fix:**  
Remove the extra `}` at line 89 so that `isLiquidatable` and `liquidate` are enclosed within the `MinimalLending` contract.

```solidity
    // line 88: close repayLoan
    }
    // DO NOT add a second } here — the contract closes at the very end
    
    function isLiquidatable(...) public view returns (bool) { ... }
    function liquidate(...) external { ... }
    
} // single contract-closing brace
```

---

## Finding 2 — [Critical] Integer Division Truncation Zeroes Out All Interest

**Location:** `getCurrentDebt()`, Line 67

**Description:**  
The interest rate per second is stored as `3170979198` (≈ 3.17 × 10⁹), which represents ~10% APR scaled by `1e18`. The calculation of `x` (the rate × time product) is:

```solidity
uint256 x = INTEREST_RATE_PER_SECOND * timeElapsed / scale;
//                    3.17e9          *    seconds    / 1e18
```

Because integer division truncates, `x` is **zero** for any loan shorter than ~10 years:

| Loan duration | Numerator | After `/1e18` |
|---|---|---|
| 1 day (86 400 s) | ≈ 2.74 × 10¹⁴ | **0** |
| 1 year (31 536 000 s) | ≈ 9.99 × 10¹⁶ | **0** |
| 10 years | ≈ 9.99 × 10¹⁷ | **0** |

When `x = 0`:
```solidity
uint256 expApprox = scale + 0 + 0 + 0;  // == 1e18
return (loan.principal * 1e18) / 1e18;  // == principal
```

Every borrower repays **exactly the principal, with zero interest**, regardless of how long the loan has been outstanding. The protocol accrues no interest revenue, and lenders earn nothing.

**Proof of concept:**  
```solidity
// Borrow 1000 tokens, wait 5 years, repay
uint256 debt = getCurrentDebt(borrower);
assert(debt == principal); // always true due to the bug
```

**Recommended fix:**  
Do **not** divide by `scale` when computing `x`. Keep the full precision through the Taylor series; divide only at the very end.

```solidity
// x represents rate * time, still scaled by 1e18
uint256 x = INTEREST_RATE_PER_SECOND * timeElapsed;
//  For 1 year: ~9.99e16  (non-zero, correct)

uint256 x2 = (x * x) / scale;
uint256 x3 = (x2 * x) / scale;

uint256 expApprox = scale + x + (x2 / 2) + (x3 / 6);
return (loan.principal * expApprox) / scale;
```

---

## Finding 3 — [Medium] Unprotected Single-Oracle Price Feed Enables Collateral Manipulation

**Location:** `borrow()` line 49, `isLiquidatable()` line 96, `liquidate()` line 103

**Description:**  
The contract uses a single `IPriceOracle.getPrice()` call with no TWAP, staleness check, or secondary source. An attacker who can influence the oracle (e.g., via a flash loan in a DEX-based oracle) can:
- Inflate the ETH price → borrow far more tokens than collateral warrants.
- Deflate the ETH price → force arbitrary liquidations of solvent borrowers.

**Recommended fix:**  
- Use a time-weighted average price (TWAP) oracle (e.g., Uniswap v3 TWAP, Chainlink with `updatedAt` staleness check).
- Add a circuit breaker that reverts if the price deviates more than X% from the last known price in a single block.

---

## Finding 4 — [Low] No Liquidation Bonus Stored in Contract; Full Collateral Sent to Liquidator

**Location:** `liquidate()`, Lines 100–109

**Description:**  
The liquidator pays `debt` tokens and receives the borrower's **full** ETH collateral. At the liquidation threshold (110%), this is a ~10% profit, which is acceptable. However, if the collateral ratio drops below 100% (e.g., due to rapid price movement) before anyone liquidates, the liquidator would pay more in tokens than the collateral is worth and suffer a loss, resulting in **no one willing to liquidate** — leaving bad debt in the protocol.

**Recommended fix:**  
Implement a tiered liquidation bonus (e.g., liquidator covers 50% of debt and receives 55% of collateral), and add a bad-debt socialization mechanism for deeply undercollateralized positions.

---

## Finding 5 — [Informational] No Events Emitted

**Location:** `borrow()`, `repayLoan()`, `liquidate()`

**Description:**  
None of the state-changing functions emit events, making it impossible to track protocol activity off-chain or detect anomalies via monitoring tools.

**Recommended fix:**  
Emit events such as `Borrowed`, `Repaid`, and `Liquidated` with relevant parameters (borrower, amount, collateral).

---

## Summary Table

| # | Severity | Title | Location |
|---|---|---|---|
| 1 | **Critical** | Extra `}` closes contract early; liquidation functions unreachable | Line 89 |
| 2 | **Critical** | Integer division zeros all interest; borrowers never pay interest | `getCurrentDebt`, L67 |
| 3 | Medium | Single unprotected oracle enables price manipulation | L49, L96, L103 |
| 4 | Low | No liquidation when position goes underwater (no bad-debt handling) | `liquidate`, L100 |
| 5 | Informational | No events emitted on state changes | L44, L78, L100 |

The two critical issues together mean **the contract cannot be deployed** (Finding 1) and, if the brace were fixed, **interest revenue would always be zero** (Finding 2). Both must be resolved before this contract is usable.