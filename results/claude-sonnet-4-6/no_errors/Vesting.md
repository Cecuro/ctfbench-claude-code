## Security Audit Report — `Vesting.sol`

---

### Contract Overview

A straightforward token vesting contract with a cliff and linear vesting schedule. It holds ERC-20 tokens on behalf of a single beneficiary and releases them linearly after the cliff period.

---

### Findings

---

#### [Low] Anyone Can Call `release()` — No Access Control

**Location:** `release()`, line 25

**Description:**
`release()` is `public` with no restriction on the caller. Any address can trigger a token release on behalf of the beneficiary. While funds always go to `beneficiary`, this means third parties can force a release at any time after the cliff, which may have unintended tax or accounting consequences for the beneficiary.

**Attack Scenario:**
An adversary (or bot) calls `release()` immediately after the cliff, forcing a token release the beneficiary did not intend to trigger yet.

**Recommended Fix:**
Restrict the caller to the beneficiary or an authorized address:
```solidity
require(msg.sender == beneficiary, "Not beneficiary");
```

---

#### [Low] Constructor Allows `_start` in the Past

**Location:** `constructor`, line 16

**Description:**
There is no validation that `_start` is in the future (i.e., `>= block.timestamp`). A deployer could accidentally or intentionally set a start time in the past, meaning the vesting schedule is partially (or fully) elapsed at deployment. This may cause unexpected immediate releasability.

**Recommended Fix:**
```solidity
require(_start >= block.timestamp, "Start must be in the future");
```
Or at minimum document that past `_start` values are intentional (e.g., for retroactive vesting).

---

#### [Low] No Validation of `_duration > 0`

**Location:** `constructor`, line 16

**Description:**
If `_duration` is zero, `vestedAmount()` at line 40 divides by `duration`, causing a division-by-zero revert. The `else if` branch at line 37 (`block.timestamp >= start + duration`) would always be true when `duration == 0`, so the revert would not be reached in that path — but the linear branch could still be reached in edge cases, and the intent of the contract is broken.

More precisely: if `duration == 0`, then `start + duration == start`, so the condition at line 37 is `block.timestamp >= start`, which is likely always true after deployment. The vesting immediately becomes 100%, which is benign but likely unintended. The division-by-zero path at line 40 is only reachable if `block.timestamp < start + duration`, so the real risk is behavioral surprise rather than a hard revert — but it still represents missing input validation.

**Recommended Fix:**
```solidity
require(_duration > 0, "Duration must be non-zero");
```

---

#### [Informational] Cliff Overflow Possibility (Theoretical)

**Location:** `constructor`, line 21

**Description:**
`cliff = _start + _cliff`. If both values are close to `type(uint256).max`, this would overflow. In Solidity `^0.8.0` this is automatically caught by the built-in overflow protection and will revert, so there is **no exploitable vulnerability** — but the revert message is unhelpful. Consider a named `require` to give a clear error.

---

#### [Informational] No Emergency Recovery / Token Rescue

**Location:** Contract-wide

**Description:**
If the `token` address is set incorrectly, or tokens are accidentally sent to the contract, there is no way to recover them. The `beneficiary` or deployer cannot retrieve misrouted funds. This is a design limitation rather than a vulnerability, but worth noting for operational risk.

---

#### [Informational] No Event Emissions

**Location:** `release()`, line 25

**Description:**
`release()` emits no event when tokens are transferred. Off-chain monitoring and indexers cannot observe vesting releases without scanning raw token transfer logs. Consider emitting a `TokensReleased(address beneficiary, uint256 amount)` event.

---

### Summary Table

| # | Severity | Title |
|---|----------|-------|
| 1 | Low | `release()` callable by anyone |
| 2 | Low | No validation that `_start` is in the future |
| 3 | Low | No validation that `_duration > 0` |
| 4 | Informational | Cliff parameter addition (safe in 0.8, but no named error) |
| 5 | Informational | No emergency token recovery |
| 6 | Informational | No events emitted on release |

---

### Overall Assessment

The contract is **generally well-structured** and free of critical vulnerabilities. It correctly uses `SafeERC20`, has no reentrancy risk (transfers happen after state update on line 29), uses Solidity 0.8.x overflow protection, and properly tracks released amounts. The issues found are low-severity or informational, centering on missing input validation in the constructor and the permissionless `release()` function.