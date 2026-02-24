# Security Audit Report: `SuperToken.sol`

---

## Summary

The contract implements a basic ERC20-like token. One **critical** vulnerability exists due to a boundary condition bug in the internal transfer logic, plus a medium-severity known ERC20 design flaw.

---

## Findings

---

### [CRITICAL] Self-Transfer Balance Inflation (Token Minting Bug)

**Location:** `_transfer()`, lines 43–46

**Description:**

The `_transfer` function caches the sender and receiver balances into local variables *before* modifying storage:

```solidity
uint256 balance_from = balanceOf[_from];   // line 43
uint256 balance_to   = balanceOf[_to];     // line 44
balanceOf[_from] = balance_from - _value;  // line 45
balanceOf[_to]   = balance_to   + _value;  // line 46
```

When `_from == _to` (a self-transfer), both `balance_from` and `balance_to` are read from the **same storage slot** before any write. The subtraction at line 45 reduces the balance, but line 46 immediately overwrites it with the **original pre-subtraction value plus `_value`**, effectively inflating the sender's balance by `_value`.

**Proof of Concept:**

```
Alice has balanceOf[Alice] = 100 tokens.

Alice calls transfer(Alice, 100):
  1. require(100 >= 100) → passes
  2. balance_from = 100, balance_to = 100  (same slot, same value)
  3. balanceOf[Alice] = 100 - 100 = 0
  4. balanceOf[Alice] = 100 + 100 = 200    ← overwrites the 0!

Result: Alice now holds 200 tokens, minted from thin air.
```

An attacker can repeat this to double their balance each iteration, reaching an arbitrary balance in O(log N) calls where N is the desired amount. `totalSupply` is never updated, so the sum of all balances will exceed it, breaking the invariant.

**Recommended Fix:**

Add a guard against self-transfers, OR avoid caching and apply writes directly (which makes the bug self-correcting):

```solidity
// Option A – guard
require(_from != _to, "ERC20: self-transfer not allowed");

// Option B – avoid stale cache (safe even with same address)
balanceOf[_from] -= _value;
balanceOf[_to]   += _value;
```

Option B is idiomatic for Solidity 0.8.x where under/overflow reverts automatically.

---

### [MEDIUM] ERC20 Approval Race Condition (Front-Running)

**Location:** `approve()`, lines 57–61

**Description:**

The `approve` function sets the allowance to an absolute value. If an owner calls `approve(spender, newValue)` to *change* an existing non-zero allowance, the spender can front-run the transaction: first spending the old allowance, then spending the new allowance, consuming both in a single block.

**Attack Scenario:**

```
1. Owner sets approve(spender, 100). Spender has allowance = 100.
2. Owner submits approve(spender, 50) to reduce the allowance.
3. Spender sees the pending tx, front-runs with transferFrom(..., 100).
4. Owner's approve(spender, 50) executes.
5. Spender now calls transferFrom(..., 50) again.
Total drained: 150 tokens instead of 50.
```

**Recommended Fix:**

Follow the OpenZeppelin pattern: require that the current allowance be zero before setting a new non-zero value, or use `increaseAllowance` / `decreaseAllowance` helpers:

```solidity
function approve(address _spender, uint256 _value) public returns (bool) {
    require(_value == 0 || allowance[msg.sender][_spender] == 0,
            "ERC20: reset allowance to 0 first");
    allowance[msg.sender][_spender] = _value;
    emit Approval(msg.sender, _spender, _value);
    return true;
}
```

---

### [LOW] `totalSupply` Invariant Not Enforced

**Location:** `_transfer()` / global state

**Description:**

`totalSupply` is set once in the constructor and never updated. While this is expected in a fixed-supply token, it means any bug that inflates individual balances (such as the critical self-transfer bug above) will silently break the fundamental ERC20 invariant `sum(balances) == totalSupply` without any on-chain detection or revert. There is no supply-integrity check anywhere.

**Recommended Fix:**

In combination with fixing the critical bug, consider adding an assertion in tests or a view function that validates the invariant, and document clearly that the supply is fixed and immutable.

---

### [INFORMATIONAL] Zero-Value Transfers Emit Events

**Location:** `transfer()`, `transferFrom()`, `_transfer()`

**Description:**

Zero-value transfers are permitted and emit `Transfer` events. Some integrations and indexers treat any `Transfer(from, to, 0)` as meaningful (e.g., ownership probes). This is a minor compliance/spam concern, not a security risk.

**Recommended Fix:**

```solidity
require(_value > 0, "ERC20: zero-value transfer");
```

---

## Severity Summary

| # | Severity | Title |
|---|----------|-------|
| 1 | **Critical** | Self-transfer inflates balance (token minting) |
| 2 | **Medium** | ERC20 approval race condition (front-running) |
| 3 | **Low** | `totalSupply` invariant not enforced |
| 4 | Informational | Zero-value transfers allowed |

---

## Key Takeaway

The dominant issue is the **cached-variable self-transfer bug** in `_transfer`. Because both `balance_from` and `balance_to` are read from storage before any write, a self-transfer skips the net-zero effect and acts as unlimited token minting. This must be fixed before deployment.