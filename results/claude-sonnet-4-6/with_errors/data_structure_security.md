## Security Audit Report — `Vesting.sol`

---

### Overview

The contract implements a basic ETH vesting mechanism: users deposit ETH, and after a 1-week lock period, they may release it to a recipient. The contract is small but contains a critical assembly bug that renders all deposited funds inaccessible through normal means.

---

## Vulnerability 1 — CRITICAL: Incorrect Calldata Decoding via `shr(96, ...)` for ABI-Encoded Address

**Location:** `processRelease`, lines 27–31

**Description:**

The function ignores Solidity's built-in ABI-decoded address parameter and instead manually extracts the recipient from raw calldata using inline assembly:

```solidity
function processRelease(uint256 _amount, address) public {
    address _recipient;
    assembly {
        _recipient := shr(96, calldataload(36))
    }
```

The ABI specification encodes `address` **right-aligned** in a 32-byte word — 12 zero-padding bytes in the high positions (bytes 0–11) followed by the 20-byte address in the low positions (bytes 12–31):

```
calldata[36..67] = 0x000000000000000000000000<ADDR_20_BYTES>
```

`calldataload(36)` returns this 32-byte word as a `uint256`. Numerically, this equals the `uint160` value of the address (padding is zero). Applying `shr(96, value)` performs integer division by `2^96`, keeping only the **top 64 bits** (8 bytes) of the 160-bit address and discarding the lower 96 bits (12 bytes):

```
shr(96, address_integer) = address_integer >> 96
                         = top-8-bytes of address only
```

**Proof of Concept:**

Calling `processRelease(1e18, 0xD8DA6BF26964AF9D7EED9E03E53415D37AA96045)` via standard ABI encoding:

- `calldataload(36)` = `0x000000000000000000000000D8DA6BF26964AF9D7EED9E03E53415D37AA96045`
- `shr(96, ...)` = `0xD8DA6BF26964AF9D` (only 8 bytes)
- `_recipient` = `address(0x000000000000D8DA6BF26964AF9D)` — **completely wrong**

The transaction will either send ETH to a garbage address or revert on the `_recipient != address(0)` check if the truncated value happens to be zero.

**Correct assembly should be:**
```solidity
assembly {
    _recipient := and(calldataload(36), 0xffffffffffffffffffffffffffffffffffffffff)
}
```
Or better yet, simply remove the assembly and use the named parameter directly.

---

## Vulnerability 2 — HIGH: `processReleaseForMyself` Always Reverts

**Location:** `processReleaseForMyself`, lines 23–25; `processRelease`, line 30

**Description:**

`processReleaseForMyself` is intended as a convenience wrapper that calls `processRelease(_amount, msg.sender)`:

```solidity
function processReleaseForMyself(uint256 _amount) public {
    processRelease(_amount, msg.sender);
}
```

This is an **internal JUMP**, not a new external call. The EVM's calldata register still contains the original transaction's calldata: exactly 36 bytes (`4 bytes selector + 32 bytes _amount`). Inside `processRelease`, `calldataload(36)` reads beyond the end of calldata and returns `0`. After `shr(96, 0) = 0`, the check on line 33 fires:

```solidity
require(_recipient != address(0), "Invalid recipient");  // always reverts
```

**Impact:** `processReleaseForMyself` is completely non-functional. A user who relies on this entry point can never release their funds.

---

## Vulnerability 3 — HIGH: All Deposited ETH is Permanently Locked

**Location:** Contract-wide; `deposit` lines 14–21, `processRelease` lines 27–41

**Description:**

As a direct consequence of Vulnerabilities 1 and 2:

- `processReleaseForMyself` always reverts (Vuln 2).
- `processRelease` called with standard ABI encoding sends ETH to a garbage address or reverts (Vuln 1).

The only way to interact correctly is by sending **hand-crafted, non-standard calldata** where the address is placed in the high 20 bytes of the 32-byte slot:

```
calldata[36..67] = <ADDR_20_BYTES>000000000000000000000000
```

This requires constructing raw transactions manually and bypasses Etherscan/dApp UI tooling entirely. Regular users have no way to recover their deposits.

---

## Vulnerability 4 — Medium: No Reentrancy Guard on External ETH Transfer

**Location:** `processRelease`, lines 37–38

**Description:**

The function correctly follows Checks-Effects-Interactions (balance decremented before the external call):

```solidity
balances[msg.sender] -= _amount;          // effect first
(bool success, ) = _recipient.call{value: _amount}("");  // then interaction
```

This prevents a classic same-sender reentrancy from draining funds. However, there is no `ReentrancyGuard` modifier and no locking mechanism. A malicious `_recipient` contract could re-enter `processRelease` as a different `msg.sender` if it holds a balance. While the impact is limited, the absence of a guard is a best-practice violation. A `nonReentrant` modifier should be added.

---

## Vulnerability 5 — Low: No Zero-Amount Validation

**Location:** `processRelease`, lines 34–39

**Description:**

There is no `require(_amount > 0)` check. A call with `_amount = 0` passes all checks, makes a zero-value external call, and emits a misleading `Released` event. This wastes gas and pollutes the event log.

**Fix:** Add `require(_amount > 0, "Zero amount");` at the top of `processRelease`.

---

## Vulnerability 6 — Informational: Redundant Balance Check

**Location:** `processRelease`, lines 35–36

**Description:**

Lines 35 and 36 are logically identical:

```solidity
require(balances[msg.sender] >= _amount, "Insufficient funds");   // line 35
require(_amount <= balances[msg.sender], "Amount exceeds balance"); // line 36
```

`a >= b` and `b <= a` are the same predicate. Remove one.

---

## Summary Table

| # | Severity | Title | Location |
|---|----------|-------|----------|
| 1 | **Critical** | `shr(96, calldataload(36))` incorrectly decodes ABI-encoded address | `processRelease` L27–31 |
| 2 | **High** | `processReleaseForMyself` always reverts due to calldata boundary | `processReleaseForMyself` L23–25 |
| 3 | **High** | All deposited ETH permanently locked | Contract-wide |
| 4 | **Medium** | No reentrancy guard on external ETH call | `processRelease` L37–38 |
| 5 | **Low** | Missing zero-amount check | `processRelease` L34 |
| 6 | **Informational** | Duplicate balance check | `processRelease` L35–36 |

---

## Root Cause Summary

The central flaw is the misuse of `shr(96, calldataload(36))` to decode a standard ABI-encoded `address`. This pattern is valid **only** for tightly-packed data where the address occupies the high 20 bytes of a 32-byte word — the exact opposite of how the Solidity ABI encodes it. The simplest fix is to remove the assembly entirely and use the named Solidity parameter, or replace the shift with a bitmask: `and(calldataload(36), 0xffffffffffffffffffffffffffffffffffffffff)`.