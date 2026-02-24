---

# Security Audit Report — `Airdrop.sol`

**Contract:** `Airdrop`
**Compiler:** `^0.8.0`
**Audited:** 2026-02-24

---

## Summary

The contract implements a two-phase airdrop: a registration window, then a single distribution of the contract's token balance split equally among participants. Three vulnerabilities were identified, two of which are critical/high severity.

---

## Vulnerability 1 — Gas Limit DoS via Unbounded Loop

**Severity:** Critical
**Location:** `distribute()`, lines 47–49

### Description

`distribute()` iterates over the entire `participants` array and performs an ERC-20 `transfer` call per participant in a single transaction. There is no upper bound on `participants.length`. If enough addresses register, the gas required to execute this loop will exceed the block gas limit, permanently bricking the distribution. The funds become irretrievable.

### Attack Scenario

1. Attacker deploys a malicious `IEligible` contract that returns `true` for any caller, or simply waits — the eligibility check is per-user, so any number of legitimate users can register.
2. With a sufficiently large participant list (e.g., 1,000+ addresses at ~25,000 gas per ERC-20 transfer ≈ 25M gas, approaching Ethereum's ~30M block gas limit), `distribute()` always reverts out-of-gas.
3. All tokens are permanently locked in the contract.

### Recommended Fix

Replace the push-payment loop with a **pull-payment** pattern:

```solidity
mapping(address => bool) public hasClaimed;

function claim() external {
    require(block.timestamp > registrationDeadline, "Distribution not started");
    require(registered[msg.sender], "Not registered");
    require(!hasClaimed[msg.sender], "Already claimed");
    hasClaimed[msg.sender] = true;

    uint256 amount = token.balanceOf(address(this)) / participants.length;
    require(token.transfer(msg.sender, amount), "Transfer failed");
}
```

Alternatively, add a batched distribution with a `startIndex`/`endIndex` parameter.

---

## Vulnerability 2 — Constructor Calls `register()` with `address(0)` / Deployer Auto-Registration

**Severity:** High
**Location:** `constructor()`, line 24; `register()`, lines 27–33

### Description

The constructor calls `register()` as its last statement. At this point `msg.sender` is the **deployer's address**. This silently adds the deployer to the `participants` array without any explicit intent or documentation. More importantly, `register()` checks `eligible.isEligible(msg.sender)` — but if the `IEligible` contract is not yet fully initialized or if the deployer is intentionally ineligible, the constructor will revert and the contract can never be deployed. This is an unintentional coupling of deployment and registration logic.

There is also a subtle ordering issue: `registrationDeadline` is set before `register()` is called, but if `_registrationDeadline` is already in the past at deploy time, the constructor reverts. This is a usability footgun, not a security issue in isolation, but it compounds the forced-registration problem.

### Attack Scenario

- If the deployer is not returned as eligible by `_eligible`, the contract **cannot be deployed at all**, making the system unusable.
- If the deployer is eligible, they silently receive a share of the airdrop, which may violate intended fairness rules and is non-obvious to external observers.

### Recommended Fix

Remove `register()` from the constructor entirely. If the deployer should be registered, do it explicitly with clear intent, or simply let them call `register()` themselves.

```solidity
constructor(address _token, uint256 _registrationDeadline, address _eligible) {
    token = IERC20(_token);
    registrationDeadline = _registrationDeadline;
    eligible = IEligible(_eligible);
    // Do NOT auto-register the deployer
}
```

---

## Vulnerability 3 — Unchecked Dust / Rounding Loss

**Severity:** Low
**Location:** `distribute()`, line 43

### Description

Integer division truncates: `balance / totalParticipants` rounds down. The remainder (`balance % totalParticipants`) is never distributed and stays permanently locked in the contract since `distributed = true` is set unconditionally and there is no withdrawal function.

For example, with 1,001 participants and a balance of 1,000 tokens (18 decimals), 1,000 wei equivalent in remainder is locked forever.

### Recommended Fix

After the loop, transfer the remainder to a designated recipient (e.g., a treasury or the last participant):

```solidity
uint256 remainder = balance - (amountPerParticipant * totalParticipants);
if (remainder > 0) {
    token.transfer(treasury, remainder);
}
```

---

## Vulnerability 4 — Untrusted External Call in `register()` (Reentrancy / Malicious Eligibility Oracle)

**Severity:** Medium
**Location:** `register()`, line 29

### Description

`eligible.isEligible(msg.sender)` is a call to an **externally supplied, immutable contract address**. If the `IEligible` implementation is malicious or compromised, it can:
- Re-enter `register()` (though `registered[msg.sender]` protects against double-registration for a single address, it does not prevent registering many addresses in one call via a malicious contract).
- Return `true` for any address, enabling Sybil attack spam registrations (which directly worsens Vulnerability 1).
- Revert selectively to deny legitimate users.

The reentrancy guard is partial: it only sets `registered[msg.sender] = true` **after** calling the external contract, meaning the external call at line 29 happens before the state update at line 31. A reentrant call for the **same** `msg.sender` would see `registered[msg.sender] == false` and could register twice if the `registered` check weren't present. The check-effect-interaction pattern is violated.

### Recommended Fix

Move the state update before the external call (checks-effects-interactions pattern):

```solidity
function register() public {
    require(block.timestamp <= registrationDeadline, "Registration closed");
    require(!registered[msg.sender], "Already registered");
    registered[msg.sender] = true;      // effect before external call
    participants.push(msg.sender);
    require(eligible.isEligible(msg.sender), "Not eligible");
}
```

---

## Summary Table

| # | Severity | Title | Lines |
|---|----------|-------|-------|
| 1 | **Critical** | Unbounded loop in `distribute()` — DoS / funds locked | 47–49 |
| 2 | **High** | Constructor auto-registers deployer via `register()` | 24, 27–33 |
| 3 | **Medium** | Checks-effects-interactions violated; untrusted eligibility oracle | 29–31 |
| 4 | **Low** | Remainder dust permanently locked after distribution | 43 |