Here is the full security audit report for `MerkleDrop.sol`.

---

# Security Audit Report — `MerkleAirdrop.sol`

## Summary

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High | 1 |
| Medium | 1 |
| Low | 1 |
| Informational | 2 |

---

## [CRITICAL] Merkle Second-Preimage Attack via Leaf/Node Confusion

**Location:** `claim()` (line 37), `verifyProof()` (lines 56–65)

### Description

The leaf hash is computed using `abi.encodePacked(nonce, receiver, amount)`:

- `nonce` → `uint96` → **12 bytes**
- `receiver` → `address` → **20 bytes**
- `amount` → `uint256` → **32 bytes**
- **Total: 64 bytes**

Internal Merkle tree nodes are also computed as `keccak256(left_hash || right_hash)` — where each hash is 32 bytes — producing **exactly 64 bytes of input**.

Because `abi.encodePacked(nonce, receiver, amount)` and `abi.encodePacked(bytes32, bytes32)` produce the same 64-byte layout, an attacker can construct a `(nonce, receiver, amount)` triple that encodes to the concatenation of any two existing internal node hashes `(L, R)`:

```
nonce    = uint96(L[0:12])       ← first 12 bytes of L
receiver = address(L[12:32])     ← last 20 bytes of L
amount   = uint256(R)            ← entire R (≈ 2^255, an astronomically large number)
```

The leaf hash then computes to `keccak256(L || R)` — which **is** an actual internal node of the tree. The attacker then provides the (shorter) Merkle proof for that internal node rather than a leaf-level proof, and `verifyProof` accepts it.

The check on line 39:
```solidity
require(payouts[leaf] + payout <= amount, "Not enough eligible amount");
```
trivially passes because `amount = uint256(R)` is a pseudorandom 256-bit value close to `2^255`.

### Proof of Concept

1. Observe the publicly available Merkle tree structure (leaves and internal nodes).
2. For each internal node pair `(L, R)`, compute `receiver = address(uint160(uint256(L)))`.
3. Find any pair where `receiver` is an address the attacker controls (possible by brute-forcing tree construction or deploying a contract via `CREATE2` at the target address).
4. Call `claim(nonce, receiver, amount, payout, proof)` with the crafted values and the sibling-path proof for the internal node.
5. Drain up to the contract's full token balance.

### Recommended Fix

Double-hash the leaf to domain-separate it from internal nodes, exactly as OpenZeppelin's `MerkleProof` library does:

```solidity
// Before
bytes32 leaf = keccak256(abi.encodePacked(nonce, receiver, amount));

// After
bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encodePacked(nonce, receiver, amount))));
```

Alternatively, use `MerkleProof.verify` from OpenZeppelin directly and build the off-chain tree with double-hashed leaves.

---

## [HIGH] Mutable Merkle Root Enables Owner Rug-Pull

**Location:** `setMerkleRoot()` (lines 23–25)

### Description

The owner can replace the Merkle root at any time with no restrictions. This breaks the trust model of an airdrop contract in several ways:

- The owner can swap in a new root that includes only their own address for the entire token balance, then claim all tokens.
- The owner can swap in a root that excludes users who have not yet claimed, permanently locking them out.
- There is no timelock, no multi-sig, and no event emitted recording the previous root.

### Attack Scenario

1. Contract is deployed with legitimate `merkleRoot`.
2. Some users claim tokens; remaining tokens sit in the contract.
3. Owner calls `setMerkleRoot(maliciousRoot)` where `maliciousRoot` is a tree containing only a single leaf `(0, ownerAddress, totalRemainingBalance)`.
4. Owner drains all remaining tokens.

### Recommended Fix

- Make the merkle root **immutable** (set only in the constructor), or
- Add a timelock and event logging if updates are genuinely required, and clearly document the trust assumption for users.

---

## [MEDIUM] Misleading `Claimed` Event (emits `amount` instead of `payout`)

**Location:** `claim()` (line 48)

### Description

```solidity
emit Claimed(receiver, amount, leaf);
```

The event emits `amount` (the total eligible allocation) rather than `payout` (the actual number of tokens transferred in this call). Off-chain indexers, dashboards, and analytics tools that rely on this event to track token distribution will report wildly incorrect numbers.

### Recommended Fix

```solidity
emit Claimed(receiver, payout, leaf);
```

---

## [LOW] No Token Recovery or Expiry Mechanism

**Location:** Contract-level

### Description

There is no `withdraw` or `rescueTokens` function and no expiry timestamp. Tokens that are never claimed are locked in the contract forever with no way for the deployer to recover them after the airdrop window closes. While this may be intentional to prevent a rug-pull, the complete absence of any recovery path is generally considered bad practice.

### Recommended Fix

Add a time-bounded recovery function:

```solidity
uint256 public expiryTimestamp;

function recoverTokens(address to) external onlyOwner {
    require(block.timestamp > expiryTimestamp, "Airdrop still active");
    token.safeTransfer(to, token.balanceOf(address(this)));
}
```

---

## [INFORMATIONAL] OpenZeppelin v5 Incompatibility — Missing `Ownable` Constructor Argument

**Location:** `constructor` (lines 17–20)

### Description

```solidity
constructor(IERC20 _token, bytes32 _merkleRoot) {
```

No `Ownable(msg.sender)` call is made. OpenZeppelin v5 changed `Ownable`'s constructor to require an explicit `initialOwner` address parameter. With OZ v5+, this contract will **fail to compile**. With OZ v4.x it is fine.

### Recommended Fix

```solidity
constructor(IERC20 _token, bytes32 _merkleRoot) Ownable(msg.sender) {
```

---

## [INFORMATIONAL] No Zero-Address Check on `receiver`

**Location:** `claim()` (line 28)

### Description

`receiver` is an attacker-controlled parameter with no validation. Passing `address(0)` would burn tokens and consume quota from the leaf's payout allowance.

### Recommended Fix

```solidity
require(receiver != address(0), "Zero receiver");
```

---

## Overall Assessment

The contract has one **critical** flaw — the second-preimage Merkle attack — that can allow a malicious actor to forge proofs and steal all tokens from the contract. This is a direct consequence of single-hashing the leaf and the coincidental 64-byte overlap with internal node encoding. The contract should not be deployed without fixing this issue.