## Security Audit Report — `MerkleDrop.sol` (MerkleAirdrop)

---

### Overview

`MerkleAirdrop` is a standard Merkle-proof airdrop contract allowing eligible recipients to claim ERC20 tokens by submitting a valid proof against a stored root. The contract inherits OpenZeppelin's `Ownable` and uses `SafeERC20`.

---

### Findings

---

#### [LOW-1] No Mechanism to Recover Unclaimed Tokens

**Location:** Contract-level (no withdrawal function exists)

**Description:**
The contract can be funded with tokens, but there is no `withdraw` or `recoverTokens` function. If an airdrop concludes with unclaimed tokens — due to unreachable recipients, incorrect proofs, or a purposeful end-of-campaign — those tokens are permanently locked in the contract.

**Attack / Impact Scenario:**
Owner deploys contract, funds it with 1,000,000 tokens, and sets the root. If 200,000 tokens remain unclaimed after the campaign ends, they are irrecoverably stuck.

**Recommended Fix:**
Add an owner-gated sweep function:
```solidity
function recoverTokens(address to, uint256 amount) external onlyOwner {
    token.safeTransfer(to, amount);
}
```
Optionally pair it with a `claimDeadline` timestamp after which claims are disallowed and recovery is enabled.

---

#### [LOW-2] Owner Can Silently Update the Merkle Root Mid-Airdrop

**Location:** `setMerkleRoot()`, line 23–25

**Description:**
The owner can replace `merkleRoot` at any time. This allows the owner to:
- Remove recipients from a new root (censorship / rug)
- Add new recipients without transparency
- Front-run a pending claim transaction, replacing the root with one that excludes the pending leaf, causing the transaction to revert with "Invalid proof"

Because `paid` entries from the old root are not cleared, any previously claimed leaf remains marked as claimed — but unclaimed entries under the old root become permanently uncollectable if the root changes.

**Recommended Fix:**
- Emit an event that includes the old and new roots to improve auditability (currently the function emits nothing)
- Consider a timelock or multi-sig governance before root updates go into effect
- Document that root updates are only intended for multi-phase drops

---

#### [INFORMATIONAL-1] No Claim Deadline / Expiry

**Location:** `claim()`, line 27–43

**Description:**
Claims can be submitted indefinitely. There is no `claimDeadline` or similar control. This means token liquidity is permanently at risk of being claimed long after the intended airdrop window.

**Recommended Fix:**
Add a configurable deadline:
```solidity
uint256 public claimDeadline;
require(block.timestamp <= claimDeadline, "Airdrop expired");
```

---

#### [INFORMATIONAL-2] Third-Party Can Trigger Claims on Behalf of Any Receiver

**Location:** `claim()`, line 27–43

**Description:**
The function does not require `msg.sender == receiver`. Any external account can call `claim` for any valid recipient. While this is common design for gasless/push airdrops, it could cause issues in jurisdictions where receiving an asset triggers tax liability (forcing a tax event on a user who did not act), or when paired with tokens that execute receiver hooks (ERC-777/ERC-1363).

**Note:** The CEI pattern is correctly observed (`paid[leaf] = true` is set before `safeTransfer`), so re-entrancy via receiver hooks is not exploitable here.

**Recommended Fix:**
If self-claiming is the intent, add `require(msg.sender == receiver, "Must claim yourself");`. If third-party claiming is intentional, document it clearly.

---

#### [INFORMATIONAL-3] OpenZeppelin v5 Incompatibility

**Location:** `constructor()`, line 18–21

**Description:**
OpenZeppelin v5 changed the `Ownable` constructor to require an explicit `initialOwner` argument: `Ownable(address initialOwner)`. The current constructor does not call `Ownable(msg.sender)`, which will cause a compilation failure if upgraded to OZ v5. The contract currently compiles only under OZ v4.

**Recommended Fix:**
```solidity
constructor(IERC20 _token, bytes32 _merkleRoot) Ownable(msg.sender) {
```
This is a no-op under OZ v4 (ignored) and compatible with OZ v5.

---

### Security Properties That Hold

| Property | Assessment |
|---|---|
| **Double-claim prevention** | Correct. `paid[leaf]` is keyed on the full leaf hash including nonce, receiver, and amount. |
| **Re-entrancy** | Safe. `paid[leaf] = true` is set before `safeTransfer` (CEI respected). |
| **Merkle proof forgery** | Not feasible. Leaf preimage is 84 bytes (`uint256‖address‖uint256`); internal node preimage is 64 bytes (`bytes32‖bytes32`). Different preimage lengths prevent second-preimage confusion attacks. |
| **Hash collision via `abi.encodePacked`** | Not applicable. All three leaf fields are fixed-width types; no ambiguity in encoding. |
| **Sorted-pair Merkle verification** | Correctly implemented. The `computedHash <= proofElement` ordering is standard and avoids order-dependent proof forgery. |
| **SafeERC20 usage** | Correctly applied; handles non-standard ERC20 tokens that do not return `bool`. |

---

### Summary

No critical or high-severity vulnerabilities were found. The contract implements the Merkle airdrop pattern correctly with proper double-claim protection and safe external call ordering. The two low-severity issues (no token recovery, unconstrained root updates) represent operational and trust risks rather than exploitable security flaws.