---

# Security Audit Report — `CTFVoting.sol`

---

## Summary

| Severity | Count |
|---|---|
| Critical | 1 |
| High | 1 |
| Medium | 1 |
| Low | 1 |
| Informational | 2 |

---

## [CRITICAL] Unprotected `setOwner` — Full Ownership Takeover

**Location:** `setOwner()`, line 45–47

**Description:**
The `setOwner` function has **no access control whatsoever**. Any externally owned account or contract can call it and immediately become the owner of the contract, granting them the `onlyOwner` privileges: adding arbitrary proposals and extending the voting deadline indefinitely.

**Proof of Concept:**
```solidity
// Attacker calls directly — no prior ownership required
CTFVoting(target).setOwner(attacker);
// Attacker is now owner
CTFVoting(target).addProposal("Attacker-controlled proposal");
CTFVoting(target).extendVoting(365 days);
```

**Recommended Fix:**
Add the `onlyOwner` modifier:
```solidity
function setOwner(address newOwner) public onlyOwner {
    require(newOwner != address(0), "Zero address");
    owner = newOwner;
}
```

---

## [HIGH] Vote Manipulation via Contract Accounts (Sybil Attack)

**Location:** `vote()`, lines 28–34

**Description:**
Voter eligibility is gated solely on `hasVoted[msg.sender]`. There is no whitelist, token-holding check, or registration mechanism. Any actor can deploy an arbitrary number of contracts (or use a factory pattern) and call `vote()` from each address, effectively casting unlimited votes for any proposal.

**Proof of Concept:**
```solidity
contract VoteSpammer {
    function spam(address target, uint256 idx, uint256 n) external {
        for (uint i = 0; i < n; i++) {
            new VoterProxy(target, idx);
        }
    }
}
contract VoterProxy {
    constructor(address target, uint256 idx) {
        CTFVoting(target).vote(idx);
    }
}
```

**Recommended Fix:**
Implement a voter whitelist (registration phase before voting opens), or gate voting on ownership of an ERC-20/ERC-721 token snapshot taken before voting begins.

---

## [MEDIUM] `winningProposal()` Returns Index `0` on Tie or Zero Votes

**Location:** `winningProposal()`, lines 49–57

**Description:**
When all proposals have zero votes, or when there is a tie at the top vote count, the function silently returns index `0` as the winner. This is a logical error: callers have no way to distinguish "proposal 0 genuinely won" from "no votes were cast" or "a tie occurred."

**Proof of Concept:**
- Deploy with two proposals, cast zero votes → `winningProposal()` returns `0`, implying proposal 0 won.
- Cast equal votes on both proposals → proposal 0 is always declared the winner regardless.

**Recommended Fix:**
Return a boolean indicating validity, or revert when no votes have been cast:
```solidity
function winningProposal() public view returns (uint256 winningProposalIndex, bool valid) {
    uint256 winningVoteCount = 0;
    for (uint i = 0; i < proposals.length; i++) {
        if (proposals[i].voteCount > winningVoteCount) {
            winningVoteCount = proposals[i].voteCount;
            winningProposalIndex = i;
            valid = true;
        }
    }
}
```

---

## [LOW] `extendVoting` Has No Upper Bound

**Location:** `extendVoting()`, lines 41–43

**Description:**
The owner (or any attacker who has hijacked ownership via the critical bug above) can call `extendVoting` with an arbitrarily large `extraTime`, permanently keeping voting open. There is no cap on how far the deadline can be pushed, undermining the integrity of the voting period.

**Recommended Fix:**
Enforce a maximum extension cap, e.g.:
```solidity
uint256 public constant MAX_EXTENSION = 7 days;
function extendVoting(uint256 extraTime) public onlyOwner {
    require(extraTime <= MAX_EXTENSION, "Extension too long");
    votingDeadline += extraTime;
}
```

---

## [Informational] Owner Can Add Proposals During Active Voting

**Location:** `addProposal()`, lines 36–39

**Description:**
The owner is permitted to add new proposals after voting has already begun. Voters who cast ballots early are not informed of newly-added options. This allows the owner to introduce a "winning" proposal after observing vote distributions.

**Recommended Fix:**
Restrict `addProposal` to a setup phase before voting opens (e.g., only when `block.timestamp < votingStart`).

---

## [Informational] No Event Emissions

**Location:** Contract-wide

**Description:**
No `event` is emitted for any state-changing operation (`vote`, `addProposal`, `extendVoting`, `setOwner`). This makes off-chain monitoring and auditability impossible.

**Recommended Fix:**
Define and emit events for all state changes:
```solidity
event Voted(address indexed voter, uint256 indexed proposalIndex);
event ProposalAdded(uint256 indexed index, string description);
event OwnerChanged(address indexed previousOwner, address indexed newOwner);
event DeadlineExtended(uint256 newDeadline);
```

---

## Overall Assessment

The most severe issue is the **completely unprotected `setOwner` function** — it renders all other access controls meaningless, as any attacker can instantly become the contract owner. Combined with the absence of any Sybil-resistance mechanism for voters, this contract cannot be considered secure for any real-world use.