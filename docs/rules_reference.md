# EPIC Rules Reference

The EPIC Semantic Engine currently enforces the following safety rules:

## EPIC-SEC-001: Missing Program Owner Verification
**Severity**: Critical
**Description**: Mutable state or operations rely on account data without checking the owning program. This allows attackers to pass in forged accounts owned by malicious programs.
**Mitigation**: Add `#[account(owner = ...)]` constraint, use an explicit `require_keys_eq!(account.owner, ...)`, or use an Anchor-validated `Account<'info, T>` type.

## EPIC-SEC-002: Missing Signer Verification
**Severity**: Critical
**Description**: Privileged instructions mutating state must ensure the authority-like account signed the transaction.
**Mitigation**: Add `#[account(signer)]` or use `Signer<'info>`.

## EPIC-SEC-003: Stale State After CPI
**Severity**: Critical
**Description**: Accounts passed to a CPI might be mutated by the callee. Reading from them directly afterwards without reloading can lead to using stale data.
**Mitigation**: Call `account.reload()?` before reading state post-CPI.

## EPIC-SEC-004: PDA Seed Collision
**Severity**: Critical
**Description**: PDA derivations with ambiguous or colliding variable seeds (e.g., dynamically sized variables placed sequentially without delimiters).
**Mitigation**: Ensure safe literal delimiters or fixed-length byte slices between variable PDA seeds.

## EPIC-SEC-005: Arbitrary CPI Target Validation
**Severity**: Critical
**Description**: CPI calls must validate the target program statically or imperatively to prevent calls to arbitrary malicious programs.
**Mitigation**: Use `Program<'info, T>` for static checking or enforce `require_keys_eq` on the target program's key.

## EPIC-SEC-009: Missing Mint Constraint
**Severity**: High
**Description**: Token accounts missing a declarative `mint` constraint could be injected with malicious tokens.
**Mitigation**: Add `#[account(token::mint = ...)]` or ensure another account exerts a `has_one` constraint over it.

## EPIC-SEC-010: Missing Authority Constraint
**Severity**: High
**Description**: Token accounts missing an `authority` constraint could be owned by an attacker, allowing them to withdraw tokens.
**Mitigation**: Add `#[account(token::authority = ...)]`.
