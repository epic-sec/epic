# EPIC Rules Reference

The rules below are the ones actually wired up in `register_standard_rules`
(`crates/epic/src/rules/mod.rs`) — this list is sourced from that function
directly, not from the set of rule source files on disk (see note at the
bottom).

## EPIC-SEC-001: Missing Program Owner Verification
**Severity**: Critical
**Description**: Mutable state or operations rely on account data without checking the owning program. This allows attackers to pass in forged accounts owned by malicious programs.
**Mitigation**: Add `#[account(owner = ...)]` constraint, use an explicit `require_keys_eq!(account.owner, ...)`, or use an Anchor-validated `Account<'info, T>` type.

## EPIC-SEC-002: Missing Signer Verification
**Severity**: Critical
**Description**: Privileged instructions mutating state must ensure the authority-like account signed the transaction. Findings from this rule carry a witness: the control-flow path from function entry to the flagged write, and, if a check exists, where it sits relative to that path.
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

## EPIC-SEC-PDA: PDA Derivation and Bump Canonicality
**Severity**: Critical (Warning for a downgraded sub-case)
**Description**: Flags accounts used as a PDA (via `find_program_address`/`create_program_address`, or in a signer-seeds array for `invoke_signed`/`CpiContext::new_with_signer`) that lack a `seeds = [...], bump` derivation constraint, and separately flags caller-supplied (non-canonical) bump values. A manual `.key()` comparison against a `find_program_address` result is downgraded to Warning rather than Critical, since that derivation is unconditionally canonical; a comparison against `create_program_address` stays Critical, since it blindly trusts its bump argument.
**Mitigation**: Use `seeds = [...], bump` in the account constraint, or derive with `find_program_address` and validate against the canonical bump.

## EPIC-SEC-TOKEN: Missing Token Account Constraints
**Severity**: High (mint/authority), Medium (combined)
**Description**: Token accounts missing a declarative `mint` and/or `authority` constraint. This rule reads only the `#[account(...)]` attribute text, `has_one` relationships in the same struct, and existing PDA guard facts — it does not analyze the instruction handler body, so a real but imperative check in the handler is invisible to it. See `KNOWN_LIMITATIONS.md` for a measured false-positive-rate discussion (0 of 10 sampled findings were true positives on their own claim).
**Mitigation**: Add `#[account(token::mint = ...)]` / `#[account(token::authority = ...)]`, or ensure another account exerts a `has_one` constraint over it.

---

## Dead rule files, not registered

`EPIC-SEC-009` (`TokenMintRule`, `crates/epic/src/rules/epic_sec_009.rs`) and
`EPIC-SEC-010` (`VaultAuthorityRule`, `crates/epic/src/rules/epic_sec_010.rs`)
still exist as source files but are commented out in
`register_standard_rules` — superseded by `EPIC-SEC-TOKEN`, which covers the
same mint/authority-constraint ground in one rule. They do not run and do not
produce findings. Left in place pending a decision on whether to delete them.
