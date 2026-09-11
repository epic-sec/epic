# KNOWN_LIMITATIONS.md

## Analysis Engine Scope & Known Boundaries

EPIC uses high-precision static analysis and abstract interpretation to detect security vulnerabilities in Anchor programs. The following boundaries define current operational assumptions and planned enhancements.

---

### EPIC-SEC-002: Mutable Write Detection Scope

**Behavior:**  
`EPIC-SEC-002` (Signer Validation Rule) detects privileged state modifications by analyzing `.borrow_mut()` / `.try_borrow_mut()` invocation chains and variable assignments initialized via `let` bindings.

**Scope Boundary:**  
Direct, plain field reassignments on structs without an intermediate `let` binding or explicit borrow call (for example, `account.field = value;`) are not currently evaluated as write triggers by `EPIC-SEC-002`.

**Verification & Real-World Impact:**  
An empirical audit across 5 production Solana codebases (Marginfi, Mango-v4, Orca Whirlpools, Squads-v4, Marinade) confirmed that this scope boundary does **not** result in missed vulnerabilities:
- Every instance of direct field reassignment in the audited codebases operates on accounts already declared as `Signer<'info>` within Anchor context structs (which are automatically validated by EPIC's structural constraint analyzer).
- Remaining instances occur within initialization-only code paths where authority checks are enforced declaratively.

**Roadmap:**  
Extending `EPIC-SEC-002` expression tracing to cover direct assignments is scoped and scheduled for a post-release update, deferred to maintain strict false-positive bounds for the initial release.

---

### Sweep Corpus Scope: metaplex-mpl Excluded (Not an Anchor Program)

**Behavior:**  
`metaplex-foundation/mpl-token-metadata` (pinned commit `349e061053c6fc5b6b815e03e896e4db57012893`) was previously included in EPIC's real-world sweep corpus as a 6th protocol alongside Marginfi, Mango-v4, Orca Whirlpools, Squads-v4, and Marinade. It has been removed. The current sweep corpus is these 5 protocols.

**Root Cause:**  
Verified directly against the pinned commit: zero `anchor-lang` dependency in any `Cargo.toml`, zero `#[program]`, zero `#[derive(Accounts)]` anywhere in the tree. It's a Shank-based native Solana program (`shank = "0.3.0"` in `token-metadata/program/Cargo.toml`, account structs use `#[derive(..., ShankAccount)]`), not Anchor.

EPIC's rules still produced output against it (37 findings, 35 of them `EPIC-SEC-002`) only because Metaplex hand-rolls its own `Context<T>` / `ctx.accounts.X` convention that is syntactically identical to Anchor's idiom despite having no macro behind it. But the premise EPIC's rules are built on — "no dominating check + no static type-level enforcement ⟹ unchecked, because Anchor would otherwise auto-enforce it" — does not hold here: there is no automatic enforcement layer in a native program. Every check is a manual free-function call (`assert_signer`, `assert_owned_by`, `assert_keys_equal`, and Metaplex's own multi-authority-type resolver `AuthorityType::get_authority_type`/`AuthorityRequest`, which has no Anchor equivalent at all).

Compounding this, Metaplex's naming convention — `AccountInfo` parameters suffixed `_info` (`authority_info`, `delegate_info`, `delegate_record_info`) while reusing the bare name (`authority`, `delegate`, `delegate_record`) for unrelated struct-literal fields elsewhere in the same function — collides directly with EPIC's authority-like-symbol scan (see the new known issue below, filed separately since it is a general EPIC bug, not specific to this repo). Of the 35 `EPIC-SEC-002` findings measured, 27 (77%) were flagged under one of these three bare names, matching the collision pattern exactly.

**Decision:**  
Dropped from the sweep corpus rather than corrected in place — the results are not representative of EPIC's accuracy on the Anchor programs it targets, and presenting them alongside 5 genuinely-Anchor protocols would overstate or understate accuracy depending on which way the collision cuts. Re-baselined sweep total and per-rule breakdown live in `benchmarks/sealevel/RESULTS.md` and session history; current 5-protocol total should be treated as the reference number going forward, not any prior 6-protocol figure.

