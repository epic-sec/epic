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

---

### EPIC-SEC-001 / EPIC-SEC-002: Struct-Literal Field Name Collision in Authority-Like Symbol Scan

**Behavior:**  
`EPIC-SEC-001` and `EPIC-SEC-002` both scan for "authority-like" account symbols (names containing `authority`, `admin`, `owner`, `delegate`, etc.) that lack a dominating owner/signer check. That scan matches on bare identifier/field text without distinguishing "a real account symbol referenced from `ctx.accounts.X`" from "an arbitrary struct-literal field label that happens to share the same name."

**Concrete Example** (`metaplex-mpl`, `programs/token-metadata/program/src/processor/burn/burn.rs:104-108`, commit `349e061053c6fc5b6b815e03e896e4db57012893`):

```rust
// line 57 — the real, dominating signer check:
assert_signer(ctx.accounts.authority_info)?;

// ...

// lines 104-108 — a struct literal being built for an unrelated helper call:
let authority_response = AuthorityType::get_authority_type(AuthorityRequest {
    authority: ctx.accounts.authority_info.key,   // <- struct-literal field name "authority"
    update_authority: &metadata.update_authority,
    mint: ctx.accounts.mint_info.key,
    // ...
});
```

The real account is `authority_info`, and it is correctly checked via `assert_signer` before this statement. But EPIC's finding names the flagged account **`authority`** — the label on the left of `:` in the `AuthorityRequest { .. }` literal, not the account referenced on the right of it. Since no account symbol literally named `authority` exists in this instruction's `Context`, the search for a dominating check on `authority` comes up empty, and EPIC reports a spurious CRITICAL finding for an account that isn't real, on top of a real account (`authority_info`) that was checked correctly.

**Impact:**  
Not specific to non-Anchor code. Any Anchor program containing a pattern like `SomeStruct { authority: ctx.accounts.some_other_field.key(), .. }` — building a struct whose field happens to be named the same as one of the scan's authority-like keywords, populated from a *different* account than the one that name would suggest — would trigger the same false match, independent of whether the account actually being referenced is validated. This was found via the metaplex-mpl corpus-scope investigation above, where it explains the majority (27 of 35) of that repo's `EPIC-SEC-002` findings, but the underlying mechanism is general to both rules and to any codebase using this shape.

**Status:**  
Documented, not fixed. Filed here as a known issue on record rather than left undiscovered. Fixing it requires the authority-like-symbol scan to resolve struct-literal field values back to their source `ctx.accounts.X` expression (the way `resolve_expr`/`resolve_expr_ir` already does for direct references) rather than treating the field *label* itself as a candidate account symbol — not yet scoped or scheduled.
