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

---

### EPIC-SEC-TOKEN: Structural Limitation — No Body Analysis, No Role Awareness

**Behavior:**  
`EPIC-SEC-TOKEN` never analyzes the instruction handler's function body. It reads only the `#[account(...)]` attribute text on the field declaration itself, `has_one` relationships elsewhere in the same `#[derive(Accounts)]` struct, and existing PDA guard facts. This is a fundamentally different (and narrower) mechanism than `EPIC-SEC-001`/`EPIC-SEC-002`, which at least attempt CFG dominance analysis to find a manual check in the handler body. A manual check on a token account — however rigorous, however clearly it closes the gap — is invisible to `EPIC-SEC-TOKEN` by construction, because it never looks past the struct definition.

`EPIC-SEC-TOKEN` also does not distinguish a token account's *role* in the operation it's declared for. A credit-only account — a deposit source that only ever gives value away, or a mint destination that only ever receives newly-minted tokens — has no attacker-exploitable path that an authority constraint would close, since no one is harmed by an arbitrary correctly-typed account being the recipient. `EPIC-SEC-TOKEN` demands both a mint constraint and an authority constraint uniformly, regardless of role.

**Verification:**  
Sampled 10 `EPIC-SEC-TOKEN` findings across 4 protocols (mango-v4, marginfi, marinade, orca-whirlpools) with full source review of each flagged account's declaration and its instruction handler:
- **0 of 10 were true positives.**
- **6 of 10** had a real, dominating check in the handler body — sometimes an explicit `require!`/`check!` naming the exact invariant (e.g. mango-v4's `serum3_settle_funds.rs`: `require!(quote_bank.vault == accounts.quote_vault.key(), ...)`; marinade's `liquid_unstake.rs`: `check_token_source_account(...)` verifying owner-or-delegate), sometimes protocol-level enforcement from the SPL Token program itself (a `transfer`/`transfer_checked` CPI unconditionally rejects a mismatched mint or an unauthorized signer, independent of anything the calling program checks).
- **4 of 10** required no constraint at all: the flagged account was a credit-only role (a deposit source such as mango-v4's `token_account` in `token_deposit.rs`, or a mint/fee destination such as marginfi's `destination_account` in `collect_bank_fees.rs` and marinade's `mint_to` in `deposit.rs`) where an authority constraint doesn't correspond to any real risk.

**Impact:**  
The finding message — *"Token account 'X' missing mint constraint"* / *"missing authority constraint"* / *"missing both mint and authority constraints"* — overstates what the rule actually detects. It reads as "this account is unconstrained and exploitable." What it actually detects is closer to *"this account does not use Anchor's declarative constraint idiom (`token::mint =`, `token::authority =`, `has_one`, etc.)"* — a style/idiom observation, not a vulnerability claim, given the rule has no way to see whether the same guarantee is enforced imperatively or by the SPL Token program itself.

**Status:**  
Documented, not fixed. `EPIC-SEC-TOKEN` findings should not be read as security findings without independently checking the instruction handler body — this document exists so that check isn't skipped.

---

### EPIC-SEC-TOKEN: Attempted Keyword Fix, Rejected

**The bug:**  
`epic_sec_token.rs`'s `has_authority` check (lines ~65-74) scans each field's `#[account(...)]` attribute text for the literal substrings `"authority"`, `"key"`, `"vault"` inside a `constraint = ...` clause, but not `"owner"`. This causes a false negative on a genuine, well-formed Anchor constraint: mango-v4's `token_force_withdraw.rs:51`, `constraint = alternate_owner_token_account.owner == account.load()?.owner`, is a real authority check that the rule doesn't recognize because it never looks for `"owner"`.

**The attempted fix:**  
Adding `"owner"` to the keyword list was implemented, built, and measured against the 5-protocol sweep and the full test suite (72 passed, 0 failed — no regression there). It was then reverted before commit.

**Why it was rejected:**  
The check is a bare substring match over the *entire* attribute text, not a match against a parsed constraint expression. Anchor constraints reference their own field by name (e.g. `constraint = token_owner_account_a.mint == whirlpool.token_mint_a`) — and orca-whirlpools names several `TokenAccount` fields with `owner` baked into the field name itself (`token_owner_account_a`, `token_owner_account_b`, `reward_owner_account`, `token_owner_account_one_a/b`, `token_owner_account_two_a/b`). Adding `"owner"` to the substring list matched the *field's own name* sitting inside a mint-only constraint, not a genuine `.owner` property comparison — and silently suppressed 18 legitimate "missing authority constraint" findings on orca-whirlpools that had no owner check of any kind. Measured impact: the 5-protocol sweep total dropped from 224 to 206, entirely from this one repo, none of it a real fix.

This also means the fix wasn't even clean on the case it was meant to solve: `alternate_owner_token_account` is itself a field name containing `owner`, so the same ambiguity is latent there too — it happens to produce the right answer for the field it was written for, but the mechanism generating that answer is unsound, not merely narrow.

**Status:**  
Not fixed, not scheduled. A correct fix requires parsing the constraint expression (e.g. via `syn`) to test for a genuine `.owner` field access on the account being declared, rather than substring-matching the raw attribute text — the same class of fix noted in `docs/` for other rules that currently rely on text heuristics over parsed structure. Given the demonstrated risk of a narrow substring change silently flipping real findings to false negatives at scale, this should not be attempted again without that structural rework in place.

---

### Architectural Finding: Signer-Check Dominance Is Mostly Redundant With Anchor's Type System

**The finding:**  
Interprocedural dominance analysis for signer checks (`EPIC-SEC-002`'s core mechanism, extended across three build stages — call graph, guard summaries, caller-CFG wiring) has real, measured payoff against the sealevel-attacks benchmark's synthetic cases, but essentially zero incremental payoff against real production Anchor code. The reason: Anchor's `Signer<'info>` account type already gives the same guarantee declaratively, for free, at parse time — no CFG, no dominance, no interprocedural reasoning required. Imperative signer checks worth tracing across function boundaries are rare in idiomatic Anchor code specifically *because* the type system already covers the common case. Where they do show up, it tends to be in code that has a reason to step outside the Anchor idiom (a native-style entrypoint, a shared helper written before/around the type system's guarantee) — and even then, the account in question is often *also* covered declaratively, making the imperative check and the interprocedural fact both correct and both redundant.

**Four measurements, in the order they were made:**

1. **Stage 2 summary survey (5 repos, before the `is_early_return` fix):** 14 raw `.is_signer` occurrences across mango-v4, marginfi, marinade, orca-whirlpools, and squads-v4, but 0 non-empty guard summaries — i.e. 0 functions where an imperative signer check could be proven to dominate every exit. After fixing a real CFG gap (hand-written `if cond { return Err }` not tagged as an early return), that number moved to exactly 2, both in marginfi's `test_transfer_hook` program.

2. **Stage 3 wiring, first 5-repo sweep:** those 2 non-empty summaries' only caller, in the entire corpus, was `test_transfer_hook::process` — a native `fn process(program_id: &Pubkey, accounts: &[AccountInfo], ...)` entrypoint, not an Anchor `Context<T>` handler. It exists outside the Anchor idiom precisely because it has no `Signer<'info>` to declare in the first place. SEC-002 total across all 5 repos: unchanged (65 before, 65 after Stage 3 wiring went live).

3. **`||`/`&&` decomposition fix, second 5-repo sweep:** surfaced a third non-empty summary, orca-whirlpools's `util/shared.rs::validate_owner` — a genuine imperative signer check in a genuine Anchor program. Its one directly-reachable call site (`transfer_locked_position.rs::handler`, called unconditionally) turned out to pass `position_authority`, which is declared `Signer<'info>` in the `Accounts` struct — already provably safe by the existing declarative path before any of this session's work existed. The new interprocedural fact was correct and changed nothing: SEC-002 total unchanged again, byte-identical output before/after.

4. **Sealevel scorecard, class 0 (`signer-authorization`):** the benchmark's own synthetic "insecure" fixture had to reach for a bare `AccountInfo` with no `Signer<'info>` wrapper and a hand-rolled `.is_signer` read to construct a missing-signer-check scenario at all — and even that fixture is a false negative for an unrelated reason (SEC-002's write-only mutation gate doesn't trigger on a read-only misuse, see the note above in this file). The benchmark couldn't find a *write-triggering* gap in the declarative-Signer idiom to exploit; it had to step outside that idiom entirely.

**Why this happened:**  
`Signer<'info>` is a static, structural guarantee checked by Anchor's own macro-generated deserialization code before the handler body ever runs. A CFG/dominance approach re-derives, at much greater engineering cost (three build stages, ~400 lines, a call graph, bottom-up summarization, conservative depth/recursion handling), a guarantee the type system already gives for zero cost when the account is declared correctly. The three build stages were not wasted — the mechanism is sound, verified via fixtures, and does the right thing when it applies — there just isn't much surface area left for it to apply to in code that already uses Anchor idiomatically.

**Where the payoff actually is:**  
The account-safety properties Anchor's type system does *not* give you for free are exactly the ones with no declarative equivalent:
- **Discriminator/type confusion** (`EPIC-SEC-004`-adjacent territory) — Anchor's `Account<'info, T>` checks the discriminator, but hand-rolled `AccountLoader`/zero-copy paths and cross-program account aliasing are not covered by any attribute.
- **Arithmetic correctness** (overflow/underflow/precision loss in balance and share-price math) — no Anchor type expresses "this multiplication won't overflow" or "this division order avoids precision loss."
- **Post-CPI staleness** (`EPIC-SEC-003`'s territory) — whether cached account data was re-read after a CPI that could have reloaded/mutated it underneath the caller. No type-level annotation exists for "this reference might now be stale."

None of these have a `Signer<'info>`-equivalent shortcut. A handler can be entirely correct about signers and owners via the type system alone and still be exploitable through any of the three above — which is exactly the gap dominance analysis *can't* close by being pointed at signer checks harder, but where the same interprocedural machinery (call graph + summaries + wiring) built for this feature would have a real, non-redundant target if retargeted at one of these properties instead.

**Status:**  
Not a bug — the interprocedural guard analysis feature works as built and is kept (correct beats redundant). This is a note for scoping the *next* build: further investment in signer-check dominance specifically has a demonstrated low ceiling against real Anchor code; the same machinery pointed at discriminator confusion, arithmetic, or post-CPI staleness has not been tried and has no declarative-type-system shortcut competing with it.
