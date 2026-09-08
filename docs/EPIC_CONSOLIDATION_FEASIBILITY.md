# EPIC Consolidated Rule Cluster — Feasibility Report

> Investigation only — no code changes made.
> Sources: direct code reads of `guards.rs`, `ssa.rs`, `nodes.rs`, `epic_sec_{004,005,009,010}.rs` and the PDA subagent report.

---

## Cluster 1 — PDA Safety

### Current state

`GuardFact::PDA { account, seeds, bump }` is extracted from `#[account(seeds=[...], bump)]`
attributes in `extract_guards_from_accounts_struct()`.  The four sub-checks map as follows:

| Sub-check | What exists | Gap |
|---|---|---|
| **(a) Seeds + bump both present** | `seeds: Vec<FactExpression>` and `bump: Option<FactExpression>` both exist in the fact | Seeds stored as a **monolithic expression** (the whole `[...]` array as one element), not per-component. No rule fires when the PDA fact is missing seeds or bump. |
| **(b) Canonical bump** | `bump: None` (bare `bump`) vs `bump: Some(expr)` (explicit `bump = expr`) is **structurally representable** already | No rule consumes the bump field. The three-way distinction (canonical = `None`, stored = `Some(field.bump)`, caller-supplied = `Some(ix_data.bump)`) is not analysed. |
| **(c) Seed component source validation** | `epic_sec_004.rs` classifies each seed as `Fixed / Variable / Unknown` via type heuristics | Seed provenance (which account each seed component references) is **not tracked**. `FactExpression` has no `DerivedFromAccount(SymbolId)` variant. Only name-string heuristics used. |
| **(d) Intra-PDA seed collision** | `check_seeds_slice()` in SEC-004 checks adjacent-pair (Fixed, Variable) ambiguity in a single PDA's seed array | Cross-PDA collision (two distinct PDAs with overlapping seeds in same instruction) is **not detected**. No cross-instruction registry. |

### Verdict: **Buildable with moderate new fact-gathering**

Two of the four sub-checks are buildable today from existing data; two need targeted additions.

**Buildable now (rule-writing task only):**
- **(a) Missing seeds/bump gate** — Iterate `guard_facts`, find accounts whose type is a PDA (heuristic: name + `#[derive(Accounts)]` membership) but have no matching `GuardFact::PDA`. Fire "missing PDA derivation constraint." No new facts needed.
- **(b) Non-canonical bump** — Consume existing `GuardFact::PDA { bump, .. }`. If `bump` is `Some(expr)` and that expression resolves to anything other than a known stored-bump field (i.e. it is an instruction-data parameter or an `Unknown` expression), fire "caller-supplied bump bypasses canonical derivation." The `FactExpression` tree and `symbol_table` are sufficient for this.

**Requires moderate new fact-gathering:**
- **(c) Seed component source validation** — Need to split the monolithic `seeds` expression into per-slot components and introduce a `DerivedFromAccount(SymbolId)` variant in `FactExpression` (or a parallel `SeedComponent` struct). Change surface: `convert_syn_expr()` and `extract_guards_from_accounts_struct()` in `guards.rs`. Medium scope.
- **(d) Cross-PDA collision** — Need to collect all `GuardFact::PDA` facts for one `InstructionAnalysisContext` and compare seed arrays pairwise for prefix/overlap ambiguity (reusing the existing `check_seeds_slice` + `classify_seed` logic). Medium scope — infrastructure exists in SEC-004; needs lifting to an instruction-level pass.

**Conceptual sketch of a consolidated `EPIC-SEC-PDA` rule:**
```
For each account A in InstructionAnalysisContext:
  pda_fact = guard_facts where GuardFact::PDA { account == A }
  
  if pda_fact is None AND account looks like a PDA:
    → (a) emit: "Account '{A}' declared without PDA derivation constraint"
  
  if pda_fact.bump is Some(expr) AND expr.resolves_to_instruction_data():
    → (b) emit: "PDA bump for '{A}' is caller-supplied — use canonical bump"
  
  for each seed_component in pda_fact.seeds (once per-slot parsed):
    referenced_account = seed_component.derive_source_account()
    if referenced_account not in guard_facts (not validated):
      → (c) emit: "Seed component references unvalidated account '{referenced_account}'"
  
  for each other PDA B in same context:
    if seeds_of(A) and seeds_of(B) share a variable-length prefix:
      → (d) emit: "PDA seed collision risk between '{A}' and '{B}'"
```

---

## Cluster 2 — Token Account Safety

### Current state

Two separate, independent rules:
- **EPIC-SEC-009** (`TokenMintRule`): finds `Account<'info, TokenAccount>` fields lacking a `mint =` / `token::mint` / `has_one` / PDA constraint. Does NOT check authority.
- **EPIC-SEC-010** (`VaultAuthorityRule`): finds `Account<'info, TokenAccount>` fields named `vault` or `pool` lacking an `authority =` / `token::authority` constraint. Does NOT check mint.

There is **no `GuardFact` for token account mint binding**. The `SolanaProperty` enum has no `Mint` variant. The two rules both independently walk the struct's raw attribute strings. Neither calls the other or shares a predicate.

Critical structural gap: a token account named `user_token_account` (not a vault) would fail SEC-009's mint check but never be evaluated by SEC-010's authority check (name filter excludes it). Conversely, a vault with a mint constraint but no authority constraint would be caught by 010 but not re-checked for mint by 009 after the `has_mint = true` branch is hit.

### Verdict: **Buildable now** (this is a rule-writing task with optional minor fact enrichment)

All the data needed already exists: the struct definition, field type strings, field attribute strings, `guard_facts` (for PDA and HasOne checks), and `symbol_table`. The only thing missing is a single predicate that answers both questions together.

**What needs to happen:**
1. Build a helper `fn token_account_constraint_set(field, s_def, guard_facts) -> TokenConstraintSet { has_mint, has_authority }` that checks both at once per field.
2. Fire a combined diagnostic if either is absent: "Token account '{name}' is missing: [mint constraint] [authority constraint]".
3. Optionally add a `GuardFact::TokenAccount { account, mint: Option<FactExpression>, authority: Option<FactExpression> }` variant to consolidate extraction (minor, but would make the facts richer for future rules).

**Conceptual sketch of consolidated `EPIC-SEC-TOKEN` rule:**
```
For each field in Accounts struct:
  if field.type is TokenAccount:
    has_mint = any attr contains (mint=, token::mint) 
               OR has_one points at this field 
               OR PDA fact covers this account
    has_auth = any attr contains (authority=, token::authority, address)
               OR has_one points at this field
               OR PDA fact covers this account
    
    if !has_mint AND !has_auth:
      emit: High — "Token account '{name}' missing both mint and authority constraints"
    elif !has_mint:
      emit: High — "Token account '{name}' missing mint constraint"
    elif !has_auth:
      emit: Medium — "Token account '{name}' missing authority constraint"
      (note: authority absence is lower severity if mint is locked — the account
       is constrained to a specific mint program, just not to a specific owner)
```

This collapses SEC-009 + SEC-010 into one pass and removes the vault/pool name filter from SEC-010, making authority checking universal for all `TokenAccount` fields.

---

## Cluster 3 — Arithmetic Safety

### Current state

| Category | IR representation | Any rule? |
|---|---|---|
| `a + b` (unchecked) | `IRExpression::BinaryOp { op: "+", lhs, rhs }` — operator string preserved | ❌ No rule queries it |
| `.checked_add(b)` | `IRExpression::Call { method: Some("checked_add"), ... }` — method name preserved | ❌ No rule queries it |
| `.saturating_add(b)` | Same — method name preserved | ❌ No rule queries it |
| `a as u32` (truncating cast) | **Silently dropped** — `syn::Expr::Cast` has no arm in `convert_expr()`, falls to `ExpressionKind::Unresolved` → `IRExpression::Literal("unresolved")` | ❌ Structurally invisible |

The SSA layer tracks variable *type* across assignments but has no arithmetic provenance. There is no def-use chain from a `BinaryOp` to a downstream use site. SSA only knows "variable `x` at node 5 has type `u64`", not "variable `x` was produced by `a + b`."

Critically: `IRExpression::BinaryOp` and `IRExpression::Call` already preserve the operator and method names. A pattern-match rule can distinguish `+` from `checked_add` from `saturating_add` right now — **but only within a single expression**. It cannot trace a value across multiple statements (e.g. `let partial = a + b; let result = partial * c;`).

### Verdict: **Split verdict**

| Sub-check | Verdict |
|---|---|
| **Unchecked op detection (within expression)** | **Buildable now** — `BinaryOp { op: "+" }` without surrounding `checked_*` call is visible in IR today |
| **checked vs. unchecked discrimination** | **Buildable now** — method name on `Call` node is preserved (`checked_add`, `saturating_add`, `wrapping_add`) |
| **Value-flow tracing across statements** | **Not feasible without significant IR changes** — SSA has no def-use chain for arithmetic provenance |
| **Truncating cast detection** | **Buildable with moderate new fact-gathering** — requires adding `IRExpression::Cast` and a handler in `convert_expr()` / `ir_converter.rs`; medium scope |

**What the moderate fact-gathering involves for truncation:**
1. Add `IRExpression::Cast { inner: Box<IRExpression>, target_type: String }` to `epic-ir/src/lib.rs`.
2. Add a `syn::Expr::Cast(cast)` arm to `convert_expr()` in `builder.rs`.
3. Add a `ExpressionKind::Cast` arm to `convert_expr_node_to_ir()` in `ir_converter.rs`.
4. Add a `TypeRef` width comparison helper (e.g. `u128 > u64 > u32 > u16 > u8`).

**Conceptual sketch of a consolidated `EPIC-SEC-ARITH` rule (for the buildable parts today):**
```
For each CFG node, for each statement:
  for each IRExpression in statement:
    match expr:
      BinaryOp { op: "+" | "-" | "*" | "<<", lhs, rhs }
        AND parent call is NOT checked_add / saturating_add / wrapping_add:
          → emit: "Unchecked arithmetic on integer operands — use checked_add / saturating_add"

      Cast { target_type, inner } where width(target_type) < width(inferred_type(inner)):
          → emit: "Truncating cast from wider integer — data loss possible"
          (requires Cast IR node — moderate addition)
```

The full "value from arithmetic to use site" semantic question (can an overflow propagate through multiple steps before it matters?) requires proper def-use chain tracking in SSA — a significant IR architecture change. That is a future-roadmap item, not a pre-demo deliverable.

---

## Summary Table

| Cluster | Verdict | Pre-demo? | What's missing |
|---|---|---|---|
| **PDA (a) — seeds+bump gate** | ✅ Buildable now | Yes | Rule-writing only |
| **PDA (b) — canonical bump** | ✅ Buildable now | Yes | Rule-writing only; data already in `GuardFact::PDA.bump` |
| **PDA (c) — seed component source** | 🔶 Moderate | No | Per-slot seed parsing + `DerivedFromAccount(SymbolId)` in `FactExpression` |
| **PDA (d) — cross-PDA collision** | 🔶 Moderate | No | Instruction-level PDA pair comparison (reuse SEC-004 logic) |
| **Token — consolidated mint+auth** | ✅ Buildable now | Yes | Single combined rule replaces SEC-009 + SEC-010 |
| **Arith — unchecked op** | ✅ Buildable now | Yes | Pattern-match on `BinaryOp.op` in IR; no new facts |
| **Arith — truncating cast** | 🔶 Moderate | No | `IRExpression::Cast` + `convert_expr()` arm |
| **Arith — value flow across statements** | ❌ Not feasible now | No | No def-use chain in SSA; needs significant IR architecture change |

### Recommended pre-demo rule additions
Based on the "Buildable now" items above, three consolidated rules are worth building before the demo and are directly comparable to what competitors implement as 4–6 separate rules:

1. **EPIC-SEC-PDA** — covers sub-checks (a) and (b): missing PDA derivation + non-canonical bump. Positions EPIC's semantic bump reasoning as architectural differentiation vs. pattern-match tools.
2. **EPIC-SEC-TOKEN** — replaces SEC-009 + SEC-010 with one joint mint+authority check, removing the vault/pool name filter limitation.
3. **EPIC-SEC-ARITH** (partial) — unchecked `+`, `-`, `*`, `<<` on integer operands. Cast detection is roadmap.
