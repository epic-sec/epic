# Soroban core leaks

Every place building the Soroban v0 frontend hit an assumption baked into
the shared Anchor-era core (`crates/epic/src/cfg/`, `audit.rs`), with file
and line. None of these were fixed in the shared code; each was worked
around entirely inside `crates/epic/src/soroban/`, so the Anchor pipeline
is untouched (confirmed: `scripts/sweep.sh` total stayed at 248, byte-
identical per protocol, before and after this entire piece of work).

## 1. `CFGBuilder` treats `match` as an opaque boundary

`crates/epic/src/cfg/builder.rs:491` (`syn::Expr::Match(_) =>` inside
`scan_boundary_warnings`) is the *only* place `CFGBuilder` looks at a
`match` expression at all -- it records `CFGBoundaryWarning::MatchExpression`
and never descends into arms. `convert_expr` (same file) has no `Match`
arm either, so a `match` used as a statement collapses to
`ExpressionKind::Unresolved` -- every arm's statements, including any
write or auth check inside them, are invisible to any Anchor rule.

Fine for Anchor (comparatively rare; mango-v4 hits this on only 11/181
handlers, all still get rules run on their straight-line code around the
match). Not fine for Soroban, which dispatches via `match` constantly
(action enums, error handling) -- review fixture (f) (`match` where one
arm authenticates and writes, the other calls `panic_with_error!`) is
exactly this shape, and it must work.

**Workaround:** `crates/epic/src/soroban/cfg_builder.rs`'s
`SorobanCfgBuilder::compile_match` descends into every arm, generalizing
the existing if/else branch+merge pattern to N arms. Entirely separate
builder; `CFGBuilder` untouched.

## 2. `is_terminating_stmt`/`is_terminating_expr` don't know `panic_with_error!`

`crates/epic/src/cfg/builder.rs:534,553` (`is_terminating_stmt`) and
`:963,990` (equivalent checks) recognize `panic!`/`unreachable!` by name,
not Soroban's own `panic_with_error!` macro. Review round 1 point 3
explicitly anticipated this and allowed a `builder.rs` edit if needed
(with the sweep held at 248) -- not needed in the end.

**Workaround:** `cfg_builder.rs`'s own `is_abort_macro`/`terminal_kind`
check for `panic`, `unreachable`, *and* `panic_with_error` directly.
`builder.rs` untouched.

## 3. No IR representation for a plain function call at all

`ExpressionKind` (`crates/epic/src/ast/nodes.rs:54`) has `MethodCall` but
no `Call` variant. `convert_expr` therefore turns any `foo(x)`-shaped
free-function call into `ExpressionKind::Unresolved` -- confirmed earlier
this same session investigating why orca-whirlpools' handler-delegates-
to-a-free-function idiom was invisible to Anchor rules. For Soroban,
where `check_admin(&e)`-style one-hop helpers are exactly what review
round 1 point 4 asks to resolve, this is a hard blocker: the converted
`CFGNode.statements` literally cannot name which helper was called.

**Workaround:** `cfg_builder.rs`'s `HelperCallVisitor` scans the *raw*
`syn::Expr` tree directly (via `syn::visit::Visit`, not the converted IR)
for `syn::ExprCall` nodes, run at leaf statements, `if`-conditions, and
`match` scrutinees during CFG construction. Nothing in `ast`/`cfg` changed.

## 4. Helper calls are routinely made through a qualified path, not a bare name

First cut matched only `syn::Path::get_ident()` (single segment). Running
against CoinFabrik's real `scout-soroban` `set-contract-storage-4` fixture
immediately found a miss: the entrypoint calls `utils::increment(env, user)`
-- a 2-segment path -- which `get_ident()` doesn't match at all, so the
helper call was never even detected.

**Fix (inside the Soroban module only):** match by the path's *last*
segment instead, the same bare-name convention `callgraph.rs`'s own
by-name resolution already uses elsewhere in this crate. `HelperIndex`
still refuses an ambiguous name, so this doesn't trade safety for recall.

## 5. `#[cfg(test)]` code pollutes the same-crate helper name index

Same `set-contract-storage-4` fixture: a `#[cfg(test)] mod tests { #[test]
fn increment() { .. } }` test function happens to share a name with the
real production helper `utils::increment`. The crate-wide helper index
(built to mirror `callgraph.rs`'s own ambiguity-refusal convention) saw
two functions named `increment` and marked the name unresolvable --
silently turning a real, resolvable helper call into "uncertain," which
(combined with leak #7 below) produced a false negative before this was
fixed.

**Fix:** `mod.rs`'s `FreeFnVisitor` now skips any `fn`/`mod` tagged
`#[cfg(test)]` entirely. Narrow, test-code-specific; not general
`#[cfg(..)]` evaluation.

## 6. The storage-sink chain walk doesn't see through a local alias

`env.storage().instance().set(&k, &v)` is one method-call chain the sink
walk follows fine. But every one of CoinFabrik's 4 real
`set-contract-storage` fixtures instead writes:

```rust
let storage = env.storage().instance();
storage.set(&k, &v);
```

-- the receiver of `.set()` is the bare local `storage`, not a chain
containing a `"storage"` method call at all. Without tracking this one
specific alias, these would have been invisible, a 4/4 miss on the
corpus actually built to exercise this detector.

**Fix:** a narrow, first-pass scan (not general alias analysis) records
any `let NAME = <chain containing a `.storage()` call>;` and treats
`NAME.set/remove(..)` the same as the direct chain.

## 7. One-hop helper following answered the wrong question

As scoped, "follow one hop" only asked "does calling this helper guarantee
`require_auth`." It never asked "does this helper's body also contain the
*sink*" -- so a handler that delegates its *entire* body (write included,
not just the auth check) to a one-hop helper was invisible end to end.
Confirmed as a real false negative against two CoinFabrik fixtures
(`set-contract-storage-4`, `unprotected-mapping-operation-2`), where the
entrypoint's whole body is `utils::f(..)` and the actual
`storage.set(..)`/`Map.set(..)`-then-`storage.set(..)` lives inside `f`.

**Fix:** `analyze_helper` now also returns the helper's own sinks that
aren't dominated by the helper's own `require_auth` calls (same
`DominanceChecker`, applied to the helper's own CFG); those are "exposed"
at the outer call site exactly as if written there directly, and flow
into the same set-avoiding bypass check as any other sink. This is a real
capability extension beyond what review round 1 literally asked for
(which was framed around auth-only helpers like `check_admin`) -- flagged
here rather than silently expanding scope without a trace.

## 8. `?`-triggered early return is not modeled as its own edge

`CFGBuilder`'s original builder has dedicated `find_tries` handling to
turn a fallible `expr?;` into an early-return edge. The Soroban builder
does not reimplement this -- a `foo()?;` is just an ordinary statement,
and code after it is modeled as always-reached on the "normal" path, even
though a real `Err` would skip it. Not hit by any of the review's
required fixtures or the external comparison corpus; left as a known gap,
not fixed, rather than risk a rushed, under-tested version of it.

## 9. Loops are an opaque boundary, same as `CFGBuilder`

Not entered, same choice the shared builder already makes. Not hit by any
required fixture or by `solis-escrow`.

## 10. v0's rule doesn't check *which* address was authorized

Any `require_auth()`/`require_auth_for_args()` call anywhere on the path
counts, regardless of whose address it authorized -- exactly as scoped
("report a finding when a sink is reachable... that doesn't pass through
a require_auth"). `GuardTarget` (Account/Variable, per review point 5) is
recorded on every auth call found, for a v1 that cross-checks it against
the sink's own target; v0 does not consume it yet.
