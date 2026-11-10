//! Stage 2 (+ multi-hop) of interprocedural writes-through-`&mut self`:
//! write summaries.
//!
//! Stage 1 (`callgraph.rs::resolve_typed`) answers "which function does
//! `ctx.accounts.process(..)` / `position.update(..)` actually call into."
//! This module answers the next question, for that resolved callee, with
//! no outer caller in the picture yet: "which of its own `self.<field>`
//! targets does it write, and what guard-worthy conditions — established
//! either directly in this method's own body, or by a further
//! `self.<method>()` call it makes, up to `guard_summary::MAX_DEPTH` hops
//! — dominate each one?"
//!
//! The multi-hop half exists because single-hop measured a concrete false
//! positive on real source: marinade's `Claim::process` writes
//! `self.state.circulating_ticket_balance -= lamports;` unconditionally in
//! its own body, but its first statement is
//! `self.check_ticket_account()?`, and *that* method validates
//! `self.ticket_account.state_address == self.state.key()` — one hop
//! deeper than a single-function scan sees. Reuses `guard_summary.rs`'s
//! own depth-cutoff (`MAX_DEPTH`) and cycle-detection pattern
//! (`in_progress`) rather than re-deriving them, generalized from "which
//! params are proven signer-checked" to "which `self.<root>` names does
//! some dominating condition mention" — a strict superset: a signer check
//! (`self.authority.is_signer`) is just one shape of condition that
//! mentions a root, not a special case this module treats differently.
//!
//! Not wired into any rule or the shipped CLI — still measurement-only,
//! consumed by `field_access_index.rs`'s stage-3 translation.
//!
//! Conservative in the same direction as every other rule in this crate:
//! a write this can't resolve to a clean `self.<path>` chain is silently
//! skipped, never guessed at; a condition this can't prove dominates
//! *every* exit of the function it's borrowed from is never propagated
//! across a call boundary — under-claim, not over-claim, same discipline
//! `guard_summary.rs` documents for its own signer summaries.

use crate::ast::{ExpressionKind, ExpressionNode, StatementKind, StatementNode};
use crate::callgraph::{CallGraph, FunctionId, FunctionInfo};
use crate::cfg::ControlFlowGraph;
use crate::guard_summary::{build_cfg, find_call_node, ok_exit_nodes, MAX_DEPTH};
use crate::rules::DominanceChecker;
use std::collections::{HashMap, HashSet};

/// One write a method makes to its own receiver's state.
#[derive(Debug, Clone)]
pub struct WriteFact {
    /// The written field, dotted for nested access (`"liquidity"`,
    /// `"indexer_flags.has_isolated"`) — never just the bare root, so a
    /// caller can later tell two different fields of the same receiver
    /// apart, same convention `EPIC-SEC-ARITH` already uses for paths.
    pub field_path: String,
    pub node_id: usize,
    pub line: usize,
    /// Human-readable guard-worthy conditions dominating this write —
    /// found directly in this method's body, or inherited from a further
    /// `self.<method>()` call (up to `MAX_DEPTH` hops) whose own
    /// condition dominates *every* exit of that deeper method, and whose
    /// call site here dominates this write. Empty, not an error, when no
    /// such condition exists anywhere in the chain — still the common
    /// case: most authority checks live in the *caller's* `Accounts`
    /// struct declaration, outside anything this module can see.
    pub dominating_guards: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct WriteSummary {
    pub writes: Vec<WriteFact>,
}

/// A guard-worthy condition, and which `self.<root>` account/field name it
/// concerns — e.g. `require_keys_eq!(self.ticket_account.state_address,
/// self.state.key(), ..)` produces *two* facts from one condition, one for
/// `root: "ticket_account"` and one for `root: "state"`, both with the
/// same `text`. A write is credited by root match, not by re-deriving what
/// the comparison actually proves — the same "mentions the root, is
/// unconditional" bar `guard_summary.rs` already uses for signer checks,
/// generalized rather than replaced.
#[derive(Debug, Clone)]
struct SelfGuardFact {
    root: String,
    text: String,
}

/// Computes the write summary for one method body. `call_graph` is needed
/// to follow further `self.<method>()` calls for the multi-hop guard
/// search; pass the same `CallGraph` stage 1 already built for the repo.
pub fn compute_write_summary(info: &FunctionInfo, call_graph: &CallGraph) -> WriteSummary {
    let id = crate::callgraph::function_id(&info.file_path, info.impl_type.as_deref(), &info.name);
    let mut computer = SelfGuardComputer::new(call_graph);
    let (cfg, facts) = computer.facts_in(&id, info);
    let dom = DominanceChecker::new(&cfg);

    let mut writes = Vec::new();
    for node in cfg.nodes_sorted() {
        let mut stmts = Vec::new();
        flatten_blocks(&node.statements, &mut stmts);
        for stmt in stmts {
            let expr = match &stmt.kind {
                StatementKind::Expr(e) | StatementKind::Semi(e) => e,
                _ => continue,
            };
            let ExpressionKind::Assign { left, .. } = &expr.kind else {
                continue;
            };
            let Some(field_path) = resolve_self_field_path(left) else {
                continue;
            };
            let write_root = field_path.split('.').next().unwrap_or(&field_path);

            let dominating_guards = facts
                .iter()
                .filter(|(fact, anchor)| {
                    fact.root == write_root && dom.dominates_node(*anchor, node.id)
                })
                .map(|(fact, _)| fact.text.clone())
                .collect();

            writes.push(WriteFact {
                field_path,
                node_id: node.id,
                line: stmt.line_number,
                dominating_guards,
            });
        }
    }
    WriteSummary { writes }
}

/// Mirrors `guard_summary.rs::SummaryComputer` exactly — same cache,
/// same `in_progress` cycle guard, same `MAX_DEPTH` cutoff — generalized
/// from "proven signer params" to "proven self-rooted conditions, anchored
/// to the node that makes each one visible."
struct SelfGuardComputer<'a> {
    graph: &'a CallGraph,
    /// Facts exported by a function: anchored at nodes within *that
    /// function's own* CFG. Only consulted when propagating across a
    /// call boundary, where only the subset dominating every one of the
    /// callee's own exits is safe to inherit (filtered at use, not here).
    cache: HashMap<FunctionId, (ControlFlowGraph, Vec<(SelfGuardFact, usize)>)>,
    in_progress: HashSet<FunctionId>,
}

impl<'a> SelfGuardComputer<'a> {
    fn new(graph: &'a CallGraph) -> Self {
        Self {
            graph,
            cache: HashMap::new(),
            in_progress: HashSet::new(),
        }
    }

    /// Facts visible within `id`'s own body: local conditions, plus
    /// whatever's inherited (anchored at the call site) from further
    /// `self.<method>()` calls `id` makes, up to `MAX_DEPTH` hops. `info`
    /// is passed by the top-level caller (which already has it) so this
    /// doesn't need a redundant `call_graph.functions.get(id)` for depth 0.
    fn facts_in(
        &mut self,
        id: &str,
        info: &FunctionInfo,
    ) -> (ControlFlowGraph, Vec<(SelfGuardFact, usize)>) {
        self.compute(id, info, 0)
    }

    /// Facts `id` *guarantees* to a caller that calls it unconditionally:
    /// the subset of `facts_in`'s result whose anchor node dominates
    /// *every* one of `id`'s own ok-exits. Vacuously empty (not "all"),
    /// same convention `guard_summary.rs::compute` uses, when `id` has no
    /// provable Ok-exit at all.
    fn exported_facts(&mut self, id: &str, depth: usize) -> Vec<SelfGuardFact> {
        if depth >= MAX_DEPTH || self.in_progress.contains(id) {
            return Vec::new();
        }
        let Some(info) = self.graph.functions.get(id).cloned() else {
            return Vec::new();
        };
        let (cfg, facts) = self.compute(id, &info, depth);
        let exits = ok_exit_nodes(&cfg);
        if exits.is_empty() {
            return Vec::new();
        }
        let dom = DominanceChecker::new(&cfg);
        facts
            .into_iter()
            .filter(|(_, anchor)| exits.iter().all(|&exit| dom.dominates_node(*anchor, exit)))
            .map(|(fact, _)| fact)
            .collect()
    }

    fn compute(
        &mut self,
        id: &str,
        info: &FunctionInfo,
        depth: usize,
    ) -> (ControlFlowGraph, Vec<(SelfGuardFact, usize)>) {
        if let Some(cached) = self.cache.get(id) {
            return cached.clone();
        }
        let cfg = build_cfg(&info.stmts);
        if depth >= MAX_DEPTH || self.in_progress.contains(id) {
            // Conservative bail-out, matching `guard_summary.rs::compute`
            // exactly: not cached (a shallower path to the same function
            // still gets a fair shot), no facts claimed.
            return (cfg, Vec::new());
        }
        self.in_progress.insert(id.to_string());

        let mut facts = local_self_facts(&cfg);

        for call in self.graph.calls_from(id) {
            // Same impl_type only — a call to a *different* type's method
            // (already out of scope for shape (a)/(b) themselves) can't
            // meaningfully be "self" here either.
            let Some(callee_info) = self.graph.functions.get(&call.callee) else {
                continue;
            };
            if callee_info.impl_type != info.impl_type {
                continue;
            }
            let Some(call_node) = find_call_node(&cfg, call) else {
                continue;
            };
            let exported = self.exported_facts(&call.callee, depth + 1);
            for fact in exported {
                facts.push((fact, call_node));
            }
        }

        self.in_progress.remove(id);
        let result = (cfg, facts);
        self.cache.insert(id.to_string(), result.clone());
        result
    }
}

/// Finds every early-return-shaped condition in `cfg` (any edge tagged
/// `is_early_return` — the CFG builder's own shape for a `require!`/
/// `assert!` macro desugar or a hand-written `if cond { return Err(..) }`,
/// generalized here from "is this specific param a signer" to "which
/// `self.<root>` names does this condition mention at all") and anchors
/// each one at the sibling node reached only when the bail-out wasn't
/// taken.
fn local_self_facts(cfg: &ControlFlowGraph) -> Vec<(SelfGuardFact, usize)> {
    let mut facts = Vec::new();
    for edge in &cfg.edges {
        // `is_early_return` is the CFG builder's own tag for exactly this
        // shape (`require!`/`assert!`-macro desugar, or a hand-written
        // `if cond { return Err(..) }`) — use it directly rather than
        // re-derive "which side bails" from `is_terminating_branch`: for
        // an ordinary two-way branch with no loop, *neither* side ever
        // reaches back into the other, so comparing both directions
        // against each other (what an earlier version of this function
        // did) is always a tie and skips every edge. `is_early_return`
        // doesn't have that problem — it's set once, at construction,
        // from the actual source shape.
        if !edge.is_early_return {
            continue;
        }
        let Some(cond) = &edge.condition else {
            continue;
        };
        let Some(sibling) = cfg
            .edges
            .iter()
            .find(|e| e.from == edge.from && e.to != edge.to)
        else {
            continue;
        };
        // `cond` is the condition under which we take the bail-out edge
        // (`edge.to`) — negated already for a macro desugar, positive for
        // a hand-written `if`. Either way, reaching `sibling.to` means
        // `edge.to` wasn't taken, so whatever `cond` concerns is known at
        // `sibling.to` — the exact polarity doesn't matter here, since
        // only *which roots are mentioned* is extracted, never the
        // boolean value itself.
        let mut roots = HashSet::new();
        collect_self_roots(cond, &mut roots);
        if roots.is_empty() {
            continue;
        }
        let text = render_condition(cond);
        for root in roots {
            facts.push((
                SelfGuardFact {
                    root,
                    text: text.clone(),
                },
                sibling.to,
            ));
        }
    }
    facts
}

/// Every `self.<root>` name mentioned anywhere in `expr` — both sides of
/// `require_keys_eq!(self.a.x, self.b.y, ..)` yield `{"a", "b"}`, same as
/// a signer check `self.authority.is_signer` yields `{"authority"}`.
fn collect_self_roots(expr: &ExpressionNode, out: &mut HashSet<String>) {
    match &expr.kind {
        ExpressionKind::FieldAccess { object, .. } => {
            if let Some(root) = self_root_of(expr) {
                out.insert(root);
            } else {
                collect_self_roots(object, out);
            }
        }
        ExpressionKind::MethodCall {
            object, arguments, ..
        } => {
            collect_self_roots(object, out);
            for a in arguments {
                collect_self_roots(a, out);
            }
        }
        ExpressionKind::BinaryOp { lhs, rhs, .. } => {
            collect_self_roots(lhs, out);
            collect_self_roots(rhs, out);
        }
        ExpressionKind::Reference { expression, .. }
        | ExpressionKind::Dereference(expression)
        | ExpressionKind::Try(expression) => collect_self_roots(expression, out),
        _ => {}
    }
}

/// `self.<root>[.<more>]` -> `Some("<root>")`. Mirrors
/// `resolve_self_field_path` but stops at the first segment — a
/// comparison can go arbitrarily deep (`self.ticket_account.state_address`)
/// and still only names one root account.
fn self_root_of(expr: &ExpressionNode) -> Option<String> {
    let path = resolve_self_field_path(expr)?;
    path.split('.').next().map(|s| s.to_string())
}

fn render_condition(expr: &ExpressionNode) -> String {
    match &expr.kind {
        ExpressionKind::Identifier(n) => n.clone(),
        ExpressionKind::Literal(l) => l.clone(),
        ExpressionKind::FieldAccess { object, field } => {
            format!("{}.{}", render_condition(object), field)
        }
        ExpressionKind::MethodCall {
            object,
            method,
            arguments,
        } => {
            let args: Vec<String> = arguments.iter().map(render_condition).collect();
            format!(
                "{}.{}({})",
                render_condition(object),
                method,
                args.join(", ")
            )
        }
        ExpressionKind::BinaryOp { op, lhs, rhs } => {
            if op == "!" {
                format!("!({})", render_condition(lhs))
            } else {
                format!("{} {} {}", render_condition(lhs), op, render_condition(rhs))
            }
        }
        ExpressionKind::Reference { expression, .. } => {
            format!("&{}", render_condition(expression))
        }
        ExpressionKind::Dereference(i) => format!("*{}", render_condition(i)),
        ExpressionKind::Try(i) => format!("{}?", render_condition(i)),
        _ => "<expr>".to_string(),
    }
}

/// `self.<field>[.<more>]` -> `Some("<field>[.<more>]")`; anything whose
/// root isn't the bare identifier `self` -> `None`. No alias chasing here
/// — a method's own body can `let`-alias a field of itself same as a
/// handler can alias `ctx.accounts.x`, but that's additional precision a
/// later pass can add; this only needs to prove the direct case works.
fn resolve_self_field_path(expr: &ExpressionNode) -> Option<String> {
    let mut segments = Vec::new();
    let mut cur = expr;
    loop {
        match &cur.kind {
            ExpressionKind::FieldAccess { object, field } => {
                segments.push(field.clone());
                cur = object;
            }
            ExpressionKind::Identifier(name) if name == "self" => {
                segments.reverse();
                return if segments.is_empty() {
                    None
                } else {
                    Some(segments.join("."))
                };
            }
            ExpressionKind::Dereference(inner)
            | ExpressionKind::Reference {
                expression: inner, ..
            } => {
                cur = inner;
            }
            _ => return None,
        }
    }
}

fn flatten_blocks<'a>(stmts: &'a [StatementNode], out: &mut Vec<&'a StatementNode>) {
    for s in stmts {
        match &s.kind {
            StatementKind::Block(inner) => flatten_blocks(inner, out),
            _ => out.push(s),
        }
    }
}
