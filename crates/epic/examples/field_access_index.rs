//! Cross-instruction account-field access index — a MEASUREMENT, not a rule.
//!
//! Builds, for every `Context<T>`-taking handler in a crate, the set of account
//! fields written and read, keyed by (account type, field name) so the same field
//! collapses across handlers. For each write it records which guards dominate it,
//! reusing the engine's own `GuardFact`s and `DominanceChecker`.
//!
//! Then runs one query: which (type, field) pairs are written in more than one
//! instruction where at least one write is guarded and at least one is not.
//!
//! Run: cargo run --release --example field_access_index -- <repo> [<repo> ...]

use epic::ast::{
    unpack_nested_generics, ExpressionKind, ExpressionNode, StatementKind, StatementNode,
};
use epic::cfg::guards::{FactExpression, GuardFact, GuardTarget, SolanaProperty};
use epic::types::{StructDef, TypeRef};
use epic::{for_each_analysis_context, AnalysisContext, DominanceChecker, SymbolId};
use std::collections::{BTreeMap, BTreeSet, HashMap};

// ─── index model ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct WriteSite {
    repo: String,
    instruction: String,
    file: String,
    line: usize,
    lhs: String,
    /// Dominating, authorization-relevant guards on the written account.
    guards: Vec<String>,
    /// `#[account(init, ..)]` on the written account — no prior state to check.
    is_init: bool,
    /// Some signer check dominates this write, but on a different account.
    foreign_signer: bool,
    /// Stage 3: set when this write was not found directly in the handler
    /// body, but inside a resolved `ctx.accounts.process(..)` /
    /// `<field>.update(..)` callee, translated back onto this account —
    /// e.g. `Some("Position::update()")`.
    via_call: Option<String>,
}

#[derive(Debug, Default)]
struct FieldEntry {
    writes: Vec<WriteSite>,
    reads: usize,
    read_in: BTreeSet<String>,
}

#[derive(Debug, Default)]
struct RepoStats {
    handlers: usize,
    handlers_with_struct: usize,
    writes: usize,
    reads: usize,
    unresolved_stmts: usize,
    loop_or_match_handlers: usize,
    /// Stage 3: writes credited through `ctx.accounts.process(..)` /
    /// `<field>.update(..)`, translated back onto the caller's namespace.
    /// Not included in `writes` above — reported separately so the direct
    /// vs. interprocedural contribution stays visible, not blended away.
    writes_via_call: usize,
}

type Key = (String, String, String); // (repo, account type, field)

// ─── expression helpers ─────────────────────────────────────────────────────

fn render(e: &ExpressionNode) -> String {
    match &e.kind {
        ExpressionKind::Identifier(n) => n.clone(),
        ExpressionKind::Literal(l) => l.clone(),
        ExpressionKind::FieldAccess { object, field } => format!("{}.{}", render(object), field),
        ExpressionKind::MethodCall {
            object,
            method,
            arguments,
        } => {
            let args: Vec<String> = arguments.iter().map(render).collect();
            match &object.kind {
                ExpressionKind::Unresolved => format!("{}({})", method, args.join(", ")),
                _ => format!("{}.{}({})", render(object), method, args.join(", ")),
            }
        }
        ExpressionKind::BinaryOp { op, lhs, rhs } => {
            if op == "!" {
                format!("!({})", render(lhs))
            } else {
                format!("{} {} {}", render(lhs), op, render(rhs))
            }
        }
        ExpressionKind::Reference {
            expression,
            is_mutable,
        } => {
            format!(
                "&{}{}",
                if *is_mutable { "mut " } else { "" },
                render(expression)
            )
        }
        ExpressionKind::Dereference(i) => format!("*{}", render(i)),
        ExpressionKind::Try(i) => format!("{}?", render(i)),
        ExpressionKind::Assign { left, right } => format!("{} = {}", render(left), render(right)),
        ExpressionKind::Unresolved => "<unresolved>".to_string(),
    }
}

/// Strips `&`, `&mut`, `*`, `?` and accessor method calls (`.load_mut()`, `.borrow_mut()`)
/// to reach the underlying place expression.
fn strip(e: &ExpressionNode) -> &ExpressionNode {
    match &e.kind {
        ExpressionKind::Reference { expression, .. } => strip(expression),
        ExpressionKind::Dereference(i) | ExpressionKind::Try(i) => strip(i),
        ExpressionKind::MethodCall { object, .. } => strip(object),
        _ => e,
    }
}

/// Flattens a place expression into its root plus the field path below it.
/// `ctx.accounts.bank.load_mut()?.fee` -> (["ctx","accounts","bank"], ["fee"]) shape,
/// returned as (root_segments, field_path) with the whole dotted chain in order.
fn flatten(e: &ExpressionNode) -> Vec<String> {
    let e = strip(e);
    match &e.kind {
        ExpressionKind::Identifier(n) => vec![n.clone()],
        ExpressionKind::FieldAccess { object, field } => {
            let mut v = flatten(object);
            v.push(field.clone());
            v
        }
        _ => Vec::new(),
    }
}

/// Collects every identifier and dotted path appearing anywhere in an expression.
fn names_in(e: &ExpressionNode, out: &mut BTreeSet<String>) {
    match &e.kind {
        ExpressionKind::Identifier(n) => {
            out.insert(n.clone());
        }
        ExpressionKind::FieldAccess { .. } => {
            for seg in flatten(e) {
                out.insert(seg);
            }
        }
        ExpressionKind::MethodCall {
            object, arguments, ..
        } => {
            names_in(object, out);
            for a in arguments {
                names_in(a, out);
            }
        }
        ExpressionKind::BinaryOp { lhs, rhs, .. } => {
            names_in(lhs, out);
            names_in(rhs, out);
        }
        ExpressionKind::Reference { expression, .. } => names_in(expression, out),
        ExpressionKind::Dereference(i) | ExpressionKind::Try(i) => names_in(i, out),
        ExpressionKind::Assign { left, right } => {
            names_in(left, out);
            names_in(right, out);
        }
        _ => {}
    }
}

// ─── per-instruction indexing ───────────────────────────────────────────────

struct Resolved {
    account: String,
    field: String,
}

struct Indexer<'a> {
    ctx: &'a AnalysisContext,
    dom: DominanceChecker,
    /// account field name -> unpacked account type (e.g. "bank" -> "Bank")
    field_types: HashMap<String, String>,
    /// account field name -> raw `#[account(..)]` attribute text
    attrs: HashMap<String, String>,
    /// local binding name -> account field name it aliases
    aliases: HashMap<String, String>,
    accounts: BTreeSet<String>,
}

impl<'a> Indexer<'a> {
    fn new(ctx: &'a AnalysisContext, accounts_struct: &StructDef) -> Self {
        let mut field_types = HashMap::new();
        let mut attrs = HashMap::new();
        let mut accounts = BTreeSet::new();
        for f in &accounts_struct.fields {
            accounts.insert(f.name.clone());
            let raw = match &f.type_ref {
                TypeRef::Custom(s) => s.clone(),
                TypeRef::Option(inner) => match inner.as_ref() {
                    TypeRef::Custom(s) => s.clone(),
                    other => format!("{:?}", other),
                },
                other => format!("{:?}", other),
            };
            field_types.insert(f.name.clone(), unpack_nested_generics(&raw));
            attrs.insert(f.name.clone(), f.attrs.join(" "));
        }
        let mut me = Self {
            ctx,
            dom: ctx.dominance(),
            field_types,
            attrs,
            aliases: HashMap::new(),
            accounts,
        };
        me.build_aliases();
        me
    }

    /// `let bank = &mut ctx.accounts.bank;` / `let b = ctx.accounts.bank.load_mut()?;`
    /// makes `bank` / `b` an alias for the `bank` account field.
    fn build_aliases(&mut self) {
        let mut found = Vec::new();
        let mut node_ids: Vec<&usize> = self.ctx.instruction_context.cfg.nodes.keys().collect();
        node_ids.sort();
        for nid in node_ids {
            let node = &self.ctx.instruction_context.cfg.nodes[nid];
            collect_lets(&node.statements, &mut found);
        }
        for (name, init) in found {
            if let Some(acc) = self.account_of_place(&flatten(&init), &HashMap::new()) {
                if acc.field.is_empty() {
                    self.aliases.insert(name, acc.account);
                }
            }
        }
    }

    /// Maps a flattened place path onto (account field, field name below it).
    fn account_of_place(
        &self,
        path: &[String],
        extra: &HashMap<String, String>,
    ) -> Option<Resolved> {
        let ctxv = &self.ctx.instruction_context.context_var_name;
        // ctx.accounts.<acc>[.<field>...]
        if path.len() >= 3
            && &path[0] == ctxv
            && path[1] == "accounts"
            && self.accounts.contains(&path[2])
        {
            return Some(Resolved {
                account: path[2].clone(),
                field: path.get(3).cloned().unwrap_or_default(),
            });
        }
        // <alias>[.<field>...] — a local binding that aliases an account
        if !path.is_empty() {
            let head = &path[0];
            let acc = self
                .aliases
                .get(head)
                .or_else(|| extra.get(head))
                .cloned()
                .or_else(|| {
                    if self.accounts.contains(head) {
                        Some(head.clone())
                    } else {
                        None
                    }
                })?;
            return Some(Resolved {
                account: acc,
                field: path.get(1).cloned().unwrap_or_default(),
            });
        }
        None
    }

    fn account_symbol(&self, name: &str) -> Option<SymbolId> {
        self.ctx.instruction_context.symbol_table.get(name).copied()
    }

    /// Authorization-relevant guard facts on `account` that dominate (node, stmt).
    ///
    /// Deliberately EXCLUDED, because they are present on nearly every field and
    /// are not authorization:
    ///   - `Owner { expected_owner: "program_id" }` — the implicit `Account<'info,T>`
    ///     ownership fact the type system already gives you.
    ///   - `KeyRelation { field: IsWritable }` — `mut`.
    fn fact_guards(&self, account: &str, node: usize, stmt: usize) -> (Vec<String>, bool, bool) {
        let sym = match self.account_symbol(account) {
            Some(s) => s,
            None => return (Vec::new(), false, false),
        };
        let mut guards = Vec::new();
        let mut is_init = false;
        let mut foreign_signer = false;

        for (fact, prov) in &self.ctx.instruction_context.guard_facts {
            let fnode = prov.node_id.unwrap_or(0);
            let dominates = self
                .dom
                .dominates(fnode, prov.statement_index, node, Some(stmt));
            if !dominates {
                continue;
            }
            let target = match fact {
                GuardFact::Signer(a) => a.symbol_id(),
                GuardFact::Owner { account: a, .. }
                | GuardFact::KeyRelation { account: a, .. }
                | GuardFact::PDA { account: a, .. }
                | GuardFact::Initialized { account: a, .. }
                | GuardFact::Resized { account: a, .. }
                | GuardFact::Deallocated { account: a, .. } => a.symbol_id(),
                GuardFact::Custom { .. } => None,
            };
            if let (GuardFact::Signer(_), Some(t)) = (fact, target) {
                if t != sym {
                    foreign_signer = true;
                }
            }
            if target != Some(sym) {
                continue;
            }
            match fact {
                GuardFact::Signer(_) => guards.push("signer".to_string()),
                GuardFact::KeyRelation {
                    field: SolanaProperty::Address,
                    target,
                    ..
                } => {
                    guards.push(format!("has_one/key == {}", target_name(target, self.ctx)));
                }
                GuardFact::KeyRelation { .. } => {} // IsWritable (`mut`) — not a guard
                GuardFact::Owner { expected_owner, .. } => {
                    if !matches!(expected_owner, FactExpression::Literal(l) if l == "program_id") {
                        guards.push(format!(
                            "owner = {}",
                            fact_expr_name(expected_owner, self.ctx)
                        ));
                    }
                }
                GuardFact::PDA { .. } => guards.push("seeds (PDA derivation)".to_string()),
                GuardFact::Initialized { .. } => is_init = true,
                _ => {}
            }
        }
        // Reclassification fix 1: `has_one` followed in both directions.
        // `#[account(has_one = liquidation_record)]` on `marginfi_account`
        // produces `KeyRelation{account: marginfi_account, target:
        // liquidation_record}` — read forwards above, that credits
        // `marginfi_account`. But it equally proves something about
        // `liquidation_record`: that the caller-supplied account is the one
        // `marginfi_account` already has on record, which is exactly the
        // kind of identity pinning `seeds=`/PDA derivation gets credit for
        // elsewhere. Measured gap: `LiquidationRecord.liquidation_receiver`
        // writes in `liquidate_start.rs`/`liquidate_end.rs` showed up as
        // the index's one *none*-guarded multi-instruction pair — every
        // write unguarded on both sides — entirely because of this missing
        // direction.
        for (fact, prov) in &self.ctx.instruction_context.guard_facts {
            if let GuardFact::KeyRelation {
                account: a,
                field: SolanaProperty::Address,
                target,
            } = fact
            {
                if target.symbol_id() != Some(sym) {
                    continue;
                }
                let fnode = prov.node_id.unwrap_or(0);
                if !self
                    .dom
                    .dominates(fnode, prov.statement_index, node, Some(stmt))
                {
                    continue;
                }
                guards.push(format!(
                    "has_one (reverse): {} has_one == this",
                    target_name(a, self.ctx)
                ));
            }
        }
        // `constraint = ..` is parsed by the attribute parser but never lowered to a
        // GuardFact, so read it off the raw attribute text.
        if let Some(a) = self.attrs.get(account) {
            if a.contains("constraint") {
                guards.push("constraint = .. (attr text)".to_string());
            }
        }
        (guards, is_init, foreign_signer)
    }

    /// Reclassification fix 3: attribute a value's own seed/signer
    /// constraint to the write that consumes it, not just to the account
    /// being written. `group.fee_state_cache.x = fee_state.x` in
    /// `propagate_fee_state.rs` writes to `group` (no constraint at all —
    /// "permissionless by design", per the comment) using a value read off
    /// `fee_state`, which IS PDA-constrained (`seeds =
    /// [FEE_STATE_SEED]`) — a singleton account only one real pubkey can
    /// ever satisfy. The write is only as trustworthy as that source, and
    /// the index measured this as fully unguarded because it only ever
    /// looked at the account being written, never where the assigned value
    /// came from.
    fn value_source_guards(
        &self,
        rhs: &ExpressionNode,
        write_account: &str,
        node: usize,
        stmt: usize,
    ) -> Vec<String> {
        let mut places = Vec::new();
        collect_places(rhs, &mut places);
        let mut sources: BTreeSet<String> = BTreeSet::new();
        for p in &places {
            let path = flatten(p);
            if let Some(r) = self.account_of_place(&path, &HashMap::new()) {
                if r.account != write_account {
                    sources.insert(r.account);
                }
            }
        }
        let mut out = Vec::new();
        for src in sources {
            let (guards, is_init, _) = self.fact_guards(&src, node, stmt);
            if !guards.is_empty() {
                out.push(format!("value from `{}` ({})", src, guards.join("; ")));
            } else if is_init {
                // An `init` source has no guard of its own to borrow — the
                // value it holds was only just set by this same handler.
            }
        }
        out
    }

    /// Branch conditions that provably hold at (node, stmt) and mention `account`.
    /// Catches `require!` / `require_keys_eq!` / `if a.key() != b { return Err }`,
    /// none of which become GuardFacts.
    fn condition_guards(&self, account: &str, node: usize) -> Vec<String> {
        let mut out = Vec::new();
        let aliases_of: BTreeSet<&String> = self
            .aliases
            .iter()
            .filter(|(_, v)| v.as_str() == account)
            .map(|(k, _)| k)
            .collect();

        for edge in &self.ctx.instruction_context.cfg.edges {
            let cond = match &edge.condition {
                Some(c) => c,
                None => continue,
            };
            // Positive branch taken, or a guard macro / early return that was not taken.
            let taken = self.dom.dominates_node(edge.to, node);
            let passed = edge.is_early_return
                && self.dom.dominates_node(edge.from, node)
                && !self.dom.dominates_node(edge.to, node);
            if !taken && !passed {
                continue;
            }
            let mut names = BTreeSet::new();
            names_in(cond, &mut names);
            let mentions = names.contains(account) || aliases_of.iter().any(|a| names.contains(*a));
            if !mentions {
                continue;
            }
            let text = render(cond);
            let label = if passed {
                format!("require/early-return: !({})", text)
            } else {
                format!("if-branch: {}", text)
            };
            if !out.contains(&label) {
                out.push(label);
            }
        }
        out
    }
}

fn target_name(t: &GuardTarget, ctx: &AnalysisContext) -> String {
    let sym = match t {
        GuardTarget::Literal(l) => return l.clone(),
        other => other.symbol_id(),
    };
    match sym {
        Some(s) => ctx
            .instruction_context
            .symbol_table
            .iter()
            .find(|(_, v)| **v == s)
            .map(|(k, _)| k.clone())
            .unwrap_or_else(|| format!("sym{}", s.0)),
        None => "?".to_string(),
    }
}

fn fact_expr_name(e: &FactExpression, ctx: &AnalysisContext) -> String {
    match e {
        FactExpression::Literal(l) => l.clone(),
        FactExpression::Target(t) => target_name(t, ctx),
        FactExpression::PropertyOf { target, property } => {
            format!("{}.{:?}", target_name(target, ctx), property)
        }
        other => format!("{:?}", other),
    }
}

fn collect_lets(stmts: &[StatementNode], out: &mut Vec<(String, ExpressionNode)>) {
    for s in stmts {
        match &s.kind {
            StatementKind::Let {
                name, initializer, ..
            } => out.push((name.clone(), initializer.clone())),
            StatementKind::Block(inner) => collect_lets(inner, out),
            _ => {}
        }
    }
}

// ─── walking statements ─────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn walk(
    stmts: &[StatementNode],
    top_stmt_idx: usize,
    node_id: usize,
    ix: &Indexer,
    call_graph: &epic::callgraph::CallGraph,
    repo: &str,
    index: &mut BTreeMap<Key, FieldEntry>,
    stats: &mut RepoStats,
) {
    for (i, stmt) in stmts.iter().enumerate() {
        let idx = if top_stmt_idx == usize::MAX {
            i
        } else {
            top_stmt_idx
        };
        match &stmt.kind {
            StatementKind::Block(inner) => {
                walk(inner, idx, node_id, ix, call_graph, repo, index, stats)
            }
            StatementKind::Let { initializer, .. } => {
                record_reads(initializer, stmt.line_number, ix, repo, index, stats);
                record_call_site_writes(
                    initializer,
                    stmt.line_number,
                    node_id,
                    idx,
                    ix,
                    call_graph,
                    repo,
                    index,
                    stats,
                );
            }
            StatementKind::Expr(e) | StatementKind::Semi(e) => {
                if let ExpressionKind::Unresolved = e.kind {
                    stats.unresolved_stmts += 1;
                }
                if let ExpressionKind::Assign { left, right } = &e.kind {
                    record_write(
                        left,
                        right,
                        stmt.line_number,
                        idx,
                        node_id,
                        ix,
                        repo,
                        index,
                        stats,
                    );
                    record_reads(right, stmt.line_number, ix, repo, index, stats);
                    record_call_site_writes(
                        right,
                        stmt.line_number,
                        node_id,
                        idx,
                        ix,
                        call_graph,
                        repo,
                        index,
                        stats,
                    );
                } else {
                    record_reads(e, stmt.line_number, ix, repo, index, stats);
                    record_call_site_writes(
                        e,
                        stmt.line_number,
                        node_id,
                        idx,
                        ix,
                        call_graph,
                        repo,
                        index,
                        stats,
                    );
                }
            }
            StatementKind::MacroCall { .. } => {}
        }
    }
}

/// Stage 3: field-namespace translation at the call boundary. Finds every
/// resolved shape (a)/(b) method call in `expr` (reusing stage 1's
/// `collect_method_calls` + `CallGraph::resolve_typed`), computes the
/// callee's write summary (stage 2), and translates each `self.<path>`
/// write back onto the *caller's* `(account, field)` namespace:
///   (a) `ctx.accounts.process(..)`  — `self.<x>[.<rest>]` -> the caller's
///       own account field `<x>`, written field `<rest>` (or the whole
///       account, if `self.<x>` itself was reassigned directly).
///   (b) `<account_field>.update(..)` — `self.<path>` -> the *same*
///       `<account_field>`, written field `<path>` as-is (the callee's
///       `self` *is* that one account's own state type).
/// Guards credited are the caller-side guards dominating the *call site*
/// (same `fact_guards`/`condition_guards` direct writes already use) — not
/// anything inside the callee, which generally has no account context to
/// guard against at all. A write whose shape doesn't resolve either way is
/// silently skipped, same convention as every other heuristic in this file.
#[allow(clippy::too_many_arguments)]
fn record_call_site_writes(
    expr: &ExpressionNode,
    line: usize,
    node_id: usize,
    stmt_idx: usize,
    ix: &Indexer,
    call_graph: &epic::callgraph::CallGraph,
    repo: &str,
    index: &mut BTreeMap<Key, FieldEntry>,
    stats: &mut RepoStats,
) {
    let mut calls = Vec::new();
    collect_method_calls(expr, &mut calls);

    for (receiver, method) in calls {
        let path = flatten(&receiver);

        // Shape (a): the receiver IS `ctx.accounts` itself.
        if path.len() == 2
            && path[0] == ix.ctx.instruction_context.context_var_name
            && path[1] == "accounts"
        {
            let struct_name = ix.ctx.instruction_context.context_struct_name.clone();
            let Some(id) = call_graph.resolve_typed(&struct_name, &method) else {
                continue;
            };
            let Some(info) = call_graph.get(id) else {
                continue;
            };
            let summary = epic::write_summary::compute_write_summary(info, call_graph);
            for w in &summary.writes {
                let Some((account, field)) = split_shape_a_path(ix, &w.field_path) else {
                    continue;
                };
                credit_translated_write(
                    &account,
                    &field,
                    &struct_name,
                    &method,
                    w.line,
                    line,
                    node_id,
                    stmt_idx,
                    ix,
                    repo,
                    index,
                    stats,
                    &w.dominating_guards,
                );
            }
            continue;
        }

        // Shape (b): the receiver resolves (directly, or through one local
        // alias) to a specific account field, with no further field below it.
        let Some(r) = ix.account_of_place(&path, &HashMap::new()) else {
            continue;
        };
        if !r.field.is_empty() {
            continue;
        }
        let Some(receiver_type) = ix.field_types.get(&r.account).cloned() else {
            continue;
        };
        let Some(id) = call_graph.resolve_typed(&receiver_type, &method) else {
            continue;
        };
        let Some(info) = call_graph.get(id) else {
            continue;
        };
        let summary = epic::write_summary::compute_write_summary(info, call_graph);
        for w in &summary.writes {
            credit_translated_write(
                &r.account,
                &w.field_path,
                &receiver_type,
                &method,
                w.line,
                line,
                node_id,
                stmt_idx,
                ix,
                repo,
                index,
                stats,
                &w.dominating_guards,
            );
        }
    }
}

/// Shape (a)'s translation: `self.<x>[.<rest>]`, where `<x>` must be a real
/// account field on the *caller's* `Accounts` struct — anything else (the
/// receiver struct having a field that isn't itself an account, which
/// doesn't occur for a `#[derive(Accounts)]` struct in practice) is
/// skipped rather than guessed at.
fn split_shape_a_path(ix: &Indexer, field_path: &str) -> Option<(String, String)> {
    let mut parts = field_path.splitn(2, '.');
    let first = parts.next()?.to_string();
    if !ix.accounts.contains(&first) {
        return None;
    }
    let field = parts.next().unwrap_or("");
    let field = if field.is_empty() {
        "(whole account)".to_string()
    } else {
        field.to_string()
    };
    Some((first, field))
}

#[allow(clippy::too_many_arguments)]
fn credit_translated_write(
    account: &str,
    field: &str,
    receiver_type: &str,
    method: &str,
    callee_line: usize,
    call_line: usize,
    call_node: usize,
    call_stmt: usize,
    ix: &Indexer,
    repo: &str,
    index: &mut BTreeMap<Key, FieldEntry>,
    stats: &mut RepoStats,
    callee_guards: &[String],
) {
    let ty = ix
        .field_types
        .get(account)
        .cloned()
        .unwrap_or_else(|| "?".to_string());
    let (mut guards, is_init, foreign_signer) = ix.fact_guards(account, call_node, call_stmt);
    guards.extend(ix.condition_guards(account, call_node));
    // Multi-hop: guard-worthy conditions `write_summary::compute_write_summary`
    // found dominating this write *inside the callee's own call chain*
    // (local to the callee, or inherited from a further `self.<method>()`
    // it calls, up to `guard_summary::MAX_DEPTH` hops) — distinct from the
    // caller-side guards above, which only look at the call site itself.
    guards.extend(callee_guards.iter().map(|g| format!("[multi-hop] {}", g)));

    stats.writes_via_call += 1;
    index
        .entry((repo.to_string(), ty, field.to_string()))
        .or_default()
        .writes
        .push(WriteSite {
            repo: repo.to_string(),
            instruction: ix.ctx.instruction_context.name.clone(),
            file: ix.ctx.instruction_context.file_path.clone(),
            line: call_line,
            lhs: format!(
                "{}.{}  (via {}::{}() body line {})",
                account, field, receiver_type, method, callee_line
            ),
            guards,
            is_init,
            foreign_signer,
            via_call: Some(format!("{}::{}()", receiver_type, method)),
        });
}

#[allow(clippy::too_many_arguments)]
fn record_write(
    left: &ExpressionNode,
    right: &ExpressionNode,
    line: usize,
    stmt_idx: usize,
    node_id: usize,
    ix: &Indexer,
    repo: &str,
    index: &mut BTreeMap<Key, FieldEntry>,
    stats: &mut RepoStats,
) {
    let path = flatten(left);
    let r = match ix.account_of_place(&path, &HashMap::new()) {
        Some(r) => r,
        None => return,
    };
    let field = if r.field.is_empty() {
        "(whole account)".to_string()
    } else {
        r.field.clone()
    };
    let ty = ix
        .field_types
        .get(&r.account)
        .cloned()
        .unwrap_or_else(|| "?".to_string());

    let (mut guards, is_init, foreign_signer) = ix.fact_guards(&r.account, node_id, stmt_idx);
    guards.extend(ix.condition_guards(&r.account, node_id));
    guards.extend(ix.value_source_guards(right, &r.account, node_id, stmt_idx));

    stats.writes += 1;
    index
        .entry((repo.to_string(), ty, field))
        .or_default()
        .writes
        .push(WriteSite {
            repo: repo.to_string(),
            instruction: ix.ctx.instruction_context.name.clone(),
            file: ix.ctx.instruction_context.file_path.clone(),
            line,
            lhs: render(left),
            guards,
            is_init,
            foreign_signer,
            via_call: None,
        });
}

fn record_reads(
    e: &ExpressionNode,
    _line: usize,
    ix: &Indexer,
    repo: &str,
    index: &mut BTreeMap<Key, FieldEntry>,
    stats: &mut RepoStats,
) {
    let mut places = Vec::new();
    collect_places(e, &mut places);
    for p in places {
        let path = flatten(&p);
        if let Some(r) = ix.account_of_place(&path, &HashMap::new()) {
            if r.field.is_empty() {
                continue;
            }
            let ty = ix
                .field_types
                .get(&r.account)
                .cloned()
                .unwrap_or_else(|| "?".to_string());
            stats.reads += 1;
            let entry = index.entry((repo.to_string(), ty, r.field)).or_default();
            entry.reads += 1;
            entry
                .read_in
                .insert(ix.ctx.instruction_context.name.clone());
        }
    }
}

fn collect_places(e: &ExpressionNode, out: &mut Vec<ExpressionNode>) {
    match &e.kind {
        ExpressionKind::FieldAccess { .. } => out.push(e.clone()),
        ExpressionKind::MethodCall {
            object, arguments, ..
        } => {
            collect_places(object, out);
            for a in arguments {
                collect_places(a, out);
            }
        }
        ExpressionKind::BinaryOp { lhs, rhs, .. } => {
            collect_places(lhs, out);
            collect_places(rhs, out);
        }
        ExpressionKind::Reference { expression, .. } => collect_places(expression, out),
        ExpressionKind::Dereference(i) | ExpressionKind::Try(i) => collect_places(i, out),
        ExpressionKind::Assign { left, right } => {
            collect_places(left, out);
            collect_places(right, out);
        }
        _ => {}
    }
}

// ─── main ───────────────────────────────────────────────────────────────────

/// Smallest check that fails if write detection or the dominance wiring breaks.
///
/// The two `dominance-*` fixtures differ only in whether the signer `require!`
/// is unconditional. Both write `vault.balance`; the guard is on `authority`,
/// a *different* account, so in both cases the write itself is unguarded — but
/// only in `dominance-safe` does that signer check dominate the write.
fn selftest() -> anyhow::Result<()> {
    for (fixture, expect_dominating_signer) in
        [("dominance-safe", true), ("dominance-bypass", false)]
    {
        let path = format!("crates/epic/tests/fixtures/{}", fixture);
        let mut index: BTreeMap<Key, FieldEntry> = BTreeMap::new();
        let mut stats = RepoStats::default();
        let call_graph = epic::callgraph::build_call_graph(&path);
        for_each_analysis_context(&path, |ctx| {
            let registry = &ctx.ast_graph.registry;
            let sd = match epic::find_struct_for_context(
                registry,
                &ctx.instruction_context.context_struct_name,
                &ctx.instruction_context.file_path,
            ) {
                Some((_, sd)) => sd.clone(),
                None => return,
            };
            let ix = Indexer::new(ctx, &sd);
            let mut ids: Vec<usize> = ctx.instruction_context.cfg.nodes.keys().copied().collect();
            ids.sort();
            for nid in ids {
                let node = &ctx.instruction_context.cfg.nodes[&nid];
                walk(
                    &node.statements,
                    usize::MAX,
                    nid,
                    &ix,
                    &call_graph,
                    fixture,
                    &mut index,
                    &mut stats,
                );
            }
        })?;

        let key = (
            fixture.to_string(),
            "VaultAccount".to_string(),
            "balance".to_string(),
        );
        let e = index
            .get(&key)
            .unwrap_or_else(|| panic!("{}: no write indexed for VaultAccount.balance", fixture));
        assert_eq!(
            e.writes.len(),
            1,
            "{}: expected exactly 1 write site",
            fixture
        );
        let w = &e.writes[0];
        assert!(
            w.guards.is_empty(),
            "{}: guard is on `authority`, not on the written `vault` — got {:?}",
            fixture,
            w.guards
        );
        assert_eq!(
            w.foreign_signer, expect_dominating_signer,
            "{}: dominating-signer-on-another-account mismatch",
            fixture
        );
        println!(
            "selftest {}: ok (1 write, unguarded, foreign_signer={})",
            fixture, w.foreign_signer
        );
    }
    println!("selftest: all ok");
    Ok(())
}

/// Stage 1 measurement: for every method call in every instruction handler,
/// can the new `(receiver_type, method_name)` path (`CallGraph::resolve_typed`)
/// resolve it, where bare-name resolution (`by_name`, ambiguous across
/// every `process`/`update` in the crate) could not?
///
/// Two receiver shapes, matching the scoped plan exactly:
///   (a) `ctx.accounts.process(..)`      — receiver_type = the handler's own `Context<T>` struct
///   (b) `<account_field>.update(..)`    — receiver_type = that field's own declared account type
/// possibly through one local alias (`let position = &mut ctx.accounts.position;`).
/// Anything else (a call on a non-account local, a free function, a call
/// already resolvable today) isn't attempted — not in scope, not a failure.
fn resolve_probe(repos: &[String]) -> anyhow::Result<()> {
    println!("# Stage 1: typed method-call resolution probe\n");
    println!(
        "{:<18} {:>10} {:>10} {:>10} {:>8} {:>10}",
        "repo", "shape(a)", "resolved", "shape(b)", "resolved", "handlers"
    );

    for repo_path in repos {
        let repo = std::path::Path::new(repo_path)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| repo_path.clone());
        let call_graph = epic::callgraph::build_call_graph(repo_path);

        let (mut a_attempted, mut a_resolved) = (0usize, 0usize);
        let (mut b_attempted, mut b_resolved) = (0usize, 0usize);
        let mut handlers = 0usize;
        let mut examples: Vec<String> = Vec::new();
        let mut misses: Vec<String> = Vec::new();

        for_each_analysis_context(repo_path, |ctx| {
            handlers += 1;
            let registry = &ctx.ast_graph.registry;
            let sd = match epic::find_struct_for_context(
                registry,
                &ctx.instruction_context.context_struct_name,
                &ctx.instruction_context.file_path,
            ) {
                Some((_, sd)) => sd.clone(),
                None => return,
            };
            let ix = Indexer::new(ctx, &sd);
            let struct_name = &ctx.instruction_context.context_struct_name;

            let mut calls = Vec::new();
            for node in ctx.instruction_context.cfg.nodes_sorted() {
                let mut stmts = Vec::new();
                flatten_blocks(&node.statements, &mut stmts);
                for stmt in &stmts {
                    let expr = match &stmt.kind {
                        StatementKind::Let { initializer, .. } => initializer,
                        StatementKind::Expr(e) | StatementKind::Semi(e) => e,
                        _ => continue,
                    };
                    collect_method_calls(expr, &mut calls);
                }
            }

            for (receiver, method) in calls {
                let path = flatten(&receiver);
                // Shape (a): the receiver IS `ctx.accounts` itself.
                if path.len() == 2
                    && path[0] == ctx.instruction_context.context_var_name
                    && path[1] == "accounts"
                {
                    a_attempted += 1;
                    if call_graph.resolve_typed(struct_name, &method).is_some() {
                        a_resolved += 1;
                        if examples.len() < 3 {
                            examples.push(format!(
                                "  (a) ctx.accounts.{}() in {} -> {}::{}",
                                method, ctx.instruction_context.name, struct_name, method
                            ));
                        }
                    }
                    continue;
                }
                // Shape (b): the receiver resolves (directly, or through
                // one local alias) to a specific account field.
                if let Some(r) = ix.account_of_place(&path, &HashMap::new()) {
                    if r.field.is_empty() {
                        if let Some(receiver_type) = ix.field_types.get(&r.account) {
                            b_attempted += 1;
                            match call_graph.resolve_typed(receiver_type, &method) {
                                Some(_) => {
                                    b_resolved += 1;
                                    if examples.len() < 6 {
                                        examples.push(format!(
                                            "  (b) {}.{}() in {} -> {}::{}",
                                            r.account,
                                            method,
                                            ctx.instruction_context.name,
                                            receiver_type,
                                            method
                                        ));
                                    }
                                }
                                None => {
                                    if misses.len() < 8 {
                                        misses.push(format!("{}::{}", receiver_type, method));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        })?;

        println!(
            "{:<18} {:>10} {:>10} {:>10} {:>8} {:>10}",
            repo, a_attempted, a_resolved, b_attempted, b_resolved, handlers
        );
        for ex in &examples {
            println!("{}", ex);
        }
        if !misses.is_empty() {
            println!("  unresolved shape(b) sample: {}", misses.join(", "));
        }
    }
    Ok(())
}

/// Finds every `ExpressionKind::MethodCall { object, method, .. }` node
/// anywhere in `expr` (receiver, arguments, nested chains — `a.b().c()`
/// yields both `a.b()` and `(a.b()).c()`), returning `(receiver, method
/// name)` pairs. Deliberately ignores `MethodCall::arguments` for the
/// recursion target itself (a call used only as an argument is still
/// walked, just not treated differently from one used as a statement).
fn flatten_blocks<'a>(stmts: &'a [StatementNode], out: &mut Vec<&'a StatementNode>) {
    for s in stmts {
        match &s.kind {
            StatementKind::Block(inner) => flatten_blocks(inner, out),
            _ => out.push(s),
        }
    }
}

fn collect_method_calls(expr: &ExpressionNode, out: &mut Vec<(ExpressionNode, String)>) {
    match &expr.kind {
        ExpressionKind::MethodCall {
            object,
            method,
            arguments,
        } => {
            out.push(((**object).clone(), method.clone()));
            collect_method_calls(object, out);
            for a in arguments {
                collect_method_calls(a, out);
            }
        }
        ExpressionKind::FieldAccess { object, .. } => collect_method_calls(object, out),
        ExpressionKind::BinaryOp { lhs, rhs, .. } => {
            collect_method_calls(lhs, out);
            collect_method_calls(rhs, out);
        }
        ExpressionKind::Reference { expression, .. } => collect_method_calls(expression, out),
        ExpressionKind::Dereference(i) | ExpressionKind::Try(i) => collect_method_calls(i, out),
        ExpressionKind::Assign { left, right } => {
            collect_method_calls(left, out);
            collect_method_calls(right, out);
        }
        _ => {}
    }
}

fn main() -> anyhow::Result<()> {
    let repos: Vec<String> = std::env::args().skip(1).collect();
    if repos.first().map(|s| s.as_str()) == Some("--selftest") {
        return selftest();
    }
    if repos.first().map(|s| s.as_str()) == Some("--resolve-probe") {
        return resolve_probe(&repos[1..]);
    }
    if repos.is_empty() {
        eprintln!("usage: field_access_index <repo-path> [<repo-path> ...]");
        std::process::exit(2);
    }

    let mut index: BTreeMap<Key, FieldEntry> = BTreeMap::new();
    let mut per_repo: BTreeMap<String, RepoStats> = BTreeMap::new();

    for repo_path in &repos {
        let repo = std::path::Path::new(repo_path)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| repo_path.clone());
        let stats = per_repo.entry(repo.clone()).or_default();
        let call_graph = epic::callgraph::build_call_graph(repo_path);

        for_each_analysis_context(repo_path, |ctx| {
            stats.handlers += 1;
            let registry = &ctx.ast_graph.registry;
            let sd = match epic::find_struct_for_context(
                registry,
                &ctx.instruction_context.context_struct_name,
                &ctx.instruction_context.file_path,
            ) {
                Some((_, sd)) => sd.clone(),
                None => return,
            };
            stats.handlers_with_struct += 1;
            if !ctx.instruction_context.cfg.boundary_warnings.is_empty() {
                stats.loop_or_match_handlers += 1;
            }

            let ix = Indexer::new(ctx, &sd);
            let mut node_ids: Vec<usize> =
                ctx.instruction_context.cfg.nodes.keys().copied().collect();
            node_ids.sort();
            for nid in node_ids {
                let node = &ctx.instruction_context.cfg.nodes[&nid];
                walk(
                    &node.statements,
                    usize::MAX,
                    nid,
                    &ix,
                    &call_graph,
                    &repo,
                    &mut index,
                    stats,
                );
            }
        })?;
    }

    report(&index, &per_repo);
    Ok(())
}

fn guarded(w: &WriteSite) -> bool {
    !w.guards.is_empty()
}

fn source_line(file: &str, line: usize) -> String {
    std::fs::read_to_string(file)
        .ok()
        .and_then(|s| {
            s.lines()
                .nth(line.saturating_sub(1))
                .map(|l| l.trim().to_string())
        })
        .unwrap_or_else(|| "<source unavailable>".to_string())
}

fn report(index: &BTreeMap<Key, FieldEntry>, per_repo: &BTreeMap<String, RepoStats>) {
    println!("# Cross-instruction account-field access index\n");

    println!("## Coverage: is the index seeing the code?\n");
    println!(
        "{:<18} {:>9} {:>9} {:>8} {:>10} {:>8} {:>7} {:>11} {:>12}",
        "repo",
        "handlers",
        "w/struct",
        "writes",
        "writes(call)",
        "reads",
        "pairs",
        "unresolved",
        "loop/match"
    );
    for (repo, s) in per_repo {
        let pairs = index.keys().filter(|(r, _, _)| r == repo).count();
        println!(
            "{:<18} {:>9} {:>9} {:>8} {:>10} {:>8} {:>7} {:>11} {:>12}",
            repo,
            s.handlers,
            s.handlers_with_struct,
            s.writes,
            s.writes_via_call,
            s.reads,
            pairs,
            s.unresolved_stmts,
            s.loop_or_match_handlers
        );
    }
    let total_pairs = index.len();
    let total_writes: usize = index.values().map(|e| e.writes.len()).sum();
    let total_writes_direct: usize = index
        .values()
        .flat_map(|e| &e.writes)
        .filter(|w| w.via_call.is_none())
        .count();
    let total_writes_via_call: usize = total_writes - total_writes_direct;
    println!(
        "\ntotal (type, field) pairs: {}   total write sites: {} ({} direct + {} via resolved call)",
        total_pairs, total_writes, total_writes_direct, total_writes_via_call
    );

    // ── the query ──
    let mut asym: Vec<(&Key, &FieldEntry)> = index
        .iter()
        .filter(|(_, e)| {
            let ins: BTreeSet<&String> = e.writes.iter().map(|w| &w.instruction).collect();
            ins.len() > 1 && e.writes.iter().any(guarded) && e.writes.iter().any(|w| !guarded(w))
        })
        .collect();
    asym.sort_by_key(|(_, e)| {
        let unguarded = e.writes.iter().filter(|w| !guarded(w)).count();
        (
            std::cmp::Reverse(unguarded),
            std::cmp::Reverse(e.writes.len()),
        )
    });

    println!("\n## Query result\n");
    println!(
        "(type, field) pairs written in >1 instruction with >=1 guarded and >=1 unguarded write: {}",
        asym.len()
    );

    // Context: how the whole population splits.
    let multi: Vec<&FieldEntry> = index
        .values()
        .filter(|e| {
            e.writes
                .iter()
                .map(|w| &w.instruction)
                .collect::<BTreeSet<_>>()
                .len()
                > 1
        })
        .collect();
    let all_guarded = multi
        .iter()
        .filter(|e| e.writes.iter().all(guarded))
        .count();
    let none_guarded = multi
        .iter()
        .filter(|e| e.writes.iter().all(|w| !guarded(w)))
        .count();
    println!(
        "   of {} pairs written in >1 instruction: {} all-guarded, {} none-guarded, {} asymmetric",
        multi.len(),
        all_guarded,
        none_guarded,
        asym.len()
    );
    println!(
        "   ({} of {} pairs total are written in exactly 1 instruction; {} are read-only)",
        index
            .values()
            .filter(|e| {
                let n = e
                    .writes
                    .iter()
                    .map(|w| &w.instruction)
                    .collect::<BTreeSet<_>>()
                    .len();
                n == 1
            })
            .count(),
        index.len(),
        index.values().filter(|e| e.writes.is_empty()).count()
    );
    println!("\n   multi-instruction pairs with NO guard on any write:");
    for ((repo, ty, field), e) in index.iter().filter(|(_, e)| {
        e.writes
            .iter()
            .map(|w| &w.instruction)
            .collect::<BTreeSet<_>>()
            .len()
            > 1
            && e.writes.iter().all(|w| !guarded(w))
    }) {
        println!(
            "     {}::{}.{}  ({} writes)",
            repo,
            ty,
            field,
            e.writes.len()
        );
    }

    println!("\n## Top {} asymmetric fields\n", asym.len().min(10));
    for (rank, ((repo, ty, field), e)) in asym.iter().take(10).enumerate() {
        println!("### {}. {}::{}.{}", rank + 1, repo, ty, field);
        println!(
            "    reads: {} across {} instructions | writes: {} ({} guarded, {} unguarded)",
            e.reads,
            e.read_in.len(),
            e.writes.len(),
            e.writes.iter().filter(|w| guarded(w)).count(),
            e.writes.iter().filter(|w| !guarded(w)).count()
        );
        println!("\n    GUARDED writes:");
        for w in e.writes.iter().filter(|w| guarded(w)) {
            println!("      {}:{}  [{}]", short(&w.file), w.line, w.instruction);
            match &w.via_call {
                Some(_) => println!("        {}", w.lhs),
                None => println!("        {}", source_line(&w.file, w.line)),
            }
            for g in &w.guards {
                println!("          guard: {}", g);
            }
        }
        println!("\n    UNGUARDED writes:");
        for w in e.writes.iter().filter(|w| !guarded(w)) {
            println!("      {}:{}  [{}]", short(&w.file), w.line, w.instruction);
            match &w.via_call {
                Some(_) => println!("        {}", w.lhs),
                None => println!("        {}", source_line(&w.file, w.line)),
            }
            let mut notes = Vec::new();
            if w.is_init {
                notes.push("account is #[account(init, ..)] — no prior state".to_string());
            }
            if w.foreign_signer {
                notes.push("a signer check dominates, but on a different account".to_string());
            }
            if let Some(via) = &w.via_call {
                notes.push(format!("stage-3 translated write, via {}", via));
            }
            if !notes.is_empty() {
                println!("          note: {}", notes.join("; "));
            }
            let _ = &w.repo;
        }
        println!();
    }

    // Full list, one line each, so nothing is hidden behind the top 10.
    if asym.len() > 10 {
        println!("## Remaining asymmetric fields (one line each)\n");
        for ((repo, ty, field), e) in asym.iter().skip(10) {
            let g = e.writes.iter().filter(|w| guarded(w)).count();
            let u = e.writes.len() - g;
            println!(
                "    {}::{}.{}  ({} guarded / {} unguarded)",
                repo, ty, field, g, u
            );
        }
    }
}

fn short(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() > 3 {
        parts[parts.len() - 3..].join("/")
    } else {
        path.to_string()
    }
}
