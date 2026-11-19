//! Per-entrypoint analysis: finds `require_auth`/`require_auth_for_args`
//! calls (guards), `storage().{instance,persistent,temporary}().set/remove`
//! and `.transfer(..)` calls (sinks), and reports a finding when a sink is
//! reachable, on some completing execution, through a path that avoids
//! every guard. Reuses `GuardFact`/`GuardTarget`/`DominanceChecker`/
//! `RuleDiagnostic`/`Witness` from the shared rule-output model; does not
//! reuse `CFGBuilder` (see `cfg_builder.rs` for why) or touch any existing
//! rule.

use super::cfg_builder::SorobanCfgBuilder;
use super::{HelperIndex, SorobanEntrypoint};
use crate::ast::{ExpressionKind, ExpressionNode, StatementKind, StatementNode};
use crate::cfg::{ControlFlowGraph, FactConfidence, GuardTarget, SSAVersionId, SymbolId};
use crate::rules::dominance::DominanceChecker;
use crate::rules::{FindingLocation, RuleDiagnostic, RuleSeverity, Witness, WitnessStep};
use std::collections::{HashMap, HashSet, VecDeque};

pub(crate) const RULE_ID: &str = "EPIC-SOROBAN-001";

#[derive(Clone, Copy, PartialEq, Eq)]
enum SinkKind {
    StorageSet,
    StorageRemove,
    Transfer,
}

impl SinkKind {
    fn label(self) -> &'static str {
        match self {
            SinkKind::StorageSet => "storage write (.set)",
            SinkKind::StorageRemove => "storage write (.remove)",
            SinkKind::Transfer => "token transfer (.transfer)",
        }
    }
}

struct Sink {
    node: usize,
    line: usize,
    kind: SinkKind,
}

struct AuthCall {
    node: usize,
    line: usize,
    /// Recorded per the review's point 5 (Account(sym) for params,
    /// Variable(ssa) for locals) -- not yet consumed by v0's bypass logic,
    /// which doesn't check *which* address was authorized, only that some
    /// require_auth call exists on the path. Kept for a v1 that does.
    #[allow(dead_code)]
    target: GuardTarget,
    address_text: String,
}

/// One hop's worth of resolution for a helper call site: whether calling it
/// is a guaranteed `require_auth`, confidently not one, or genuinely
/// unknown because it itself calls something we don't follow a second hop
/// into.
enum HelperAuthResult {
    AlwaysGuards,
    NotAGuard,
    Uncertain { reason: String },
}

pub(crate) fn analyze_entrypoint(
    ep: &SorobanEntrypoint,
    helper_index: &HelperIndex,
) -> Vec<RuleDiagnostic> {
    let symbol_table = build_symbol_table(ep);
    let helper_names = helper_index.names();

    let mut builder = SorobanCfgBuilder::new(helper_names.clone());
    let end = builder.compile(&ep.stmts, 0);
    if !builder.graph.exit_nodes.contains(&end) {
        builder.graph.exit_nodes.push(end);
    }
    let graph = &builder.graph;

    let (auth_calls, mut sinks) = scan_nodes(graph, &symbol_table);
    let mut confirmed_auth: HashSet<usize> = auth_calls.iter().map(|a| a.node).collect();
    let mut uncertain: HashSet<usize> = HashSet::new();
    let mut uncertain_reasons: HashMap<usize, String> = HashMap::new();

    for (node, name, line) in &builder.helper_call_sites {
        match helper_index.resolve(name) {
            None => {
                uncertain.insert(*node);
                uncertain_reasons.insert(
                    *node,
                    format!(
                        "call to `{name}` could not be uniquely resolved in this crate (not found, or ambiguous with another function of the same name) -- cannot confirm whether it authenticates"
                    ),
                );
            }
            Some(stmts) => {
                let report = analyze_helper(stmts, &helper_names);
                match report.result {
                    HelperAuthResult::AlwaysGuards => {
                        confirmed_auth.insert(*node);
                    }
                    HelperAuthResult::NotAGuard => {
                        // Confirmed not a guard -- contributes nothing, same
                        // as an ordinary call with no auth effect.
                    }
                    HelperAuthResult::Uncertain { reason } => {
                        uncertain.insert(*node);
                        uncertain_reasons.insert(*node, format!("`{name}`: {reason}"));
                    }
                }
                // The whole handler can be delegated to a one-hop helper,
                // not just the auth check -- confirmed against two real
                // scout-soroban fixtures (set-contract-storage-4,
                // unprotected-mapping-operation-2) where the entrypoint's
                // own body is just `utils::f(..)` and the actual storage
                // write lives inside `f`. A sink inside the helper that
                // isn't dominated by the helper's *own* auth calls is
                // exposed at the call site exactly as if it were written
                // there directly.
                for kind in report.exposed_sinks {
                    sinks.push(Sink {
                        node: *node,
                        line: *line,
                        kind,
                    });
                }
            }
        }
    }

    let normal_exits: Vec<usize> = graph
        .exit_nodes
        .iter()
        .copied()
        .filter(|n| !builder.abort_nodes.contains(n))
        .collect();

    let mut diagnostics = Vec::new();
    for sink in &sinks {
        if let Some(diag) = check_sink(
            ep,
            graph,
            sink,
            &auth_calls,
            &confirmed_auth,
            &uncertain,
            &uncertain_reasons,
            &normal_exits,
        ) {
            diagnostics.push(diag);
        }
    }
    diagnostics
}

#[allow(clippy::too_many_arguments)]
fn check_sink(
    ep: &SorobanEntrypoint,
    graph: &ControlFlowGraph,
    sink: &Sink,
    auth_calls: &[AuthCall],
    confirmed_auth: &HashSet<usize>,
    uncertain: &HashSet<usize>,
    uncertain_reasons: &HashMap<usize, String>,
    normal_exits: &[usize],
) -> Option<RuleDiagnostic> {
    // Does entry -> sink -> some normal exit exist avoiding confirmed auth
    // entirely? If not, every completing execution that reaches this sink
    // also passes through a confirmed require_auth somewhere -- safe,
    // because Soroban reverts the whole invocation (including any earlier
    // write) if that auth check fails.
    let entry_to_sink = find_bypassing_path_avoiding_set(graph, confirmed_auth, sink.node)?;
    let sink_to_exit = reach_any_avoiding(graph, confirmed_auth, sink.node, normal_exits)?;

    // A path avoiding confirmed auth exists. Does one still exist that
    // *also* avoids every uncertain (unresolved / 2nd-hop) call? If so,
    // it's a confirmed finding -- no guard of any kind, confirmed or not,
    // blocks it. If not, the only bypass routes all go through something
    // we can't vouch for either way: INCONCLUSIVE, not a guess.
    let avoid_all: HashSet<usize> = confirmed_auth.union(uncertain).copied().collect();
    let confirmed_bypass = find_bypassing_path_avoiding_set(graph, &avoid_all, sink.node)
        .filter(|_| reach_any_avoiding(graph, &avoid_all, sink.node, normal_exits).is_some());

    let (confidence, message_suffix, witness_path) = match confirmed_bypass {
        Some(path) => (
            FactConfidence::Asserted,
            String::new(),
            Some((path, sink_to_exit)),
        ),
        None => {
            // Find which uncertain node the entry->sink->exit route had to
            // pass through, to name it in the message.
            let blocking: Vec<&str> = entry_to_sink
                .iter()
                .chain(sink_to_exit.iter())
                .filter_map(|n| uncertain_reasons.get(n).map(|s| s.as_str()))
                .collect();
            let reason = blocking
                .first()
                .copied()
                .unwrap_or("a one-hop helper call's auth status could not be confirmed either way");
            (
                FactConfidence::Inconclusive,
                format!(" INCONCLUSIVE: {reason}."),
                None,
            )
        }
    };

    let nearest_auth = auth_calls.iter().min_by_key(|a| a.line.abs_diff(sink.line));
    let auth_desc = nearest_auth
        .map(|a| {
            format!(
                " (nearest `require_auth` in this function: `{}` at line {})",
                a.address_text, a.line
            )
        })
        .unwrap_or_default();

    let witness = witness_path.map(|(entry_path, exit_path)| {
        let mut steps: Vec<WitnessStep> = entry_path
            .iter()
            .map(|&n| WitnessStep {
                line: node_line(graph, n).unwrap_or(0),
                label: format!("node {n}"),
            })
            .collect();
        for &n in exit_path.iter().skip(1) {
            steps.push(WitnessStep {
                line: node_line(graph, n).unwrap_or(0),
                label: format!("node {n}"),
            });
        }
        Witness {
            check: None,
            path: steps,
        }
    });

    Some(RuleDiagnostic {
        rule_id: RULE_ID.to_string(),
        severity: RuleSeverity::Critical,
        message: format!(
            "{} in `{}` is reachable on a path that never calls `require_auth`/`require_auth_for_args`.{}{}",
            sink.kind.label(),
            ep.name,
            auth_desc,
            message_suffix
        ),
        location: FindingLocation {
            file: ep.file_path.clone(),
            line: sink.line,
            column: 0,
            node_id: sink.node,
            statement_index: None,
        },
        confidence,
        target_symbol: SymbolId(0),
        witness,
    })
}

fn node_line(graph: &ControlFlowGraph, node: usize) -> Option<usize> {
    graph
        .nodes
        .get(&node)
        .and_then(|n| n.statements.first())
        .map(|s| s.line_number)
}

/// One-hop helper check: does `require_auth`/`require_auth_for_args`
/// dominate *every* normal-return exit of this function body? If the body
/// itself makes a further same-crate call we don't resolve, and its own
/// direct auth coverage is incomplete, the answer is genuinely unknown
/// (that further call might complete the auth chain) -- `Uncertain`, not a
/// guess either way. No helper names are passed into the inner builder, so
/// this never follows a second hop.
struct HelperReport {
    result: HelperAuthResult,
    /// Sinks inside the helper's own body that aren't dominated by any of
    /// the helper's own auth calls -- exposed at whatever call site invokes
    /// it, same as if written there directly.
    exposed_sinks: Vec<SinkKind>,
}

fn analyze_helper(stmts: &[syn::Stmt], helper_names: &HashSet<String>) -> HelperReport {
    let symbol_table = build_symbol_table_from_stmts(stmts, &[]);
    // Passing the real helper-name set here (not an empty one) is what lets
    // `builder.helper_call_sites` below actually *detect* a further
    // same-crate call this function makes -- caught by fixture (i): with an
    // empty set, scan_helper_calls short-circuits immediately (see its own
    // early return) and `helper_call_sites` is always empty, so a helper
    // whose only auth lives one hop deeper always read as confidently
    // NotAGuard instead of Uncertain. The one-hop depth cap is enforced by
    // *not resolving* these further calls (no recursive analyze_helper
    // call below), not by hiding that they exist.
    let mut builder = SorobanCfgBuilder::new(helper_names.clone());
    let end = builder.compile(stmts, 0);
    if !builder.graph.exit_nodes.contains(&end) {
        builder.graph.exit_nodes.push(end);
    }
    let graph = &builder.graph;
    let (auth_calls, sinks) = scan_nodes(graph, &symbol_table);
    let auth_nodes: HashSet<usize> = auth_calls.iter().map(|a| a.node).collect();

    let normal_exits: Vec<usize> = graph
        .exit_nodes
        .iter()
        .copied()
        .filter(|n| !builder.abort_nodes.contains(n))
        .collect();

    if normal_exits.is_empty() {
        // Never completes normally -- vacuously not a guard, and nothing
        // meaningfully "exposes" a sink through a call that never returns.
        return HelperReport {
            result: HelperAuthResult::NotAGuard,
            exposed_sinks: Vec::new(),
        };
    }

    let dom = DominanceChecker::new(graph);
    let fully_covered = normal_exits
        .iter()
        .all(|&e| auth_nodes.iter().any(|&a| dom.dominates_node(a, e)));

    let result = if fully_covered {
        HelperAuthResult::AlwaysGuards
    } else if !builder.helper_call_sites.is_empty() {
        HelperAuthResult::Uncertain {
            reason: "its own auth coverage is incomplete and it calls another function one hop deeper, which was not followed".to_string(),
        }
    } else {
        HelperAuthResult::NotAGuard
    };

    let exposed_sinks = sinks
        .iter()
        .filter(|s| !auth_nodes.iter().any(|&a| dom.dominates_node(a, s.node)))
        .map(|s| s.kind)
        .collect();

    HelperReport {
        result,
        exposed_sinks,
    }
}

fn scan_nodes(
    graph: &ControlFlowGraph,
    symbol_table: &HashMap<String, (SymbolId, bool)>,
) -> (Vec<AuthCall>, Vec<Sink>) {
    let mut auth_calls = Vec::new();
    let mut sinks = Vec::new();

    let mut node_ids: Vec<&usize> = graph.nodes.keys().collect();
    node_ids.sort_unstable();

    // First pass: `let storage = env.storage().instance();` is the idiom
    // every CoinFabrik scout-soroban `set-contract-storage` fixture uses
    // (confirmed empirically, not assumed) -- the sink-detecting chain
    // walk below only follows method-call/field-access/reference chains,
    // so without tracking this specific alias, `storage.set(..)` on the
    // *local* would never be recognized as a storage sink at all. Not
    // general alias analysis -- just this one idiom, to the depth it was
    // observed.
    let mut storage_aliases: HashSet<String> = HashSet::new();
    for &node_id in &node_ids {
        let node = &graph.nodes[node_id];
        let mut stmts = Vec::new();
        flatten_blocks(&node.statements, &mut stmts);
        for stmt in stmts {
            if let StatementKind::Let {
                name, initializer, ..
            } = stmt
            {
                if chain_contains_method(initializer, "storage", &storage_aliases) {
                    storage_aliases.insert(name.clone());
                }
            }
        }
    }

    for &node_id in &node_ids {
        let node = &graph.nodes[node_id];
        let mut stmts = Vec::new();
        flatten_blocks(&node.statements, &mut stmts);
        for stmt in stmts {
            let expr = match stmt {
                StatementKind::Let { initializer, .. } => initializer,
                StatementKind::Expr(e) | StatementKind::Semi(e) => e,
                StatementKind::MacroCall { .. } | StatementKind::Block(_) => continue,
            };
            walk_expr_for_sites(
                expr,
                *node_id,
                stmt_line(node, expr),
                symbol_table,
                &storage_aliases,
                &mut auth_calls,
                &mut sinks,
            );
        }
    }
    (auth_calls, sinks)
}

fn stmt_line(node: &crate::cfg::CFGNode, _expr: &ExpressionNode) -> usize {
    node.statements.first().map(|s| s.line_number).unwrap_or(0)
}

#[allow(clippy::too_many_arguments)]
fn walk_expr_for_sites(
    expr: &ExpressionNode,
    node: usize,
    line: usize,
    symbol_table: &HashMap<String, (SymbolId, bool)>,
    storage_aliases: &HashSet<String>,
    auth_calls: &mut Vec<AuthCall>,
    sinks: &mut Vec<Sink>,
) {
    if let ExpressionKind::MethodCall {
        object,
        method,
        arguments,
    } = &expr.kind
    {
        if method == "require_auth" || method == "require_auth_for_args" {
            let (target, text) = resolve_address_target(object, symbol_table);
            auth_calls.push(AuthCall {
                node,
                line,
                target,
                address_text: text,
            });
        } else if method == "set" || method == "remove" {
            if chain_contains_method(object, "storage", storage_aliases) {
                let kind = if method == "set" {
                    SinkKind::StorageSet
                } else {
                    SinkKind::StorageRemove
                };
                sinks.push(Sink { node, line, kind });
            }
        } else if method == "transfer" {
            sinks.push(Sink {
                node,
                line,
                kind: SinkKind::Transfer,
            });
        }
        walk_expr_for_sites(
            object,
            node,
            line,
            symbol_table,
            storage_aliases,
            auth_calls,
            sinks,
        );
        for a in arguments {
            walk_expr_for_sites(
                a,
                node,
                line,
                symbol_table,
                storage_aliases,
                auth_calls,
                sinks,
            );
        }
        return;
    }
    match &expr.kind {
        ExpressionKind::FieldAccess { object, .. } => walk_expr_for_sites(
            object,
            node,
            line,
            symbol_table,
            storage_aliases,
            auth_calls,
            sinks,
        ),
        ExpressionKind::BinaryOp { lhs, rhs, .. } => {
            walk_expr_for_sites(
                lhs,
                node,
                line,
                symbol_table,
                storage_aliases,
                auth_calls,
                sinks,
            );
            walk_expr_for_sites(
                rhs,
                node,
                line,
                symbol_table,
                storage_aliases,
                auth_calls,
                sinks,
            );
        }
        ExpressionKind::Assign { left, right } => {
            walk_expr_for_sites(
                left,
                node,
                line,
                symbol_table,
                storage_aliases,
                auth_calls,
                sinks,
            );
            walk_expr_for_sites(
                right,
                node,
                line,
                symbol_table,
                storage_aliases,
                auth_calls,
                sinks,
            );
        }
        ExpressionKind::Reference { expression, .. }
        | ExpressionKind::Dereference(expression)
        | ExpressionKind::Try(expression) => walk_expr_for_sites(
            expression,
            node,
            line,
            symbol_table,
            storage_aliases,
            auth_calls,
            sinks,
        ),
        _ => {}
    }
}

fn chain_contains_method(expr: &ExpressionNode, target: &str, aliases: &HashSet<String>) -> bool {
    if let ExpressionKind::Identifier(name) = &expr.kind {
        if target == "storage" && aliases.contains(name) {
            return true;
        }
    }
    match &expr.kind {
        ExpressionKind::MethodCall { object, method, .. } => {
            method == target || chain_contains_method(object, target, aliases)
        }
        ExpressionKind::FieldAccess { object, .. }
        | ExpressionKind::Reference {
            expression: object, ..
        }
        | ExpressionKind::Dereference(object)
        | ExpressionKind::Try(object) => chain_contains_method(object, target, aliases),
        _ => false,
    }
}

fn flatten_blocks<'a>(stmts: &'a [StatementNode], out: &mut Vec<&'a StatementKind>) {
    for s in stmts {
        match &s.kind {
            StatementKind::Block(inner) => flatten_blocks(inner, out),
            kind => out.push(kind),
        }
    }
}

/// `Account(sym)` for a plain parameter name, `Variable(ssa)` for a locally
/// bound name (version 1 -- same "don't need full SSA for a declarative
/// fact" convention `cfg::guards::convert_syn_expr` already uses), or a
/// rendered-text fallback for anything else (a field access, a method
/// chain). Records the address either way, per the review's point 5.
fn resolve_address_target(
    expr: &ExpressionNode,
    symbol_table: &HashMap<String, (SymbolId, bool)>,
) -> (GuardTarget, String) {
    let text = render(expr);
    if let ExpressionKind::Identifier(name) = &expr.kind {
        if let Some(&(sym, is_param)) = symbol_table.get(name) {
            return if is_param {
                (GuardTarget::Account(sym), text)
            } else {
                (
                    GuardTarget::Variable(SSAVersionId {
                        symbol_id: sym,
                        version: 1,
                    }),
                    text,
                )
            };
        }
    }
    (GuardTarget::Literal(text.clone()), text)
}

fn render(expr: &ExpressionNode) -> String {
    match &expr.kind {
        ExpressionKind::Identifier(n) => n.clone(),
        ExpressionKind::Literal(l) => l.clone(),
        ExpressionKind::FieldAccess { object, field } => format!("{}.{}", render(object), field),
        ExpressionKind::MethodCall {
            object,
            method,
            arguments,
        } => {
            let args: Vec<String> = arguments.iter().map(render).collect();
            format!("{}.{}({})", render(object), method, args.join(", "))
        }
        ExpressionKind::Reference { expression, .. } => format!("&{}", render(expression)),
        ExpressionKind::Dereference(i) => format!("*{}", render(i)),
        ExpressionKind::Try(i) => format!("{}?", render(i)),
        _ => "<expr>".to_string(),
    }
}

/// `name -> (SymbolId, is_param)`. Params from the entrypoint signature get
/// a fresh id first; every `let`-bound local anywhere in the body
/// (including inside `if`/`match` arms) gets one too.
fn build_symbol_table(ep: &SorobanEntrypoint) -> HashMap<String, (SymbolId, bool)> {
    build_symbol_table_from_stmts(&ep.stmts, &ep.sig_params)
}

fn build_symbol_table_from_stmts(
    stmts: &[syn::Stmt],
    params: &[String],
) -> HashMap<String, (SymbolId, bool)> {
    let mut table = HashMap::new();
    let mut next_id = 1usize;
    for p in params {
        table.insert(p.clone(), (SymbolId(next_id), true));
        next_id += 1;
    }
    let mut locals = Vec::new();
    collect_lets(stmts, &mut locals);
    for name in locals {
        table.entry(name).or_insert_with(|| {
            let id = (SymbolId(next_id), false);
            next_id += 1;
            id
        });
    }
    table
}

fn collect_lets(stmts: &[syn::Stmt], out: &mut Vec<String>) {
    for stmt in stmts {
        if let syn::Stmt::Local(local) = stmt {
            if let syn::Pat::Ident(pi) = &local.pat {
                out.push(pi.ident.to_string());
            }
        }
        if let syn::Stmt::Expr(e, _) = stmt {
            collect_lets_in_expr(e, out);
        }
    }
}

fn collect_lets_in_expr(expr: &syn::Expr, out: &mut Vec<String>) {
    match expr {
        syn::Expr::If(i) => {
            collect_lets(&i.then_branch.stmts, out);
            if let Some((_, e)) = &i.else_branch {
                collect_lets_in_expr(e, out);
            }
        }
        syn::Expr::Block(b) => collect_lets(&b.block.stmts, out),
        syn::Expr::Match(m) => {
            for arm in &m.arms {
                if let syn::Expr::Block(b) = &*arm.body {
                    collect_lets(&b.block.stmts, out);
                }
            }
        }
        _ => {}
    }
}

/// Set-avoiding variant of `rules::dominance::find_bypassing_path` -- that
/// function is untouched; this is its own BFS, local to the Soroban
/// module, that avoids an entire *set* of nodes instead of one.
pub(crate) fn find_bypassing_path_avoiding_set(
    cfg: &ControlFlowGraph,
    avoid_nodes: &HashSet<usize>,
    target_node: usize,
) -> Option<Vec<usize>> {
    let entry = cfg.entry_node;
    if avoid_nodes.contains(&entry) {
        return None;
    }
    bfs(cfg, avoid_nodes, entry, |n| n == target_node)
}

/// Is any of `targets` reachable from `start`, avoiding `avoid_nodes`?
/// Returns the path if so (used for the sink -> normal-exit leg).
fn reach_any_avoiding(
    cfg: &ControlFlowGraph,
    avoid_nodes: &HashSet<usize>,
    start: usize,
    targets: &[usize],
) -> Option<Vec<usize>> {
    if avoid_nodes.contains(&start) {
        return None;
    }
    let target_set: HashSet<usize> = targets.iter().copied().collect();
    bfs(cfg, avoid_nodes, start, |n| target_set.contains(&n))
}

fn bfs(
    cfg: &ControlFlowGraph,
    avoid_nodes: &HashSet<usize>,
    start: usize,
    is_target: impl Fn(usize) -> bool,
) -> Option<Vec<usize>> {
    let mut came_from: HashMap<usize, usize> = HashMap::new();
    let mut visited: HashSet<usize> = HashSet::new();
    let mut queue: VecDeque<usize> = VecDeque::new();
    visited.insert(start);
    queue.push_back(start);

    while let Some(node) = queue.pop_front() {
        if is_target(node) {
            let mut path = vec![node];
            let mut cur = node;
            while let Some(&prev) = came_from.get(&cur) {
                path.push(prev);
                cur = prev;
            }
            path.reverse();
            return Some(path);
        }
        for edge in &cfg.edges {
            if edge.from == node && !avoid_nodes.contains(&edge.to) && visited.insert(edge.to) {
                came_from.insert(edge.to, node);
                queue.push_back(edge.to);
            }
        }
    }
    None
}
