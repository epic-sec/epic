//! Stage 2 of interprocedural guard analysis: guard summaries.
//!
//! Not wired into any rule or caller CFG yet — this module only answers,
//! for a given function, "which of its own parameters are guaranteed to
//! have passed a signer check on every path that returns Ok?" Wiring that
//! answer into a caller's CFG as a guard node is a separate, later step.
//!
//! Conservative by construction throughout: anything the analysis can't
//! *prove* — an unresolved inner call, a depth cutoff, recursion, a
//! function with no provable Ok-exit at all — comes out as "no guarantee,"
//! never "probably fine." A summary that over-claims turns into a
//! suppressed finding, and those are invisible; under-claiming just leaves
//! a function looking exactly as unanalyzed as it does today.

use crate::callgraph::{CallGraph, CallSite, FunctionId};
use crate::cfg::guards::{extract_signer_check_from_ir_expr, is_terminating_branch};
use crate::cfg::{CFGBuilder, ControlFlowGraph};
use crate::rules::DominanceChecker;
use std::collections::{HashMap, HashSet};

/// How many call-graph hops to chase before conservatively giving up.
pub const MAX_DEPTH: usize = 3;

/// The parameter *names* (not positions — names are what a call site's
/// argument-to-parameter mapping is keyed on) proven to carry a signer
/// check dominating every Ok-returning path through the function.
pub type GuardSummary = HashSet<String>;

/// Builds a CFG for an arbitrary function body, not just an instruction
/// handler's — the same builder, just pointed at a helper's statements.
fn build_cfg(stmts: &[syn::Stmt]) -> ControlFlowGraph {
    let mut builder = CFGBuilder::new();
    let _ = builder.compile_statements(stmts, 0);
    builder.graph
}

/// The exits a summary must dominate: every exit node NOT reached solely
/// via an early-return edge (the require!/assert!/`?` desugar's bail-out
/// path, which the CFG builder already tags `is_early_return: true`).
///
/// A hand-written `if cond { return Err(..) }` that doesn't go through that
/// desugar is NOT recognized as an Err-path here — it still gets counted as
/// an exit the check must dominate. For a first version that's the
/// conservative direction to be wrong in: such a function may look less
/// guaranteed than it actually is, never more.
fn ok_exit_nodes(cfg: &ControlFlowGraph) -> Vec<usize> {
    let early_return_targets: HashSet<usize> = cfg
        .edges
        .iter()
        .filter(|e| e.is_early_return)
        .map(|e| e.to)
        .collect();
    cfg.exit_nodes
        .iter()
        .copied()
        .filter(|n| !early_return_targets.contains(n))
        .collect()
}

/// Finds every signer-check branch in `cfg`, mapping the checked parameter
/// name to the node where "checked and passed" is established. Mirrors
/// guards.rs's own is_signer fact-anchoring exactly, minus the
/// `ctx.accounts.` symbol-table lookup — a helper function has no accounts
/// struct, only bare parameter names, and
/// `extract_signer_check_from_ir_expr` already falls back to the bare
/// identifier when there's no `ctx.accounts.` prefix to strip.
fn direct_signer_checks(cfg: &ControlFlowGraph) -> HashMap<String, usize> {
    let mut result = HashMap::new();
    for edge in &cfg.edges {
        let Some(cond) = &edge.ir_condition else {
            continue;
        };
        let Some((param_name, expects_signer)) = extract_signer_check_from_ir_expr(cond) else {
            continue;
        };
        let Some(sibling_to) = cfg
            .edges
            .iter()
            .find(|e| e.from == edge.from && e.to != edge.to)
            .map(|e| e.to)
        else {
            continue;
        };
        if expects_signer {
            if is_terminating_branch(cfg, sibling_to, edge.to) {
                result.entry(param_name).or_insert(edge.to);
            }
        } else if is_terminating_branch(cfg, edge.to, sibling_to) {
            result.entry(param_name).or_insert(sibling_to);
        }
    }
    result
}

/// A call site's argument, when it's a bare identifier (possibly behind a
/// `&`/`*`) matching one of the caller's own parameter names — the only
/// shape a guarantee is propagated through. Anything else (a field access,
/// a computed expression, a literal) is left unresolved rather than
/// guessed: propagating a callee's guarantee onto the wrong caller
/// parameter would be exactly the over-claim this module exists to avoid.
fn bare_identifier(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::Path(p) => p.path.get_ident().map(|i| i.to_string()),
        syn::Expr::Reference(r) => bare_identifier(&r.expr),
        syn::Expr::Paren(p) => bare_identifier(&p.expr),
        syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => bare_identifier(&u.expr),
        _ => None,
    }
}

/// Finds the CFG node containing the statement a call site came from, by
/// line number. Good enough for a first version: `CallSite` doesn't carry a
/// direct statement/node backreference from stage 1, and a call's own
/// source line is rarely shared with an unrelated statement in the same
/// function.
fn find_call_node(cfg: &ControlFlowGraph, call: &CallSite) -> Option<usize> {
    let mut node_ids: Vec<usize> = cfg.nodes.keys().copied().collect();
    node_ids.sort_unstable();
    for node_id in node_ids {
        let node = &cfg.nodes[&node_id];
        if node.statements.iter().any(|s| s.line_number == call.line) {
            return Some(node_id);
        }
    }
    None
}

pub struct SummaryComputer<'a> {
    graph: &'a CallGraph,
    cache: HashMap<FunctionId, GuardSummary>,
    in_progress: HashSet<FunctionId>,
}

impl<'a> SummaryComputer<'a> {
    pub fn new(graph: &'a CallGraph) -> Self {
        Self {
            graph,
            cache: HashMap::new(),
            in_progress: HashSet::new(),
        }
    }

    /// Computes (and caches) the guard summary for a function, recursing
    /// into functions it calls up to `MAX_DEPTH` hops. Safe to call
    /// repeatedly / in any order — memoized, so this naturally computes
    /// leaves of the call graph first regardless of call order.
    pub fn summary_for(&mut self, id: &str) -> GuardSummary {
        self.compute(id, 0)
    }

    fn compute(&mut self, id: &str, depth: usize) -> GuardSummary {
        if let Some(cached) = self.cache.get(id) {
            return cached.clone();
        }
        // Conservative bail-outs: a cycle or a depth cutoff means we can't
        // prove anything about this function from here, so it guarantees
        // nothing as far as this analysis can tell — not cached, so a
        // shallower call path to the same function still gets a fair shot.
        if depth >= MAX_DEPTH || self.in_progress.contains(id) {
            return GuardSummary::new();
        }
        let Some(info) = self.graph.functions.get(id) else {
            return GuardSummary::new();
        };

        self.in_progress.insert(id.to_string());

        let cfg = build_cfg(&info.stmts);
        let exits = ok_exit_nodes(&cfg);
        let mut guaranteed = GuardSummary::new();

        // A function with no provable Ok-exit guarantees nothing: "dominates
        // every element of an empty set" is vacuously true, which would
        // grant a guarantee we haven't actually observed anything about.
        if !exits.is_empty() {
            let dom = DominanceChecker::new(&cfg);

            for (param, check_node) in direct_signer_checks(&cfg) {
                if exits
                    .iter()
                    .all(|&exit| dom.dominates_node(check_node, exit))
                {
                    guaranteed.insert(param);
                }
            }

            for call in self.graph.calls_from(id) {
                let Some(call_node) = find_call_node(&cfg, call) else {
                    continue;
                };
                if !exits
                    .iter()
                    .all(|&exit| dom.dominates_node(call_node, exit))
                {
                    continue;
                }
                let callee_summary = self.compute(&call.callee, depth + 1);
                if callee_summary.is_empty() {
                    continue;
                }
                let Some(callee_info) = self.graph.functions.get(&call.callee) else {
                    continue;
                };
                for (i, arg) in call.args.iter().enumerate() {
                    let Some(callee_param) = callee_info.params.get(i) else {
                        continue;
                    };
                    if !callee_summary.contains(callee_param) {
                        continue;
                    }
                    if let Some(name) = bare_identifier(arg) {
                        if info.params.contains(&name) {
                            guaranteed.insert(name);
                        }
                    }
                }
            }
        }

        self.in_progress.remove(id);
        self.cache.insert(id.to_string(), guaranteed.clone());
        guaranteed
    }
}
