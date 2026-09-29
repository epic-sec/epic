//! Stage 3 of interprocedural guard analysis: wires guard summaries (stage
//! 2) into a caller's CFG as guard facts, in exactly the shape an existing
//! require!/assert!-derived fact already takes. Everything downstream —
//! dominance, witnesses, SEC-002 — consumes `GuardFact`/`FactProvenance`
//! already; this module only produces more of them, from a different
//! source. No rule changes.

use crate::callgraph::CallGraph;
use crate::cfg::guards::{
    ir_expr_to_string, FactConfidence, FactProvenance, GuardFact, GuardTarget,
};
use crate::cfg::{ControlFlowGraph, SymbolId};
use crate::guard_summary::SummaryComputer;
use std::collections::HashMap;

/// Resolves a call-site argument expression to the account name it refers
/// to, in the same two shapes guards.rs's own owner/signer extraction
/// already recognizes: a `ctx.accounts.<name>` field access, or a bare
/// identifier (unwrapping `&`/`*`/`?` around either). Anything else is left
/// unresolved rather than guessed.
fn resolve_arg_to_account_name(expr: &epic_ir::IRExpression) -> Option<String> {
    match expr {
        epic_ir::IRExpression::FieldAccess { .. } => {
            let path = ir_expr_to_string(expr);
            path.strip_prefix("ctx.accounts.").map(|s| s.to_string())
        }
        epic_ir::IRExpression::Variable(name) => Some(name.clone()),
        epic_ir::IRExpression::Reference { expression, .. }
        | epic_ir::IRExpression::Dereference(expression)
        | epic_ir::IRExpression::Try(expression) => resolve_arg_to_account_name(expression),
        _ => None,
    }
}

/// Finds the CFG node containing the statement a call site came from, by
/// line number — same approach stage 2 uses internally, and for the same
/// reason: `CallSite` doesn't carry a direct statement/node backreference,
/// and a call's own source line is rarely shared with an unrelated
/// statement in the same function.
fn find_call_node(cfg: &ControlFlowGraph, call_line: usize) -> Option<usize> {
    let mut node_ids: Vec<usize> = cfg.nodes.keys().copied().collect();
    node_ids.sort_unstable();
    for node_id in node_ids {
        let node = &cfg.nodes[&node_id];
        if node.statements.iter().any(|s| s.line_number == call_line) {
            return Some(node_id);
        }
    }
    None
}

/// Extracts interprocedural guard facts for one instruction handler: for
/// each direct call it makes (resolved by stage 1's call graph) to a
/// function with a non-empty guard summary (stage 2), maps the guaranteed
/// parameter back onto the caller's own `ctx.accounts` symbol via the
/// call-site argument, and emits a `GuardFact::Signer` anchored at the
/// call's own node — the same provenance shape a require!-derived fact
/// already has, so dominance/witnesses/SEC-002 need no changes to consume
/// it.
pub fn extract_interprocedural_guards(
    caller_id: &str,
    cfg: &ControlFlowGraph,
    call_graph: &CallGraph,
    computer: &mut SummaryComputer,
    symbol_table: &HashMap<String, SymbolId>,
    file_path: &str,
) -> Vec<(GuardFact, FactProvenance)> {
    let mut facts = Vec::new();

    for call in call_graph.calls_from(caller_id) {
        let summary = computer.summary_for(&call.callee);
        if summary.is_empty() {
            continue;
        }
        let Some(callee_info) = call_graph.functions.get(&call.callee) else {
            continue;
        };
        let Some(call_node) = find_call_node(cfg, call.line) else {
            continue;
        };

        for (i, arg) in call.args.iter().enumerate() {
            let Some(callee_param) = callee_info.params.get(i) else {
                continue;
            };
            if !summary.contains(callee_param) {
                continue;
            }
            let arg_ir = crate::ir_converter::convert_expr_node_to_ir(
                &crate::cfg::builder::convert_expr(arg),
            );
            let account_name = resolve_arg_to_account_name(&arg_ir);
            let Some(account_name) = account_name else {
                continue;
            };
            let Some(&sym) = symbol_table.get(&account_name) else {
                continue;
            };

            facts.push((
                GuardFact::Signer(GuardTarget::Account(sym)),
                FactProvenance {
                    source_file: file_path.to_string(),
                    line_number: call.line,
                    column_number: 0,
                    framework: "Anchor".to_string(),
                    confidence_level: FactConfidence::Asserted,
                    node_id: Some(call_node),
                    statement_index: None,
                },
            ));
        }
    }

    facts
}
