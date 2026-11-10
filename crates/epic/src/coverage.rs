//! Coverage reporting: how much of a program's instruction surface EPIC's
//! rules actually got to see, independent of what they found.
//!
//! A 0-finding repo and a fully-analyzed-and-clean repo look identical in
//! `epic audit`'s output — but they mean completely different things. This
//! module answers "how many instruction handlers exist, how many resolved
//! to an `Accounts` struct, and how many were analyzed without hitting a
//! structural boundary (a loop, a `match`, recursion)" so the difference is
//! visible instead of silently collapsing to the same empty finding list.
//!
//! Also answers a narrower, sharper question for resolved handlers: of the
//! writes a handler's body makes or delegates to, how many does a rule
//! actually see today (`visible_writes`, direct in the handler's own CFG),
//! vs. how many only exist one hop away in a resolved `&mut self` delegate
//! (`reachable_via_resolved_delegate`, counted via `write_summary.rs`,
//! read-only — never wired into any rule) vs. how many are behind a
//! delegate-shaped call this build couldn't resolve at all
//! (`unresolved_delegate_calls`, a call-site count, not a write count: with
//! no resolved function there's no body to count writes in).
//!
//! Deliberately lighter than `for_each_analysis_context` otherwise: no SSA,
//! no guard-fact extraction — coverage only needs resolution, CFG shape,
//! and this one extra pass over each resolved handler's own statements.

use crate::ast::{ExpressionKind, ExpressionNode, StatementKind, StatementNode};
use crate::audit::{discover_raw_functions, field_effective_type, resolve_accounts_struct};
use crate::callgraph::{build_call_graph, CallGraph};
use crate::cfg::{CFGBoundaryWarning, CFGBuilder, ControlFlowGraph};
use crate::write_summary::compute_write_summary;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status")]
pub enum CoverageStatus {
    /// Resolved to an `Accounts` struct, CFG built cleanly, no boundary
    /// warnings — every rule got a full, unobstructed view of this handler.
    FullyAnalyzed,
    /// Resolved and analyzed, but the CFG hit a structural boundary (a
    /// loop body, a `match` arm, or recursion) that it doesn't model —
    /// rules still ran, but on a CFG that doesn't cover 100% of the
    /// handler's real control flow.
    PartiallyAnalyzed {
        boundary_warnings: Vec<CFGBoundaryWarning>,
    },
    /// No `Accounts` struct could be resolved for this handler's
    /// `Context<T>` argument — no rule saw this handler at all.
    Unresolved { reason: String },
    /// The struct resolved, but building a CFG from the handler's body
    /// itself failed — no rule saw this handler at all.
    CfgBuildFailed,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct MutationVisibility {
    /// Writes to `ctx.accounts.<path>` found directly in this handler's own
    /// CFG — what a rule scanning this handler's statements sees today.
    pub visible_writes: usize,
    /// Writes found inside a `ctx.accounts.<method>()` / `<field>.<method>()`
    /// delegate call that resolved (via `CallGraph::resolve_typed`) to a
    /// known `&mut self` method, counted with `write_summary::compute_write_summary`
    /// — real writes this handler's own body never shows a rule.
    pub reachable_via_resolved_delegate: usize,
    /// Delegate-shaped call sites that did *not* resolve to a known method.
    /// A write count behind these is unknowable (no function body to look
    /// at), so this counts the call sites themselves, not writes.
    pub unresolved_delegate_calls: usize,
}

impl MutationVisibility {
    /// True once resolved-but-hidden writes outnumber what's actually
    /// visible — the shape worth flagging: most of what this handler does
    /// is invisible to every rule, not just some of it.
    pub fn mostly_invisible(&self) -> bool {
        self.reachable_via_resolved_delegate > self.visible_writes
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HandlerCoverage {
    pub name: String,
    pub file: String,
    pub status: CoverageStatus,
    /// `None` for an `Unresolved`/`CfgBuildFailed` handler — mutation
    /// visibility is only meaningful for a handler a rule could actually
    /// run on.
    pub mutation: Option<MutationVisibility>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CoverageReport {
    pub total_handlers: usize,
    pub resolved_to_struct: usize,
    pub fully_analyzed: usize,
    /// `.rs` files that failed to parse entirely — any handler inside one
    /// is absent from `handlers` below, not just unresolved, since it was
    /// never even discovered.
    pub files_failed_to_parse: Vec<String>,
    pub handlers: Vec<HandlerCoverage>,
}

pub fn collect_coverage(root_path: &str) -> CoverageReport {
    let (workspace, raw_functions, files_failed_to_parse) = discover_raw_functions(root_path);
    let call_graph = build_call_graph(root_path);

    let mut handlers = Vec::with_capacity(raw_functions.len());
    let mut resolved_to_struct = 0;
    let mut fully_analyzed = 0;

    for raw_fn in &raw_functions {
        let resolved = resolve_accounts_struct(
            &workspace.registry,
            &raw_fn.program_name,
            &raw_fn.module_path,
            &raw_fn.file_path,
            &raw_fn.context_struct_name,
            raw_fn.impl_type.as_deref(),
        );

        let (status, mutation) = match resolved {
            None => {
                let reason = if raw_fn.context_struct_name == "Self" {
                    match &raw_fn.impl_type {
                        None => "Context<Self> with no enclosing impl type (trait impl or free function)".to_string(),
                        Some(t) => format!("Context<Self> resolved to impl type '{t}', but no Accounts struct named '{t}' found"),
                    }
                } else {
                    format!(
                        "no Accounts struct named '{}' found",
                        raw_fn.context_struct_name
                    )
                };
                (CoverageStatus::Unresolved { reason }, None)
            }
            Some((_, struct_def)) => {
                resolved_to_struct += 1;
                let field_types: HashMap<String, String> = struct_def
                    .fields
                    .iter()
                    .map(|f| (f.name.clone(), field_effective_type(f)))
                    .collect();
                let mut cfg_builder = CFGBuilder::new();
                match cfg_builder.compile_statements(&raw_fn.stmts, 0) {
                    Err(_) => (CoverageStatus::CfgBuildFailed, None),
                    Ok(_) => {
                        let cfg = &cfg_builder.graph;
                        let warnings = cfg.boundary_warnings.clone();
                        let status = if warnings.is_empty() {
                            fully_analyzed += 1;
                            CoverageStatus::FullyAnalyzed
                        } else {
                            CoverageStatus::PartiallyAnalyzed {
                                boundary_warnings: warnings,
                            }
                        };
                        let mutation = measure_mutation_visibility(
                            cfg,
                            &raw_fn.context_var_name,
                            &raw_fn.context_struct_name,
                            &field_types,
                            &call_graph,
                        );
                        (status, Some(mutation))
                    }
                }
            }
        };

        handlers.push(HandlerCoverage {
            name: raw_fn.name.clone(),
            file: raw_fn.file_path.clone(),
            status,
            mutation,
        });
    }

    CoverageReport {
        total_handlers: raw_functions.len(),
        resolved_to_struct,
        fully_analyzed,
        files_failed_to_parse,
        handlers,
    }
}

/// Walks every statement in `cfg` once, classifying each write or delegate
/// call it finds against `ctx_var_name`/`ctx_struct_name` (the handler's own
/// `Context<T>` binding and type — e.g. `ctx`/`Withdraw`) and
/// `field_types` (for shape (b) delegate calls, `<account_field>.method()`).
fn measure_mutation_visibility(
    cfg: &ControlFlowGraph,
    ctx_var_name: &str,
    ctx_struct_name: &str,
    field_types: &HashMap<String, String>,
    call_graph: &CallGraph,
) -> MutationVisibility {
    let mut result = MutationVisibility::default();
    for node in cfg.nodes_sorted() {
        let mut stmts = Vec::new();
        flatten_blocks(&node.statements, &mut stmts);
        for stmt in stmts {
            let expr = match stmt {
                StatementKind::Let { initializer, .. } => initializer,
                StatementKind::Expr(e) | StatementKind::Semi(e) => e,
                StatementKind::MacroCall { .. } | StatementKind::Block(_) => continue,
            };
            walk_expr(
                expr,
                ctx_var_name,
                ctx_struct_name,
                field_types,
                call_graph,
                &mut result,
            );
        }
    }
    result
}

fn flatten_blocks<'a>(stmts: &'a [StatementNode], out: &mut Vec<&'a StatementKind>) {
    for s in stmts {
        match &s.kind {
            StatementKind::Block(inner) => flatten_blocks(inner, out),
            kind => out.push(kind),
        }
    }
}

fn walk_expr(
    expr: &ExpressionNode,
    ctx_var_name: &str,
    ctx_struct_name: &str,
    field_types: &HashMap<String, String>,
    call_graph: &CallGraph,
    result: &mut MutationVisibility,
) {
    match &expr.kind {
        ExpressionKind::Assign { left, right } => {
            if let Some(path) = resolve_rooted_path(left, ctx_var_name) {
                if path.first().map(String::as_str) == Some("accounts") {
                    result.visible_writes += 1;
                }
            }
            walk_expr(
                left,
                ctx_var_name,
                ctx_struct_name,
                field_types,
                call_graph,
                result,
            );
            walk_expr(
                right,
                ctx_var_name,
                ctx_struct_name,
                field_types,
                call_graph,
                result,
            );
        }
        ExpressionKind::MethodCall {
            object,
            method,
            arguments,
        } => {
            classify_delegate_call(
                object,
                method,
                ctx_var_name,
                ctx_struct_name,
                field_types,
                call_graph,
                result,
            );
            walk_expr(
                object,
                ctx_var_name,
                ctx_struct_name,
                field_types,
                call_graph,
                result,
            );
            for a in arguments {
                walk_expr(
                    a,
                    ctx_var_name,
                    ctx_struct_name,
                    field_types,
                    call_graph,
                    result,
                );
            }
        }
        ExpressionKind::FieldAccess { object, .. } => {
            walk_expr(
                object,
                ctx_var_name,
                ctx_struct_name,
                field_types,
                call_graph,
                result,
            );
        }
        ExpressionKind::BinaryOp { lhs, rhs, .. } => {
            walk_expr(
                lhs,
                ctx_var_name,
                ctx_struct_name,
                field_types,
                call_graph,
                result,
            );
            walk_expr(
                rhs,
                ctx_var_name,
                ctx_struct_name,
                field_types,
                call_graph,
                result,
            );
        }
        ExpressionKind::Reference { expression, .. }
        | ExpressionKind::Dereference(expression)
        | ExpressionKind::Try(expression) => {
            walk_expr(
                expression,
                ctx_var_name,
                ctx_struct_name,
                field_types,
                call_graph,
                result,
            );
        }
        ExpressionKind::Identifier(_) | ExpressionKind::Literal(_) | ExpressionKind::Unresolved => {
        }
    }
}

/// Classifies one `receiver.method(..)` call against the two shapes
/// `write_summary.rs`'s own measurement tooling already established:
/// (a) `ctx.accounts.method(..)` — receiver type is this handler's own
///     `Context<T>` struct; (b) `<account_field>.method(..)` with nothing
///     further — receiver type is that field's own declared type (via
///     `field_types`). Anything else (a free function call, a call on a
/// value with no resolvable account-field type, a chain with more fields
/// after the account, e.g. `ctx.accounts.vault.reload()`) isn't a
/// delegate-shaped call this measurement can classify, and is silently
/// ignored — same discipline every heuristic in this crate uses for a
/// shape it doesn't recognize.
fn classify_delegate_call(
    receiver: &ExpressionNode,
    method: &str,
    ctx_var_name: &str,
    ctx_struct_name: &str,
    field_types: &HashMap<String, String>,
    call_graph: &CallGraph,
    result: &mut MutationVisibility,
) {
    let Some(path) = resolve_rooted_path(receiver, ctx_var_name) else {
        return;
    };

    let receiver_type = match path.as_slice() {
        // Shape (a): `ctx.accounts.method(..)` — the receiver IS
        // `ctx.accounts` itself, nothing further.
        [a] if a == "accounts" => ctx_struct_name.to_string(),
        // Shape (b): `ctx.accounts.<field>.method(..)` — exactly one field
        // below `accounts`, nothing nested further.
        [a, field] if a == "accounts" => match field_types.get(field) {
            Some(t) => t.clone(),
            None => return,
        },
        _ => return,
    };

    match call_graph.resolve_typed(&receiver_type, method) {
        Some(id) => {
            let Some(info) = call_graph.get(id) else {
                result.unresolved_delegate_calls += 1;
                return;
            };
            let summary = compute_write_summary(info, call_graph);
            result.reachable_via_resolved_delegate += summary.writes.len();
        }
        None => {
            result.unresolved_delegate_calls += 1;
        }
    }
}

/// `<root>.<field>[.<more>]` -> `Some(["field", "more", ..])`; `None` if the
/// expression's root identifier isn't `root` (e.g. a local variable, not
/// the handler's own `ctx`/`self`), or if it's not a field-access chain at
/// all.
fn resolve_rooted_path(expr: &ExpressionNode, root: &str) -> Option<Vec<String>> {
    let mut segments = Vec::new();
    let mut cur = expr;
    loop {
        match &cur.kind {
            ExpressionKind::FieldAccess { object, field } => {
                segments.push(field.clone());
                cur = object;
            }
            ExpressionKind::Identifier(name) if name == root => {
                segments.reverse();
                return Some(segments);
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
