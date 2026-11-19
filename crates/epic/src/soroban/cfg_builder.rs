//! A small, Soroban-only CFG builder. Reuses `crate::cfg`'s data types
//! (`ControlFlowGraph`/`CFGNode`/`CFGEdge`) and `cfg::builder`'s syn->IR
//! statement/expression converters, but is its own construction logic --
//! **not** `CFGBuilder`, and `CFGBuilder` is not modified by anything here.
//!
//! Two real gaps in reusing the shared `CFGBuilder` as-is, found while
//! building this (see `docs/soroban-core-leaks.md`):
//! - `CFGBuilder` treats `match` as an opaque boundary (records a warning,
//!   never descends into arms) -- fine for Anchor, where `match` is
//!   comparatively rare, but Soroban dispatches via `match` constantly
//!   (error handling, action enums). This builder descends into every arm.
//! - `CFGBuilder::is_terminating_stmt` recognizes `panic!`/`unreachable!`
//!   but not Soroban's own `panic_with_error!` macro. This builder treats
//!   all three as aborts.
//!
//! Loops are still treated as an opaque boundary (not entered) -- same
//! choice `CFGBuilder` makes, kept for v0 scope; logged as a limitation,
//! not silently different from the documented behavior elsewhere.

use crate::ast::StatementNode;
use crate::cfg::builder::{convert_expr, convert_stmt};
use crate::cfg::{CFGEdge, CFGNode, ControlFlowGraph};
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::Visit;

pub(crate) struct SorobanCfgBuilder {
    pub graph: ControlFlowGraph,
    /// Exit nodes that terminated via `panic!`/`unreachable!`/
    /// `panic_with_error!` -- the invocation never completes, so these are
    /// never "normal returns" for the auth-bypass check.
    pub abort_nodes: HashSet<usize>,
    /// `(node, callee_name, line)` for every plain function call found
    /// (anywhere: leaf statements, if-conditions, match scrutinees) whose
    /// callee matches a name in the one-hop helper index. `ExpressionKind`
    /// has no representation for a plain `syn::Expr::Call` at all (only
    /// method calls) -- confirmed earlier this session investigating why
    /// orca-whirlpools' free-function delegation was invisible to the
    /// shared IR -- so this can only be found by scanning raw syn, not by
    /// walking the converted `CFGNode.statements`.
    pub helper_call_sites: Vec<(usize, String, usize)>,
    helper_names: HashSet<String>,
    next_id: usize,
}

impl SorobanCfgBuilder {
    pub fn new(helper_names: HashSet<String>) -> Self {
        let mut graph = ControlFlowGraph::default();
        graph.nodes.insert(
            0,
            CFGNode {
                id: 0,
                statements: Vec::new(),
                ir_instructions: Vec::new(),
            },
        );
        graph.entry_node = 0;
        Self {
            graph,
            abort_nodes: HashSet::new(),
            helper_call_sites: Vec::new(),
            helper_names,
            next_id: 1,
        }
    }

    fn scan_helper_calls(&mut self, node: usize, expr: &syn::Expr) {
        if self.helper_names.is_empty() {
            return;
        }
        let mut visitor = HelperCallVisitor {
            helper_names: &self.helper_names,
            found: Vec::new(),
        };
        visitor.visit_expr(expr);
        for (name, line) in visitor.found {
            self.helper_call_sites.push((node, name, line));
        }
    }

    fn new_node(&mut self) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.graph.nodes.insert(
            id,
            CFGNode {
                id,
                statements: Vec::new(),
                ir_instructions: Vec::new(),
            },
        );
        id
    }

    fn add_edge(&mut self, from: usize, to: usize) {
        self.graph.edges.push(CFGEdge {
            from,
            to,
            condition: None,
            ir_condition: None,
            is_early_return: false,
            line: None,
        });
    }

    fn push_stmt(&mut self, node: usize, converted: StatementNode) {
        self.graph
            .nodes
            .get_mut(&node)
            .unwrap()
            .statements
            .push(converted);
    }

    fn mark_exit(&mut self, node: usize, is_abort: bool) {
        if !self.graph.exit_nodes.contains(&node) {
            self.graph.exit_nodes.push(node);
        }
        if is_abort {
            self.abort_nodes.insert(node);
        }
    }

    /// Compiles `stmts` starting at `current`, returning the node execution
    /// ends at if it falls off the end of the block normally (the caller
    /// decides whether that's reachable further, same convention
    /// `CFGBuilder` uses).
    pub fn compile(&mut self, stmts: &[syn::Stmt], mut current: usize) -> usize {
        for stmt in stmts {
            if let Some(is_abort) = terminal_kind(stmt) {
                let converted = convert_stmt(stmt);
                self.push_stmt(current, converted);
                self.mark_exit(current, is_abort);
                return current;
            }

            match stmt {
                syn::Stmt::Expr(syn::Expr::If(expr_if), _) => {
                    current = self.compile_if(expr_if, current);
                }
                syn::Stmt::Expr(syn::Expr::Match(expr_match), _) => {
                    current = self.compile_match(expr_match, current);
                }
                syn::Stmt::Expr(
                    syn::Expr::Loop(_) | syn::Expr::While(_) | syn::Expr::ForLoop(_),
                    _,
                ) => {
                    // Boundary, same choice CFGBuilder makes: record the
                    // statement opaquely, don't enter the body.
                    let converted = convert_stmt(stmt);
                    self.push_stmt(current, converted);
                }
                _ => {
                    if let syn::Stmt::Expr(e, _) = stmt {
                        self.scan_helper_calls(current, e);
                    }
                    let converted = convert_stmt(stmt);
                    self.push_stmt(current, converted);
                }
            }
        }
        current
    }

    fn compile_if(&mut self, expr_if: &syn::ExprIf, current: usize) -> usize {
        let then_id = self.new_node();
        let else_id = self.new_node();
        let merge_id = self.new_node();

        self.scan_helper_calls(current, &expr_if.cond);
        let cond = convert_expr(&expr_if.cond);
        self.graph.edges.push(CFGEdge {
            from: current,
            to: then_id,
            condition: Some(cond),
            ir_condition: None,
            is_early_return: false,
            line: None,
        });
        self.add_edge(current, else_id);

        let then_end = self.compile(&expr_if.then_branch.stmts, then_id);
        let else_end = match &expr_if.else_branch {
            None => else_id,
            Some((_, else_expr)) => match &**else_expr {
                syn::Expr::Block(b) => self.compile(&b.block.stmts, else_id),
                // else-if chain: recurse as a single-statement block.
                other => {
                    let wrapped = vec![syn::Stmt::Expr(other.clone(), None)];
                    self.compile(&wrapped, else_id)
                }
            },
        };

        if !self.graph.exit_nodes.contains(&then_end) {
            self.add_edge(then_end, merge_id);
        }
        if !self.graph.exit_nodes.contains(&else_end) {
            self.add_edge(else_end, merge_id);
        }
        merge_id
    }

    fn compile_match(&mut self, expr_match: &syn::ExprMatch, current: usize) -> usize {
        self.scan_helper_calls(current, &expr_match.expr);
        let merge_id = self.new_node();
        let mut any_arm_continues = false;

        for arm in &expr_match.arms {
            let arm_id = self.new_node();
            self.add_edge(current, arm_id);
            let body_stmts: Vec<syn::Stmt> = match &*arm.body {
                syn::Expr::Block(b) => b.block.stmts.clone(),
                other => vec![syn::Stmt::Expr(other.clone(), None)],
            };
            let arm_end = self.compile(&body_stmts, arm_id);
            if !self.graph.exit_nodes.contains(&arm_end) {
                self.add_edge(arm_end, merge_id);
                any_arm_continues = true;
            }
        }

        if any_arm_continues {
            merge_id
        } else {
            // every arm aborted or returned -- nothing falls through.
            // merge_id stays an isolated, unreachable node; mark it an exit
            // so callers don't accidentally treat it as live.
            self.mark_exit(merge_id, true);
            merge_id
        }
    }
}

/// `Some(is_abort)` when this statement unconditionally stops execution in
/// this block -- `Some(true)` for panic!/unreachable!/panic_with_error!,
/// `Some(false)` for an explicit `return`. `None` for anything else
/// (including a fallible `?` call -- not modeled as early-return here, see
/// docs/soroban-core-leaks.md).
fn terminal_kind(stmt: &syn::Stmt) -> Option<bool> {
    let (expr, semi) = match stmt {
        syn::Stmt::Macro(m) => {
            return if is_abort_macro(&m.mac) {
                Some(true)
            } else {
                None
            };
        }
        syn::Stmt::Expr(e, semi) => (e, semi),
        _ => return None,
    };
    match expr {
        // `return Err(..)` aborts the whole invocation (storage writes made
        // before it are rolled back -- verified empirically, see
        // docs/soroban-core-leaks.md #14); `return Ok(x)` / `return x` is an
        // ordinary normal-return exit.
        syn::Expr::Return(r) => {
            if r.expr.as_deref().is_some_and(is_err_call) {
                Some(true)
            } else {
                Some(false)
            }
        }
        syn::Expr::Macro(m) if is_abort_macro(&m.mac) => Some(true),
        // A semicolon-less `Err(..)` is the block's own tail value (Rust's
        // grammar requires a non-unit expression with no semicolon to be in
        // tail position), i.e. this function's return value -- same abort
        // semantics as an explicit `return Err(..)`.
        e if semi.is_none() && is_err_call(e) => Some(true),
        _ => None,
    }
}

/// `Err(..)` or `SomePath::Err(..)` -- matched by the call's last path
/// segment, same bare-name convention used elsewhere in this module.
fn is_err_call(expr: &syn::Expr) -> bool {
    let syn::Expr::Call(call) = expr else {
        return false;
    };
    let syn::Expr::Path(p) = &*call.func else {
        return false;
    };
    p.path.segments.last().is_some_and(|s| s.ident == "Err")
}

fn is_abort_macro(mac: &syn::Macro) -> bool {
    let Some(name) = mac.path.segments.last().map(|s| s.ident.to_string()) else {
        return false;
    };
    name == "panic" || name == "unreachable" || name == "panic_with_error"
}

/// Collects every `syn::ExprCall` whose callee is a bare path matching a
/// name in `helper_names`, anywhere in the visited subtree (`Visit`
/// recurses through `?`, references, parens, nested calls, etc. for free).
struct HelperCallVisitor<'a> {
    helper_names: &'a HashSet<String>,
    found: Vec<(String, usize)>,
}

impl<'ast> Visit<'ast> for HelperCallVisitor<'_> {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        // Match by the path's *last* segment, not `get_ident()` (single
        // segment only) -- a same-crate helper is routinely called through
        // a module-qualified path (`utils::increment(..)`), confirmed
        // against a real scout-soroban fixture that uses exactly this
        // shape. Same bare-name convention the rest of this crate's call
        // resolution already uses; `HelperIndex` still refuses an
        // ambiguous name, so this doesn't trade safety for recall.
        if let syn::Expr::Path(p) = &*call.func {
            if let Some(name) = p.path.segments.last().map(|s| s.ident.to_string()) {
                if self.helper_names.contains(&name) {
                    self.found.push((name, call.span().start().line));
                }
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
}
