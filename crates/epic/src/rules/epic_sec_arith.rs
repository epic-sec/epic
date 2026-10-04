use crate::ast::{StatementKind, StatementNode};
use crate::cfg::guards::{FactConfidence, InstructionAnalysisContext, SymbolId};
use crate::cfg::ControlFlowGraph;
use crate::rules::{
    find_bypassing_path, AnalysisContext, DominanceChecker, FindingLocation, Rule, RuleDiagnostic,
    RuleSeverity, Witness, WitnessCheck, WitnessStep,
};
use epic_ir::{IRExpression, IRInstruction};
use std::collections::{HashMap, HashSet};

/// EPIC-SEC-ARITH: raw `+`/`-`/`*` on a value that traces back to an
/// instruction parameter or account data, with no bound established on
/// every path reaching it. Unlike a signer check, Anchor has no
/// declarative constraint for arithmetic safety — there is no type-system
/// shortcut, so unlike EPIC-SEC-002's signer-dominance work, a real,
/// imperative, sometimes-conditional guard is the norm here, not the
/// exception. That is the condition under which dominance (a guard that
/// exists but doesn't cover every path) actually has something to find.
///
/// `checked_*`/`saturating_*`/`wrapping_*` never appear in this scan at
/// all: they are method calls, not `+`/`-`/`*` operators, so they're
/// structurally absent from the candidate set rather than excluded by a
/// special case. A bound is instead established by one of:
/// - a `checked_*`/`saturating_*`/`wrapping_*` call on the same value
///   elsewhere, dominating this point;
/// - a `require!`/`assert!` comparison, or a hand-written
///   `if cond { return Err(..) }`, mentioning the value — both desugar to
///   the same CFG shape (an edge tagged `is_early_return`), so both are
///   checked the same way, on the CFG, not by matching source syntax.
///
/// "Mentioning the value" means the *same resolved field/method path*,
/// not just the same root account — `require_keys_eq!(x.owner, ...)` is
/// not a bound on `x.balance`, even though both are reached through `x`.
/// Matching only by root, measured directly against the 5-protocol sweep,
/// credited exactly this: a delegate-ownership `Pubkey` comparison
/// (`account.fixed.owner`) got treated as a bound on an unrelated balance
/// subtraction reached via `account.token_position_mut_by_raw_index(..)
/// .native(..)` — same account, different field entirely. See
/// `KNOWN_LIMITATIONS.md`.
///
/// Provenance tracing is deliberately shallow: a plain `let`-alias chain
/// (notably `let x = &mut ctx.accounts.y;`, the single most common Anchor
/// idiom for this) is traced back through its full path, but an operand
/// produced by its own arithmetic, a loop counter, or anything else this
/// can't resolve a complete path for is left untraced — which means it's
/// simply never a candidate *and* never credited as a bound for one, per
/// the brief: under-claim rather than guess, in both directions.
pub struct UncheckedArithmeticRule;

const CHECKED_METHODS: &[&str] = &[
    "checked_add",
    "checked_sub",
    "checked_mul",
    "checked_div",
    "saturating_add",
    "saturating_sub",
    "saturating_mul",
    "wrapping_add",
    "wrapping_sub",
    "wrapping_mul",
];
const COMPARISON_OPS: &[&str] = &["<", "<=", ">", ">=", "==", "!="];
const ARITH_OPS: &[&str] = &["+", "-", "*"];

/// A location (and, for display, the text) where a bound on `path` is
/// established — the arithmetic equivalent of `GuardFact::Signer`, kept
/// local to this rule rather than added to the shared `GuardFact` enum.
///
/// `path` is the full resolved field/method chain (e.g.
/// `"account.fixed.owner"`), not just the root account — a comparison on
/// one field must never be credited as a bound on a different field of
/// the same account. Exact string match, deliberately: this rule does not
/// attempt to reason about partial overlap between two paths.
#[derive(Clone)]
struct BoundFact {
    path: String,
    node_id: usize,
    check: WitnessCheck,
}

enum BoundResult {
    Dominates,
    Bypassed {
        fact_node: usize,
        check: WitnessCheck,
    },
    NotFound,
}

impl Rule for UncheckedArithmeticRule {
    fn id(&self) -> &'static str {
        "EPIC-SEC-ARITH"
    }

    fn name(&self) -> &'static str {
        "Unchecked Arithmetic on Untrusted Input"
    }

    fn check(&self, context: &AnalysisContext) -> Vec<RuleDiagnostic> {
        let dom_checker = context.dominance();
        let ic = &context.instruction_context;
        let mut diagnostics = Vec::new();

        // Pass 1: whole-function alias map. Name-based, not SSA-versioned —
        // this rule only needs "could this identifier ultimately be an
        // account field or instruction parameter", never reassignment
        // history, so the simpler model is enough.
        let mut aliases: HashMap<String, String> = HashMap::new();
        for node in ic.cfg.nodes.values() {
            let mut stmts = Vec::new();
            collect_statements(&node.statements, &mut stmts);
            for stmt in &stmts {
                if let StatementKind::Let {
                    name, initializer, ..
                } = &stmt.kind
                {
                    let init_ir = crate::ir_converter::convert_expr_node_to_ir(initializer);
                    if let Some(path) = resolve_full_path(&init_ir, &ic.context_var_name, &aliases)
                    {
                        aliases.insert(name.clone(), path);
                    }
                }
            }
        }

        // Pass 2: bound facts (checked_*/saturating_*/wrapping_* calls and
        // early-return guard edges).
        let bound_facts = collect_bound_facts(ic, &aliases);

        // Pass 3: arithmetic candidates, checked against the bound facts.
        // Keyed by resolved path, not root symbol — two different fields
        // of the same account are reported independently.
        let mut reported: HashSet<String> = HashSet::new();
        for node in ic.cfg.nodes.values() {
            let mut stmts = Vec::new();
            collect_statements(&node.statements, &mut stmts);
            for (stmt_idx, stmt) in stmts.iter().enumerate() {
                for instr in crate::ir_converter::convert_statement_node_to_ir(stmt) {
                    let expr = match &instr {
                        IRInstruction::Expr(e) => e,
                        IRInstruction::Assignment(a) => &a.value,
                        _ => continue,
                    };
                    scan_for_arithmetic(
                        expr,
                        node.id,
                        stmt_idx,
                        stmt.line_number,
                        ic,
                        &aliases,
                        &bound_facts,
                        &dom_checker,
                        &mut reported,
                        &mut diagnostics,
                    );
                }
            }
        }

        diagnostics.sort_by_key(|d| d.location.line);
        diagnostics
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_for_arithmetic(
    expr: &IRExpression,
    node_id: usize,
    stmt_idx: usize,
    line: usize,
    ic: &InstructionAnalysisContext,
    aliases: &HashMap<String, String>,
    bound_facts: &[BoundFact],
    dom_checker: &DominanceChecker,
    reported: &mut HashSet<String>,
    diagnostics: &mut Vec<RuleDiagnostic>,
) {
    if let IRExpression::BinaryOp { op, lhs, rhs } = expr {
        if ARITH_OPS.contains(&op.as_str()) {
            for operand in [lhs.as_ref(), rhs.as_ref()] {
                if let Some((sym, path)) = traced_candidate(operand, ic, aliases) {
                    check_bound(
                        sym,
                        &path,
                        op,
                        node_id,
                        stmt_idx,
                        line,
                        ic,
                        bound_facts,
                        dom_checker,
                        reported,
                        diagnostics,
                    );
                }
            }
        }
    }

    // Recurse regardless of whether this node itself was a flaggable
    // arithmetic op — a candidate's own operands can be further arithmetic
    // (`(a + b) * c`), each checked independently on its own terms.
    match expr {
        IRExpression::BinaryOp { lhs, rhs, .. }
        | IRExpression::Assign {
            left: lhs,
            right: rhs,
        } => {
            scan_for_arithmetic(
                lhs,
                node_id,
                stmt_idx,
                line,
                ic,
                aliases,
                bound_facts,
                dom_checker,
                reported,
                diagnostics,
            );
            scan_for_arithmetic(
                rhs,
                node_id,
                stmt_idx,
                line,
                ic,
                aliases,
                bound_facts,
                dom_checker,
                reported,
                diagnostics,
            );
        }
        IRExpression::FieldAccess { object, .. } => {
            scan_for_arithmetic(
                object,
                node_id,
                stmt_idx,
                line,
                ic,
                aliases,
                bound_facts,
                dom_checker,
                reported,
                diagnostics,
            );
        }
        IRExpression::Call {
            target, arguments, ..
        } => {
            scan_for_arithmetic(
                target,
                node_id,
                stmt_idx,
                line,
                ic,
                aliases,
                bound_facts,
                dom_checker,
                reported,
                diagnostics,
            );
            for arg in arguments {
                scan_for_arithmetic(
                    arg,
                    node_id,
                    stmt_idx,
                    line,
                    ic,
                    aliases,
                    bound_facts,
                    dom_checker,
                    reported,
                    diagnostics,
                );
            }
        }
        IRExpression::Reference { expression, .. }
        | IRExpression::Dereference(expression)
        | IRExpression::Try(expression) => {
            scan_for_arithmetic(
                expression,
                node_id,
                stmt_idx,
                line,
                ic,
                aliases,
                bound_facts,
                dom_checker,
                reported,
                diagnostics,
            );
        }
        _ => {}
    }
}

/// Resolves `expr` to both the root account/param `SymbolId` (for
/// candidacy and `target_symbol`) and its full resolved path (for bound
/// matching — see `BoundFact`).
fn traced_candidate(
    expr: &IRExpression,
    ic: &InstructionAnalysisContext,
    aliases: &HashMap<String, String>,
) -> Option<(SymbolId, String)> {
    let path = resolve_full_path(expr, &ic.context_var_name, aliases)?;
    let root = path.split('.').next()?;
    let &sym = ic.symbol_table.get(root)?;
    if ic.account_field_ids.contains(&sym) || ic.param_ids.contains(&sym) {
        Some((sym, path))
    } else {
        None
    }
}

#[allow(clippy::too_many_arguments)]
fn check_bound(
    sym: SymbolId,
    path: &str,
    op: &str,
    node_id: usize,
    stmt_idx: usize,
    line: usize,
    ic: &InstructionAnalysisContext,
    bound_facts: &[BoundFact],
    dom_checker: &DominanceChecker,
    reported: &mut HashSet<String>,
    diagnostics: &mut Vec<RuleDiagnostic>,
) {
    let classification = classify_bound(path, node_id, stmt_idx, bound_facts, dom_checker);
    if matches!(classification, BoundResult::Dominates) {
        return;
    }
    // Only report once per resolved path per instruction, same convention
    // EPIC-SEC-002 uses for its own symbols — otherwise every further
    // unguarded use of the same value re-states the same finding.
    if !reported.insert(path.to_string()) {
        return;
    }

    let witness = build_witness(&classification, &ic.cfg, node_id, line);

    diagnostics.push(RuleDiagnostic {
        rule_id: "EPIC-SEC-ARITH".to_string(),
        severity: RuleSeverity::Critical,
        message: format!(
            "Unchecked `{}` on '{}', which traces back to instruction input or account data, with no bound established on every path reaching it. A silent overflow/underflow here is not caught at runtime unless this is a checked/saturating/wrapping operation.",
            op, path
        ),
        location: FindingLocation {
            file: ic.file_path.clone(),
            line,
            column: 0,
            node_id,
            statement_index: Some(stmt_idx),
        },
        confidence: FactConfidence::Asserted,
        target_symbol: sym,
        witness,
    });
}

fn classify_bound(
    path: &str,
    use_node: usize,
    use_stmt: usize,
    bound_facts: &[BoundFact],
    dom_checker: &DominanceChecker,
) -> BoundResult {
    let mut bypassed: Option<&BoundFact> = None;
    for fact in bound_facts {
        if fact.path != path {
            continue;
        }
        if dom_checker.dominates(fact.node_id, None, use_node, Some(use_stmt)) {
            return BoundResult::Dominates;
        }
        if bypassed.is_none() {
            bypassed = Some(fact);
        }
    }
    match bypassed {
        Some(fact) => BoundResult::Bypassed {
            fact_node: fact.node_id,
            check: fact.check.clone(),
        },
        None => BoundResult::NotFound,
    }
}

fn build_witness(
    classification: &BoundResult,
    cfg: &ControlFlowGraph,
    use_node: usize,
    use_line: usize,
) -> Option<Witness> {
    match classification {
        BoundResult::Dominates => None,
        BoundResult::NotFound => Some(Witness {
            check: None,
            path: Vec::new(),
        }),
        BoundResult::Bypassed { fact_node, check } => {
            let path = find_bypassing_path(cfg, *fact_node, use_node).unwrap_or_default();
            Some(Witness {
                check: Some(check.clone()),
                path: render_path(cfg, &path, use_line),
            })
        }
    }
}

fn render_path(cfg: &ControlFlowGraph, path: &[usize], use_line: usize) -> Vec<WitnessStep> {
    let mut steps = Vec::with_capacity(path.len());
    for (i, &node) in path.iter().enumerate() {
        if i == 0 {
            let line = cfg
                .nodes
                .get(&node)
                .and_then(|n| n.statements.first())
                .map(|s| s.line_number)
                .unwrap_or(0);
            steps.push(WitnessStep {
                line,
                label: format!("entry (bb{})", node),
            });
            continue;
        }
        if i == path.len() - 1 {
            steps.push(WitnessStep {
                line: use_line,
                label: format!("arithmetic at line {} (bb{})", use_line, node),
            });
            continue;
        }
        let prev = path[i - 1];
        let edge = cfg.edges.iter().find(|e| e.from == prev && e.to == node);
        match edge.and_then(|e| e.ir_condition.as_ref().map(|c| (e, c))) {
            Some((e, cond)) => steps.push(WitnessStep {
                line: e.line.unwrap_or(0),
                label: format!(
                    "bb{} (branch at line {}: {})",
                    node,
                    e.line.unwrap_or(0),
                    ir_expr_to_display(cond)
                ),
            }),
            None => steps.push(WitnessStep {
                line: edge.and_then(|e| e.line).unwrap_or(0),
                label: format!("bb{}", node),
            }),
        }
    }
    steps
}

fn collect_bound_facts(
    ic: &InstructionAnalysisContext,
    aliases: &HashMap<String, String>,
) -> Vec<BoundFact> {
    let mut facts = Vec::new();

    // (a) `require!`/`assert!`/hand-written `if cond { return Err(..) }` —
    // all desugar to the same CFG shape, an edge tagged `is_early_return`.
    // The bound holds on the sibling (continuing) edge's target node; same
    // shape EPIC-SEC-006 uses for its own body-level guard check.
    for edge in &ic.cfg.edges {
        if !edge.is_early_return {
            continue;
        }
        let Some(cond) = &edge.ir_condition else {
            continue;
        };
        let mentioned = comparison_mentioned_paths(cond, ic, aliases);
        if mentioned.is_empty() {
            continue;
        }
        let Some(sibling) = ic
            .cfg
            .edges
            .iter()
            .find(|se| se.from == edge.from && se.to != edge.to)
        else {
            continue;
        };
        let check = WitnessCheck {
            line: edge.line.unwrap_or(0),
            text: ir_expr_to_display(cond),
        };
        for path in mentioned {
            facts.push(BoundFact {
                path,
                node_id: sibling.to,
                check: check.clone(),
            });
        }
    }

    // (b) checked_*/saturating_*/wrapping_* calls, anywhere in the function.
    for node in ic.cfg.nodes.values() {
        let mut stmts = Vec::new();
        collect_statements(&node.statements, &mut stmts);
        for stmt in &stmts {
            for instr in crate::ir_converter::convert_statement_node_to_ir(stmt) {
                let expr = match &instr {
                    IRInstruction::Expr(e) => e,
                    IRInstruction::Assignment(a) => &a.value,
                    _ => continue,
                };
                collect_checked_call_facts(
                    expr,
                    node.id,
                    stmt.line_number,
                    ic,
                    aliases,
                    &mut facts,
                );
            }
        }
    }

    facts
}

fn collect_checked_call_facts(
    expr: &IRExpression,
    node_id: usize,
    line: usize,
    ic: &InstructionAnalysisContext,
    aliases: &HashMap<String, String>,
    facts: &mut Vec<BoundFact>,
) {
    match expr {
        IRExpression::Call {
            target,
            method: Some(m),
            arguments,
        } => {
            if CHECKED_METHODS.contains(&m.as_str()) {
                if let Some(path) = resolve_full_path(target, &ic.context_var_name, aliases) {
                    let is_tracked = path
                        .split('.')
                        .next()
                        .and_then(|root| ic.symbol_table.get(root))
                        .is_some_and(|&sym| {
                            ic.account_field_ids.contains(&sym) || ic.param_ids.contains(&sym)
                        });
                    if is_tracked {
                        facts.push(BoundFact {
                            path: path.clone(),
                            node_id,
                            check: WitnessCheck {
                                line,
                                text: format!("{}.{}(..)", path, m),
                            },
                        });
                    }
                }
            }
            collect_checked_call_facts(target, node_id, line, ic, aliases, facts);
            for arg in arguments {
                collect_checked_call_facts(arg, node_id, line, ic, aliases, facts);
            }
        }
        IRExpression::BinaryOp { lhs, rhs, .. }
        | IRExpression::Assign {
            left: lhs,
            right: rhs,
        } => {
            collect_checked_call_facts(lhs, node_id, line, ic, aliases, facts);
            collect_checked_call_facts(rhs, node_id, line, ic, aliases, facts);
        }
        IRExpression::FieldAccess { object, .. } => {
            collect_checked_call_facts(object, node_id, line, ic, aliases, facts);
        }
        IRExpression::Reference { expression, .. }
        | IRExpression::Dereference(expression)
        | IRExpression::Try(expression) => {
            collect_checked_call_facts(expression, node_id, line, ic, aliases, facts);
        }
        _ => {}
    }
}

/// Every account/param path mentioned in a comparison inside `expr` —
/// `expr` may be a plain comparison or a `&&`/`||` of several, so this
/// recurses through boolean connectives to find every comparison,
/// regardless of nesting.
///
/// This is deliberately exact-path, not root-account: comparing `.owner`
/// does not bound `.balance` just because both live on the same account.
/// A comparison that resolves but whose path turns out to be a *different*
/// field than the one being checked is correctly not a match — it's
/// simply never credited as a bound for anything else, which is the
/// point. The one thing still left loose, same as before: no attempt is
/// made to prove the comparison bounds the value in the
/// overflow-relevant *direction* (e.g. `<=` vs `>=`) — a presence check
/// on the matching path, not a soundness proof.
fn comparison_mentioned_paths(
    expr: &IRExpression,
    ic: &InstructionAnalysisContext,
    aliases: &HashMap<String, String>,
) -> Vec<String> {
    let mut found = Vec::new();
    if let IRExpression::BinaryOp { op, lhs, rhs } = expr {
        if COMPARISON_OPS.contains(&op.as_str()) {
            for side in [lhs.as_ref(), rhs.as_ref()] {
                if let Some((_, path)) = traced_candidate(side, ic, aliases) {
                    found.push(path);
                }
            }
        } else {
            found.extend(comparison_mentioned_paths(lhs, ic, aliases));
            found.extend(comparison_mentioned_paths(rhs, ic, aliases));
        }
    } else if let IRExpression::Reference { expression, .. }
    | IRExpression::Dereference(expression)
    | IRExpression::Try(expression) = expr
    {
        found.extend(comparison_mentioned_paths(expression, ic, aliases));
    }
    found
}

/// Resolves `expr` to the full field/method path of the account field or
/// instruction parameter it ultimately refers to — e.g. `"vault.balance"`,
/// or `"account.token_position_mut_by_raw_index.native"` for a value
/// reached through a chain of `let`-aliases and method calls. A direct
/// `ctx.accounts.<name>` access anchors the root; a bare
/// parameter/local identifier is resolved through `aliases` if it's an
/// alias, otherwise treated as a root itself. Returns `None` if any step
/// can't be classified this way — the "under-claim" case: an unresolvable
/// path is never treated as a candidate *or* as a bound for one.
///
/// `.len()` is explicitly excluded here, not just left unresolved by
/// omission: `Call` is otherwise transparent (so `.to_account_info()`,
/// `.clone()`, etc. see through to their receiver), and without this
/// special case `ctx.accounts.vault.items.len()` would trace straight
/// through to `vault`, flagging ordinary bounds arithmetic on a length.
fn resolve_full_path(
    expr: &IRExpression,
    context_var: &str,
    aliases: &HashMap<String, String>,
) -> Option<String> {
    match expr {
        IRExpression::Try(inner) => resolve_full_path(inner, context_var, aliases),
        IRExpression::Reference { expression, .. } => {
            resolve_full_path(expression, context_var, aliases)
        }
        IRExpression::Dereference(inner) => resolve_full_path(inner, context_var, aliases),
        IRExpression::Call { target, method, .. } => {
            if method.as_deref() == Some("len") {
                return None;
            }
            let base = resolve_full_path(target, context_var, aliases)?;
            match method {
                Some(m) => Some(format!("{}.{}", base, m)),
                None => Some(base),
            }
        }
        IRExpression::Variable(name) => {
            Some(aliases.get(name).cloned().unwrap_or_else(|| name.clone()))
        }
        IRExpression::FieldAccess { object, field } => {
            if let IRExpression::FieldAccess {
                object: inner_obj,
                field: inner_field,
            } = object.as_ref()
            {
                if inner_field == "accounts" {
                    if let IRExpression::Variable(v) = inner_obj.as_ref() {
                        if v == context_var {
                            return Some(field.clone());
                        }
                    }
                }
            }
            let base = resolve_full_path(object, context_var, aliases)?;
            Some(format!("{}.{}", base, field))
        }
        _ => None,
    }
}

fn ir_expr_to_display(expr: &IRExpression) -> String {
    match expr {
        IRExpression::Variable(name) => name.clone(),
        IRExpression::Literal(val) => val.clone(),
        IRExpression::FieldAccess { object, field } => {
            format!("{}.{}", ir_expr_to_display(object), field)
        }
        // Unary `!cond` lowers to a `BinaryOp{op: "!", rhs: Unresolved}`
        // node at the AST layer (there's no dedicated unary-not variant),
        // so it needs its own prefix rendering — formatting it as a plain
        // infix op would print the dummy `rhs` as literal "unresolved"
        // text (`"a == b ! unresolved"` instead of `"!(a == b)"`).
        IRExpression::BinaryOp { op, lhs, .. } if op == "!" => {
            format!("!({})", ir_expr_to_display(lhs))
        }
        IRExpression::BinaryOp { op, lhs, rhs } => {
            format!(
                "{} {} {}",
                ir_expr_to_display(lhs),
                op,
                ir_expr_to_display(rhs)
            )
        }
        IRExpression::Call {
            target,
            method: Some(m),
            arguments,
        } => {
            let args = arguments
                .iter()
                .map(ir_expr_to_display)
                .collect::<Vec<_>>()
                .join(", ");
            format!("{}.{}({})", ir_expr_to_display(target), m, args)
        }
        IRExpression::Call {
            target,
            method: None,
            arguments,
        } => {
            let args = arguments
                .iter()
                .map(ir_expr_to_display)
                .collect::<Vec<_>>()
                .join(", ");
            format!("{}({})", ir_expr_to_display(target), args)
        }
        IRExpression::Assign { left, right } => {
            format!(
                "{} = {}",
                ir_expr_to_display(left),
                ir_expr_to_display(right)
            )
        }
        IRExpression::Reference { expression, .. }
        | IRExpression::Dereference(expression)
        | IRExpression::Try(expression) => ir_expr_to_display(expression),
    }
}

fn collect_statements<'a>(stmts: &'a [StatementNode], out: &mut Vec<&'a StatementNode>) {
    for stmt in stmts {
        if let StatementKind::Block(inner) = &stmt.kind {
            collect_statements(inner, out);
        }
        out.push(stmt);
    }
}
