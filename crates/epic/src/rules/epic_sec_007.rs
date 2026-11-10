use crate::ast::{StatementKind, StatementNode};
use crate::cfg::guards::{parse_anchor_attribute_string, FactConfidence, ParsedAttributeMeta};
use crate::rules::{AnalysisContext, FindingLocation, Rule, RuleDiagnostic, RuleSeverity};
use crate::types::FieldDef;
use epic_ir::{IRExpression, IRInstruction};
use std::collections::{HashMap, HashSet};

/// EPIC-SEC-007: an account manually drained of lamports to close it,
/// without either Anchor's `close = <dest>` constraint or a manual
/// `CLOSED_ACCOUNT_DISCRIMINATOR` write — the sealevel-attacks
/// `closing-accounts` class. Zeroing lamports alone (even zeroing all data
/// bytes alongside it) doesn't stop the account from being "revived": the
/// runtime only purges a zero-lamport account at the end of the
/// *transaction*, so a later instruction in the same transaction can
/// refund rent and resurrect it with attacker-controlled data.
pub struct UnsafeAccountCloseRule;

impl Rule for UnsafeAccountCloseRule {
    fn id(&self) -> &'static str {
        "EPIC-SEC-007"
    }

    fn name(&self) -> &'static str {
        "Unsafe Manual Account Close"
    }

    fn check(&self, context: &AnalysisContext) -> Vec<RuleDiagnostic> {
        let mut diagnostics = Vec::new();
        let instruction_context = &context.instruction_context;
        let context_var = &instruction_context.context_var_name;

        let mut all_statements: Vec<&StatementNode> = Vec::new();
        for node in instruction_context.cfg.nodes_sorted() {
            collect_statements(&node.statements, &mut all_statements);
        }

        // Local `let x = ctx.accounts.<name>...` aliases (notably
        // `.to_account_info()`), so a drain performed through a local
        // binding still resolves back to the real account field.
        let mut aliases: HashMap<String, String> = HashMap::new();
        for stmt in &all_statements {
            if let StatementKind::Let {
                name, initializer, ..
            } = &stmt.kind
            {
                let ir = crate::ir_converter::convert_expr_node_to_ir(initializer);
                if let Some(account_name) = resolve_account_field(&ir, context_var, &aliases) {
                    aliases.insert(name.clone(), account_name);
                }
            }
        }

        let mut drained_accounts: Vec<(String, usize)> = Vec::new();
        // True once the function anywhere references the closed-account
        // sentinel — whether writing it (the manual-close idiom) or
        // reading it as an already-closed precondition before acting (e.g.
        // a permissionless "sweep any revived lamports" instruction, which
        // only ever runs after confirming the account was already marked
        // closed). Either shows the handler understands the sentinel, so
        // this rule has nothing further to add for either shape.
        let mut mentions_closed_discriminator = false;

        for stmt in &all_statements {
            for instr in crate::ir_converter::convert_statement_node_to_ir(stmt) {
                if let Some(target) = lamport_zero_target(&instr) {
                    if let Some(account_name) = resolve_account_field(target, context_var, &aliases)
                    {
                        drained_accounts.push((account_name, stmt.line_number));
                    }
                }
                if instruction_mentions_identifier(&instr, "CLOSED_ACCOUNT_DISCRIMINATOR") {
                    mentions_closed_discriminator = true;
                }
            }
        }

        // Branch conditions (`if discriminator != CLOSED_ACCOUNT_DISCRIMINATOR
        // { return Err(..) }`) live on CFG edges, not in any node's
        // statement list — a plain statement scan never sees them.
        if !mentions_closed_discriminator {
            for edge in &instruction_context.cfg.edges {
                if let Some(cond) = &edge.ir_condition {
                    if expr_mentions_identifier(cond, "CLOSED_ACCOUNT_DISCRIMINATOR") {
                        mentions_closed_discriminator = true;
                        break;
                    }
                }
            }
        }

        if drained_accounts.is_empty() {
            return diagnostics;
        }

        let struct_name = &instruction_context.context_struct_name;
        let struct_match = crate::audit::resolve_accounts_struct(
            &context.ast_graph.registry,
            &context.program_metadata.name,
            &instruction_context.module_path,
            &instruction_context.file_path,
            struct_name,
            instruction_context.impl_type.as_deref(),
        );
        let Some((struct_path, s_def)) = struct_match else {
            return diagnostics;
        };
        let file_path = context
            .ast_graph
            .registry
            .file_paths
            .get(struct_path)
            .cloned()
            .unwrap_or_else(|| instruction_context.file_path.clone());

        let mut seen = HashSet::new();
        for (account_name, line) in drained_accounts {
            if !seen.insert(account_name.clone()) {
                continue;
            }

            let Some(field) = s_def.fields.iter().find(|f| f.name == account_name) else {
                continue;
            };

            if field_has_close_constraint(field) {
                continue; // Anchor's `close = ` already does this safely.
            }
            if mentions_closed_discriminator {
                continue; // manually re-implements the safe close idiom.
            }

            let Some(&field_sym) = instruction_context.symbol_table.get(&account_name) else {
                continue;
            };

            diagnostics.push(RuleDiagnostic {
                rule_id: self.id().to_string(),
                severity: RuleSeverity::Critical,
                message: format!(
                    "Account '{}' has its lamports manually drained to close it, but neither Anchor's `close = <dest>` constraint nor a manual `CLOSED_ACCOUNT_DISCRIMINATOR` write marks it closed — it can be revived within the same transaction by refunding rent before the runtime purges it",
                    account_name
                ),
                location: FindingLocation {
                    file: file_path.clone(),
                    line,
                    column: field.column_number,
                    node_id: 0,
                    statement_index: None,
                },
                confidence: FactConfidence::Asserted,
                target_symbol: field_sym,
                witness: None,
            });
        }

        diagnostics.sort_by_key(|d| d.location.line);
        diagnostics
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

fn field_has_close_constraint(field: &FieldDef) -> bool {
    field.attrs.iter().any(|attr| {
        parse_anchor_attribute_string(attr)
            .iter()
            .any(|meta| matches!(meta, ParsedAttributeMeta::Close(_)))
    })
}

/// Resolves `expr` to the `Accounts` struct field it ultimately refers to:
/// either a direct `ctx.accounts.<name>` access, or a local variable
/// previously aliased to one (see `aliases`). Transparent to `?`, `&`/`&mut`,
/// `*`, and any method call in between (`.to_account_info()`, `.clone()`, …) —
/// those change representation, not identity.
fn resolve_account_field(
    expr: &IRExpression,
    context_var: &str,
    aliases: &HashMap<String, String>,
) -> Option<String> {
    match expr {
        IRExpression::Try(inner) => resolve_account_field(inner, context_var, aliases),
        IRExpression::Reference { expression, .. } => {
            resolve_account_field(expression, context_var, aliases)
        }
        IRExpression::Dereference(inner) => resolve_account_field(inner, context_var, aliases),
        IRExpression::Call { target, .. } => resolve_account_field(target, context_var, aliases),
        IRExpression::Variable(name) => aliases.get(name).cloned(),
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
            resolve_account_field(object, context_var, aliases)
        }
        _ => None,
    }
}

/// `**<account-ish-expr>.lamports.borrow_mut() = 0` — the manual
/// lamport-drain idiom. Returns the drained expression (still needs
/// resolving back to an account field by the caller).
fn lamport_zero_target(instr: &IRInstruction) -> Option<&IRExpression> {
    let IRInstruction::Expr(expr) = instr else {
        return None;
    };
    let IRExpression::Assign { left, right } = expr else {
        return None;
    };
    let is_zero = matches!(right.as_ref(), IRExpression::Literal(s) if s.trim() == "0");
    if !is_zero {
        return None;
    }
    lamports_borrow_mut_target(left)
}

fn lamports_borrow_mut_target(expr: &IRExpression) -> Option<&IRExpression> {
    match expr {
        IRExpression::Dereference(inner) => lamports_borrow_mut_target(inner),
        IRExpression::Call {
            method: Some(m),
            target,
            ..
        } if m == "borrow_mut" || m == "try_borrow_mut" => {
            if let IRExpression::FieldAccess { object, field } = target.as_ref() {
                if field == "lamports" {
                    return Some(object);
                }
            }
            None
        }
        _ => None,
    }
}

fn instruction_mentions_identifier(instr: &IRInstruction, needle: &str) -> bool {
    match instr {
        IRInstruction::Expr(expr) => expr_mentions_identifier(expr, needle),
        IRInstruction::Assignment(assign) => expr_mentions_identifier(&assign.value, needle),
        _ => false,
    }
}

fn expr_mentions_identifier(expr: &IRExpression, needle: &str) -> bool {
    match expr {
        IRExpression::Variable(name) | IRExpression::Literal(name) => name.contains(needle),
        IRExpression::FieldAccess { object, field } => {
            field.contains(needle) || expr_mentions_identifier(object, needle)
        }
        IRExpression::BinaryOp { lhs, rhs, .. } => {
            expr_mentions_identifier(lhs, needle) || expr_mentions_identifier(rhs, needle)
        }
        IRExpression::Call {
            target, arguments, ..
        } => {
            expr_mentions_identifier(target, needle)
                || arguments
                    .iter()
                    .any(|a| expr_mentions_identifier(a, needle))
        }
        IRExpression::Assign { left, right } => {
            expr_mentions_identifier(left, needle) || expr_mentions_identifier(right, needle)
        }
        IRExpression::Reference { expression, .. }
        | IRExpression::Dereference(expression)
        | IRExpression::Try(expression) => expr_mentions_identifier(expression, needle),
    }
}
