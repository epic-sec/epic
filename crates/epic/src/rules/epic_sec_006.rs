use crate::cfg::guards::{parse_anchor_attribute_string, FactConfidence, ParsedAttributeMeta};
use crate::cfg::ControlFlowGraph;
use crate::rules::{AnalysisContext, FindingLocation, Rule, RuleDiagnostic, RuleSeverity};
use crate::types::{FieldDef, StructDef, TypeDef, TypeRef};
use epic_ir::IRExpression;
use std::collections::HashMap;

/// EPIC-SEC-006: two `Accounts` struct fields of the same program-defined
/// `#[account]` type, with no constraint proving they can't be the same
/// pubkey — the `duplicate-mutable-accounts` class from sealevel-attacks.
/// A caller passing the same account for both lets one write clobber or
/// read back the other, depending on what the handler does with them.
pub struct DuplicateMutableAccountsRule;

impl Rule for DuplicateMutableAccountsRule {
    fn id(&self) -> &'static str {
        "EPIC-SEC-006"
    }

    fn name(&self) -> &'static str {
        "Duplicate Mutable Accounts"
    }

    fn check(&self, context: &AnalysisContext) -> Vec<RuleDiagnostic> {
        let mut diagnostics = Vec::new();
        let instruction_context = &context.instruction_context;
        let struct_name = &instruction_context.context_struct_name;

        let struct_match = crate::audit::find_struct_for_context(
            &context.ast_graph.registry,
            struct_name,
            &instruction_context.file_path,
        );
        let (struct_path, s_def) = match struct_match {
            Some(pair) => pair,
            None => return diagnostics,
        };

        let file_path = context
            .ast_graph
            .registry
            .file_paths
            .get(struct_path)
            .cloned()
            .unwrap_or_else(|| instruction_context.file_path.clone());

        // Group fields by the program-defined account type they share.
        // Builtin/SPL types (TokenAccount, Mint, Signer, ...) never resolve
        // to a struct in this workspace's registry, so they're naturally
        // excluded without needing a denylist.
        let mut groups: HashMap<String, Vec<&FieldDef>> = HashMap::new();
        for field in &s_def.fields {
            if let Some(type_name) = custom_account_type_name(&field.type_ref) {
                if is_user_defined_account_type(&context.ast_graph.registry, &type_name) {
                    groups.entry(type_name).or_default().push(field);
                }
            }
        }

        for (type_name, fields) in groups {
            if fields.len() < 2 {
                continue;
            }
            for i in 0..fields.len() {
                for j in (i + 1)..fields.len() {
                    let a = fields[i];
                    let b = fields[j];

                    // A PDA's address is already determined by its seeds. Two
                    // PDA fields of the same type are structurally distinct
                    // as long as their seeds differ, which is the common
                    // case (per-user/per-resource state of the same shape) —
                    // flagging those would be exactly the false-positive
                    // class documented in KNOWN_LIMITATIONS.md. Seed
                    // collision itself is EPIC-SEC-004's job, not this rule's.
                    if has_seeds(a) || has_seeds(b) {
                        continue;
                    }

                    if pair_has_distinguishing_constraint(s_def, a, b) {
                        continue;
                    }

                    // Not every program expresses this declaratively. Orca's
                    // two_hop_swap guards whirlpool_one/whirlpool_two with a
                    // plain `if a.key() == b.key() { return Err(..) }` in the
                    // handler body instead of a struct constraint — measured
                    // directly against the 5-protocol sweep, this is exactly
                    // the shape that turns up in practice. Doesn't require
                    // the check to dominate every write (full dominance is
                    // SEC-002's job for a single account; this only needs to
                    // know the pair is guarded at all), so a presence check
                    // over the CFG's early-return edges is enough.
                    if pair_has_body_level_guard(&instruction_context.cfg, &a.name, &b.name) {
                        continue;
                    }

                    let Some(&field_sym) = instruction_context.symbol_table.get(&a.name) else {
                        continue;
                    };

                    diagnostics.push(RuleDiagnostic {
                        rule_id: self.id().to_string(),
                        severity: RuleSeverity::High,
                        message: format!(
                            "'{}' and '{}' are both '{}' accounts with no constraint proving they're distinct — a caller passing the same account for both can corrupt program state or bypass logic that assumes two different accounts",
                            a.name, b.name, type_name
                        ),
                        location: FindingLocation {
                            file: file_path.clone(),
                            line: a.line_number,
                            column: a.column_number,
                            node_id: 0,
                            statement_index: None,
                        },
                        confidence: FactConfidence::Asserted,
                        target_symbol: field_sym,
                        witness: None,
                    });
                }
            }
        }

        // Sort for deterministic output: HashMap iteration order is random.
        diagnostics.sort_by(|a, b| {
            a.location
                .line
                .cmp(&b.location.line)
                .then_with(|| a.message.cmp(&b.message))
        });

        diagnostics
    }
}

/// If `type_ref` is (or unwraps, via `Box<...>`, to) `Account<'info, X>`,
/// returns `X`'s bare name. `Box` is already unwrapped by the AST parser
/// before `type_ref` is built, so only the direct `Account<...>` shape
/// needs handling here.
fn custom_account_type_name(type_ref: &TypeRef) -> Option<String> {
    let TypeRef::Custom(raw) = type_ref else {
        return None;
    };
    let normalized = raw.replace(' ', "");
    let inner = normalized
        .strip_prefix("Account<")
        .and_then(|s| s.strip_suffix('>'))?;
    // inner is e.g. "'info,User" or "'info,some_mod::User"
    let last_segment = inner.rsplit(',').next()?;
    let bare_name = last_segment.rsplit("::").next()?;
    if bare_name.is_empty() || bare_name.starts_with('\'') {
        None
    } else {
        Some(bare_name.to_string())
    }
}

fn is_user_defined_account_type(registry: &crate::types::TypeRegistry, name: &str) -> bool {
    registry.definitions.values().any(|def| match def {
        TypeDef::Struct(s) => s.name == name && s.is_account,
        _ => false,
    })
}

fn has_seeds(field: &FieldDef) -> bool {
    field.attrs.iter().any(|attr| {
        parse_anchor_attribute_string(attr)
            .iter()
            .any(|meta| matches!(meta, ParsedAttributeMeta::Seeds(_)))
    })
}

/// A constraint on either field that compares `a`'s and `b`'s keys for
/// inequality — the sealevel-attacks `recommended` fix
/// (`constraint = user_a.key() != user_b.key()`) — proves the pair can
/// never alias.
fn pair_has_distinguishing_constraint(s_def: &StructDef, a: &FieldDef, b: &FieldDef) -> bool {
    s_def.fields.iter().any(|f| {
        f.attrs.iter().any(|attr| {
            parse_anchor_attribute_string(attr).iter().any(|meta| {
                if let ParsedAttributeMeta::Constraint(expr) = meta {
                    let text = quote::quote!(#expr).to_string().replace(' ', "");
                    text.contains(&a.name) && text.contains(&b.name) && text.contains("!=")
                } else {
                    false
                }
            })
        })
    })
}

/// The sealevel-attacks `secure` fix: an early-return guard in the handler
/// body itself, `if a.key() == b.key() { return Err(..) }`, rather than a
/// struct-level constraint. Looks for any CFG edge tagged
/// `is_early_return` whose branch condition is an `==` comparison
/// mentioning both field names — presence only, not dominance, which
/// matches this rule's existing precision level (the struct-constraint
/// check above isn't path-sensitive either).
fn pair_has_body_level_guard(cfg: &ControlFlowGraph, a: &str, b: &str) -> bool {
    cfg.edges.iter().any(|edge| {
        edge.is_early_return
            && edge
                .ir_condition
                .as_ref()
                .is_some_and(|cond| is_key_equality_check(cond, a, b))
    })
}

fn is_key_equality_check(expr: &IRExpression, a: &str, b: &str) -> bool {
    match expr {
        IRExpression::BinaryOp { op, lhs, rhs } if op == "==" => {
            (mentions_identifier(lhs, a) && mentions_identifier(rhs, b))
                || (mentions_identifier(lhs, b) && mentions_identifier(rhs, a))
        }
        _ => false,
    }
}

fn mentions_identifier(expr: &IRExpression, needle: &str) -> bool {
    match expr {
        IRExpression::Variable(name) | IRExpression::Literal(name) => name == needle,
        IRExpression::FieldAccess { object, field } => {
            field == needle || mentions_identifier(object, needle)
        }
        IRExpression::BinaryOp { lhs, rhs, .. } => {
            mentions_identifier(lhs, needle) || mentions_identifier(rhs, needle)
        }
        IRExpression::Call {
            target, arguments, ..
        } => {
            mentions_identifier(target, needle)
                || arguments.iter().any(|arg| mentions_identifier(arg, needle))
        }
        IRExpression::Assign { left, right } => {
            mentions_identifier(left, needle) || mentions_identifier(right, needle)
        }
        IRExpression::Reference { expression, .. }
        | IRExpression::Dereference(expression)
        | IRExpression::Try(expression) => mentions_identifier(expression, needle),
    }
}
