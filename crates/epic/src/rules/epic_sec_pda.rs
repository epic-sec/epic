use crate::cfg::guards::{FactConfidence, FactExpression, GuardFact, GuardTarget, SymbolId};
use crate::rules::{AnalysisContext, FindingLocation, Rule, RuleDiagnostic, RuleSeverity};
use std::collections::HashMap;

/// EPIC-SEC-PDA — Consolidated PDA Derivation and Bump Canonicality Rule.
///
/// Sub-check 1 (Missing PDA Derivation Gate):
///   For each account in the Anchor `#[derive(Accounts)]` struct, if the field
///   name strongly suggests it is a PDA (e.g. contains "pda") but no
///   `GuardFact::PDA` was extracted for it, fire a CRITICAL finding.
///
/// Sub-check 2 (Non-Canonical Bump):
///   For each `GuardFact::PDA { bump, .. }`, classify the bump:
///   - `bump: None`                  → bare `bump` keyword, canonical, SAFE.
///   - `bump: Some(expr)` where expr resolves to a stored-bump field (e.g.
///     `some_account.bump`) → stored-bump, SAFE.
///   - `bump: Some(expr)` otherwise  → caller-supplied (instruction data), UNSAFE.
pub struct PdaDerivationRule;

// ─────────────────────────────────────────────────────────────────────────────
// Bump classification helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Known instruction-data/argument container name prefixes.
/// Bumps coming from these are caller-supplied — always unsafe.
const INSTRUCTION_DATA_PREFIXES: &[&str] = &[
    "ix", "args", "params", "data", "instruction", "input", "inputs", "request",
];

/// Returns `true` when the base object of a `.bump` field access looks like an
/// instruction-data container (and thus the bump is caller-supplied).
fn object_is_instruction_data(object_name: &str) -> bool {
    let n = object_name.trim().to_lowercase();
    INSTRUCTION_DATA_PREFIXES
        .iter()
        .any(|prefix| n == *prefix || n.starts_with(&format!("{}_", prefix)) || n.ends_with(&format!("_{}", prefix)))
}

/// Returns `true` when `expr` looks like a stored-on-chain bump reference.
///
/// Canonical rule:
/// - `bump` alone (the identifier) → stored-canonical, safe.
/// - `<account_field>.bump` where `<account_field>` is a known Anchor account → stored, safe.
/// - `<instruction_data_container>.bump` → caller-supplied, unsafe.
/// - Anything else → treat conservatively as caller-supplied.
fn is_stored_bump_expr(expr: &FactExpression, symbol_table: &HashMap<String, SymbolId>) -> bool {
    match expr {
        // SolanaProperty enum has no Bump variant; treat as unsafe.
        FactExpression::PropertyOf { .. } => false,

        FactExpression::Literal(val) => {
            let v = val.trim();
            // Bare "bump" identifier → canonical, safe.
            if v == "bump" {
                return true;
            }
            // "object.bump" pattern.
            if let Some(object) = v.strip_suffix(".bump") {
                // object must be a known account field (in symbol_table) AND not an
                // instruction-data container to be considered stored.
                let is_account = symbol_table.contains_key(object);
                let is_ix_data = object_is_instruction_data(object);
                return is_account && !is_ix_data;
            }
            false
        }

        FactExpression::Target(target) => match target {
            GuardTarget::Literal(name) => {
                let n = name.trim();
                if n == "bump" {
                    return true;
                }
                if let Some(object) = n.strip_suffix(".bump") {
                    let is_account = symbol_table.contains_key(object);
                    let is_ix_data = object_is_instruction_data(object);
                    return is_account && !is_ix_data;
                }
                false
            }
            // Variable / Account targets correspond to account-level symbols;
            // conservatively safe (they reference on-chain data).
            _ => true,
        },

        // Binary-op bump expressions are unusual; treat as unsafe.
        FactExpression::BinaryOp { .. } => false,

        FactExpression::Unknown => false,
    }
}

fn is_caller_supplied_bump(expr: &FactExpression, symbol_table: &HashMap<String, SymbolId>) -> bool {
    !is_stored_bump_expr(expr, symbol_table)
}

// ─────────────────────────────────────────────────────────────────────────────
// Reverse-lookup: SymbolId → field name
// ─────────────────────────────────────────────────────────────────────────────

fn symbol_name(target: &GuardTarget, symbol_table: &HashMap<String, SymbolId>) -> Option<String> {
    let sym_id = target.symbol_id()?;
    symbol_table
        .iter()
        .find(|(_, &v)| v == sym_id)
        .map(|(k, _)| k.clone())
}

// ─────────────────────────────────────────────────────────────────────────────
// PDA name heuristic — conservative to avoid false positives
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` when a field name strongly suggests it is a PDA account.
/// Deliberately conservative: only "pda" substring patterns.
fn name_looks_like_pda(name: &str) -> bool {
    let n = name.to_lowercase();
    n == "pda"
        || n.starts_with("pda_")
        || n.ends_with("_pda")
        || n.contains("_pda_")
}

// ─────────────────────────────────────────────────────────────────────────────
// Rule implementation
// ─────────────────────────────────────────────────────────────────────────────

impl Rule for PdaDerivationRule {
    fn id(&self) -> &'static str {
        "EPIC-SEC-PDA"
    }

    fn name(&self) -> &'static str {
        "PDA Derivation and Bump Canonicality"
    }

    fn check(&self, context: &AnalysisContext) -> Vec<RuleDiagnostic> {
        let mut diagnostics = Vec::new();
        let instruction_context = &context.instruction_context;
        let struct_name = &instruction_context.context_struct_name;

        // Locate the context struct definition using the file-aware, deterministic helper.
        // This correctly handles same-named structs in different modules by preferring
        // the struct in the same file or directory as the instruction.
        let struct_match = crate::audit::find_struct_for_context(
            &context.ast_graph.registry,
            struct_name,
            &instruction_context.file_path,
        );

        // ─────────────────────────────────────────────────────────────────────
        // Sub-check 1: Missing PDA derivation gate
        // ─────────────────────────────────────────────────────────────────────
        if let Some((struct_path, struct_def)) = struct_match {
            let file_path = context
                .ast_graph
                .registry
                .file_paths
                .get(struct_path)
                .cloned()
                .unwrap_or_else(|| instruction_context.file_path.clone());

            for field in &struct_def.fields {
                // Gate: only real Anchor account fields.
                let field_sym = match instruction_context.symbol_table.get(&field.name) {
                    Some(&s) => s,
                    None => continue,
                };
                if !instruction_context.account_field_ids.contains(&field_sym) {
                    continue;
                }

                // Heuristic: does the name strongly suggest PDA?
                if !name_looks_like_pda(&field.name) {
                    continue;
                }

                // Is a PDA fact already present for this account?
                let has_pda_fact =
                    instruction_context.guard_facts.iter().any(|(fact, _)| {
                        matches!(fact, GuardFact::PDA { account, .. }
                            if account.symbol_id() == Some(field_sym))
                    });

                if !has_pda_fact {
                    diagnostics.push(RuleDiagnostic {
                        rule_id: self.id().to_string(),
                        severity: RuleSeverity::Critical,
                        message: format!(
                            "Account '{}' declared without PDA derivation constraint. \
                             Add `seeds = [...]` and `bump` to the `#[account(...)]` \
                             attribute to prevent account substitution attacks.",
                            field.name
                        ),
                        location: FindingLocation {
                            file: file_path.clone(),
                            line: field.line_number,
                            column: field.column_number,
                            node_id: 0,
                            statement_index: None,
                        },
                        confidence: FactConfidence::Asserted,
                        target_symbol: field_sym,
                    });
                }
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // Sub-check 2: Non-canonical (caller-supplied) bump detection
        // ─────────────────────────────────────────────────────────────────────
        for (fact, provenance) in &instruction_context.guard_facts {
            if let GuardFact::PDA {
                account,
                bump: Some(bump_expr),
                ..
            } = fact
            {
                if is_caller_supplied_bump(bump_expr, &instruction_context.symbol_table) {
                    let account_name = symbol_name(account, &instruction_context.symbol_table)
                        .unwrap_or_else(|| "<unknown>".to_string());

                    diagnostics.push(RuleDiagnostic {
                        rule_id: self.id().to_string(),
                        severity: RuleSeverity::Critical,
                        message: format!(
                            "PDA bump for '{}' is caller-supplied — use canonical bump \
                             derivation, not a caller-provided value. Replace `bump = {}` \
                             with bare `bump` (or store the canonical bump and load it from \
                             the account's own field).",
                            account_name,
                            fact_expr_to_string(bump_expr),
                        ),
                        location: FindingLocation {
                            file: provenance.source_file.clone(),
                            line: provenance.line_number,
                            column: provenance.column_number,
                            node_id: provenance.node_id.unwrap_or(0),
                            statement_index: provenance.statement_index,
                        },
                        confidence: FactConfidence::Asserted,
                        target_symbol: account.symbol_id().unwrap_or(SymbolId(0)),
                    });
                }
            }
        }

        diagnostics
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Display helpers
// ─────────────────────────────────────────────────────────────────────────────

fn fact_expr_to_string(expr: &FactExpression) -> String {
    match expr {
        FactExpression::Literal(s) => s.clone(),
        FactExpression::Target(t) => match t {
            GuardTarget::Literal(s) => s.clone(),
            GuardTarget::Variable(v) => format!("<var:{}>", v.symbol_id.0),
            GuardTarget::Account(s) => format!("<account:{}>", s.0),
        },
        FactExpression::PropertyOf { target, .. } => match target {
            GuardTarget::Literal(s) => format!("{}.property", s),
            GuardTarget::Variable(v) => format!("<var:{}>.property", v.symbol_id.0),
            GuardTarget::Account(s) => format!("<account:{}>.property", s.0),
        },
        FactExpression::BinaryOp { op, lhs, rhs } => format!(
            "{} {} {}",
            fact_expr_to_string(lhs),
            op,
            fact_expr_to_string(rhs)
        ),
        FactExpression::Unknown => "<unknown>".to_string(),
    }
}
