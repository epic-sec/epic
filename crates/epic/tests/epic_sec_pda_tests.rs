//! Unit tests for EPIC-SEC-PDA (PDA Derivation and Bump Canonicality rule).
//!
//! Test coverage:
//!   1. Canonical bump (`bump: None`) → no finding.
//!   2. Stored-bump field (`bump = some_account.bump`) → no finding.
//!   3. Caller-supplied bump (`bump = ix_data.bump`) → CRITICAL finding.
//!   4. PDA-named account WITHOUT a PDA fact → CRITICAL finding.
//!   5. Normal non-PDA account (no PDA name, no PDA fact) → no finding.

use epic::cfg::{
    ControlFlowGraph, FactConfidence, FactExpression, FactProvenance, GuardFact, GuardTarget,
    InstructionAnalysisContext, SSAVersionId, SymbolId,
};
use epic::rules::epic_sec_pda::PdaDerivationRule;
use epic::rules::{AnalysisContext, ProgramMetadata, Rule, RuleSeverity};
use epic::types::{FieldDef, StructDef, TypeDef, TypeRef, TypeRegistry};
use epic::Workspace;
use std::collections::{HashMap, HashSet};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn make_field(name: &str) -> FieldDef {
    FieldDef {
        name: name.to_string(),
        type_ref: TypeRef::Custom("Account<'info, SomeState>".to_string()),
        attrs: vec![],
        line_number: 10,
        column_number: 5,
    }
}

fn make_pda_fact(sym: SymbolId, bump: Option<FactExpression>) -> (GuardFact, FactProvenance) {
    (
        GuardFact::PDA {
            account: GuardTarget::Account(sym),
            seeds: vec![FactExpression::Literal("[b\"prefix\"]".to_string())],
            bump,
        },
        FactProvenance {
            source_file: "lib.rs".to_string(),
            line_number: 10,
            column_number: 5,
            framework: "Anchor".to_string(),
            confidence_level: FactConfidence::Declared,
            node_id: None,
            statement_index: None,
        },
    )
}

fn build_context(
    fields: Vec<FieldDef>,
    guard_facts: Vec<(GuardFact, FactProvenance)>,
    symbol_table: HashMap<String, SymbolId>,
    account_field_ids: HashSet<SymbolId>,
) -> AnalysisContext {
    let struct_def = StructDef {
        name: "TestAccounts".to_string(),
        fields,
        attrs: vec![],
        is_account: false,
    };

    let mut registry = TypeRegistry::new();
    registry
        .definitions
        .insert("TestAccounts".to_string(), TypeDef::Struct(struct_def));
    registry
        .file_paths
        .insert("TestAccounts".to_string(), "lib.rs".to_string());

    let instruction_context = InstructionAnalysisContext {
        name: "test_ix".to_string(),
        guard_facts,
        cfg: ControlFlowGraph::default(),
        symbol_table,
        account_field_ids,
        file_path: "lib.rs".to_string(),
        context_var_name: "ctx".to_string(),
        context_struct_name: "TestAccounts".to_string(),
    };

    AnalysisContext {
        program_metadata: ProgramMetadata {
            name: "test".to_string(),
            address: None,
        },
        idl_metadata: None,
        ast_graph: Workspace { registry },
        instruction_context,
        rule_registry: vec![],
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: Canonical bump (bump: None) — no finding expected
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_canonical_bump_no_finding() {
    let sym = SymbolId(1);
    let mut symbol_table = HashMap::new();
    symbol_table.insert("user_pda".to_string(), sym);
    let mut account_field_ids = HashSet::new();
    account_field_ids.insert(sym);

    // Canonical bump: bump = None (bare `bump` keyword in attribute)
    let facts = vec![make_pda_fact(sym, None)];

    let context = build_context(
        vec![make_field("user_pda")],
        facts,
        symbol_table,
        account_field_ids,
    );

    let rule = PdaDerivationRule;
    let diagnostics = rule.check(&context);

    assert!(
        diagnostics.is_empty(),
        "Canonical bump should produce no findings, got: {:?}",
        diagnostics
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: Stored-bump field reference — no finding expected
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_stored_bump_field_no_finding() {
    let sym = SymbolId(2);
    let mut symbol_table = HashMap::new();
    symbol_table.insert("state_pda".to_string(), sym);
    let mut account_field_ids = HashSet::new();
    account_field_ids.insert(sym);

    // Stored bump: `bump = state_pda.bump` — state_pda is a known account field.
    // The classifier should recognise it as stored-on-chain and suppress the finding.
    let stored_bump = FactExpression::Literal("state_pda.bump".to_string());
    let facts = vec![make_pda_fact(sym, Some(stored_bump))];

    let context = build_context(
        vec![make_field("state_pda")],
        facts,
        symbol_table,
        account_field_ids,
    );

    let rule = PdaDerivationRule;
    let diagnostics = rule.check(&context);

    assert!(
        diagnostics.is_empty(),
        "Stored bump (.bump field on known account) should produce no findings, got: {:?}",
        diagnostics
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: Caller-supplied bump → CRITICAL finding
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_caller_supplied_bump_finding() {
    let sym = SymbolId(3);
    let mut symbol_table = HashMap::new();
    symbol_table.insert("vault_pda".to_string(), sym);
    let mut account_field_ids = HashSet::new();
    account_field_ids.insert(sym);

    // Caller-supplied bump: `bump = ix_data.bump` — ix_data is instruction input,
    // not a stored on-chain value.
    let caller_bump = FactExpression::Literal("ix_data.bump".to_string());
    let facts = vec![make_pda_fact(sym, Some(caller_bump))];

    let context = build_context(
        vec![make_field("vault_pda")],
        facts,
        symbol_table,
        account_field_ids,
    );

    let rule = PdaDerivationRule;
    let diagnostics = rule.check(&context);

    assert_eq!(
        diagnostics.len(),
        1,
        "Caller-supplied bump should produce exactly 1 finding, got: {:?}",
        diagnostics
    );
    assert_eq!(diagnostics[0].severity, RuleSeverity::Critical);
    assert!(diagnostics[0].rule_id.contains("EPIC-SEC-PDA"));
    assert!(
        diagnostics[0].message.contains("caller-supplied"),
        "Message should mention 'caller-supplied': {}",
        diagnostics[0].message
    );
    assert!(
        diagnostics[0].message.contains("vault_pda"),
        "Message should mention account name: {}",
        diagnostics[0].message
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: PDA-named account with no PDA fact → CRITICAL finding
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_pda_named_account_without_pda_fact_finding() {
    let sym = SymbolId(4);
    let mut symbol_table = HashMap::new();
    symbol_table.insert("escrow_pda".to_string(), sym);
    let mut account_field_ids = HashSet::new();
    account_field_ids.insert(sym);

    // No GuardFact::PDA for this account at all.
    let context = build_context(
        vec![make_field("escrow_pda")],
        vec![], // no guard facts
        symbol_table,
        account_field_ids,
    );

    let rule = PdaDerivationRule;
    let diagnostics = rule.check(&context);

    assert_eq!(
        diagnostics.len(),
        1,
        "PDA-named account without PDA fact should produce exactly 1 finding, got: {:?}",
        diagnostics
    );
    assert_eq!(diagnostics[0].severity, RuleSeverity::Critical);
    assert!(diagnostics[0].rule_id.contains("EPIC-SEC-PDA"));
    assert!(
        diagnostics[0]
            .message
            .contains("without PDA derivation constraint"),
        "Message should mention missing constraint: {}",
        diagnostics[0].message
    );
    assert!(
        diagnostics[0].message.contains("escrow_pda"),
        "Message should mention account name: {}",
        diagnostics[0].message
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5: Normal non-PDA account → no finding (false positive sanity check)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_normal_non_pda_account_no_finding() {
    let sym = SymbolId(5);
    let mut symbol_table = HashMap::new();
    // "user" — no PDA-like name pattern, no PDA fact expected
    symbol_table.insert("user".to_string(), sym);
    let mut account_field_ids = HashSet::new();
    account_field_ids.insert(sym);

    // No guard facts — but "user" doesn't trigger PDA heuristic
    let context = build_context(
        vec![make_field("user")],
        vec![],
        symbol_table,
        account_field_ids,
    );

    let rule = PdaDerivationRule;
    let diagnostics = rule.check(&context);

    assert!(
        diagnostics.is_empty(),
        "Regular non-PDA-named account should produce no findings, got: {:?}",
        diagnostics
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 6: Multiple accounts — pda_named + canonical PDA + caller-supplied bump
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_mixed_accounts() {
    let sym_good = SymbolId(10); // canonical bump → no finding
    let sym_bad_bump = SymbolId(11); // caller-supplied bump → finding
    let sym_no_fact = SymbolId(12); // pda name, no fact → finding
    let sym_normal = SymbolId(13); // normal account → no finding

    let mut symbol_table = HashMap::new();
    symbol_table.insert("good_pda".to_string(), sym_good);
    symbol_table.insert("bad_bump_pda".to_string(), sym_bad_bump);
    symbol_table.insert("raw_pda".to_string(), sym_no_fact);
    symbol_table.insert("authority".to_string(), sym_normal);

    let mut account_field_ids = HashSet::new();
    account_field_ids.insert(sym_good);
    account_field_ids.insert(sym_bad_bump);
    account_field_ids.insert(sym_no_fact);
    account_field_ids.insert(sym_normal);

    let facts = vec![
        make_pda_fact(sym_good, None), // canonical
        make_pda_fact(
            sym_bad_bump,
            Some(FactExpression::Literal("ctx.accounts.args.bump_override".to_string())),
        ),
        // sym_no_fact intentionally has no PDA fact
    ];

    let fields = vec![
        make_field("good_pda"),
        make_field("bad_bump_pda"),
        make_field("raw_pda"),
        make_field("authority"),
    ];

    let context = build_context(fields, facts, symbol_table, account_field_ids);

    let rule = PdaDerivationRule;
    let mut diagnostics = rule.check(&context);

    // Expect exactly 2 findings: caller-supplied bump + missing PDA fact
    assert_eq!(
        diagnostics.len(),
        2,
        "Expected 2 findings (caller bump + missing PDA fact), got: {:?}",
        diagnostics
    );

    // All findings should be CRITICAL
    for d in &diagnostics {
        assert_eq!(d.severity, RuleSeverity::Critical);
        assert_eq!(d.rule_id, "EPIC-SEC-PDA");
    }

    // Verify we have one of each type
    let has_caller_supplied = diagnostics
        .iter()
        .any(|d| d.message.contains("caller-supplied"));
    let has_missing_constraint = diagnostics
        .iter()
        .any(|d| d.message.contains("without PDA derivation constraint"));

    assert!(
        has_caller_supplied,
        "Should have a caller-supplied bump finding"
    );
    assert!(
        has_missing_constraint,
        "Should have a missing PDA constraint finding"
    );
}
