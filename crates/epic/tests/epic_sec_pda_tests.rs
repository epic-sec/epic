//! Unit tests for EPIC-SEC-PDA (PDA Derivation and Bump Canonicality rule).
//!
//! Test coverage:
//!   1. Canonical bump (`bump: None`) → no finding.
//!   2. Stored-bump field (`bump = some_account.bump`) → no finding.
//!   3. Caller-supplied bump (`bump = ix_data.bump`) → CRITICAL finding.
//!   4. Account used in `find_program_address`/`invoke_signed`/variable-
//!      indirected signer seeds, WITHOUT a PDA fact → CRITICAL finding.
//!      Deliberately named without any "pda" substring (`escrow`, `bank`,
//!      `vault`) to prove detection is usage-based, not name-based.
//!   4d. Account passed as a plain CPI argument (not the seeds slot) → no
//!      finding, confirming detection targets the seeds argument specifically.
//!   5. Normal non-PDA account (never referenced in a PDA call) → no finding.

use epic::ast::{ExpressionKind, ExpressionNode, StatementKind, StatementNode};
use epic::cfg::{
    CFGNode, ControlFlowGraph, FactConfidence, FactExpression, FactProvenance, GuardFact,
    GuardTarget, InstructionAnalysisContext, SymbolId,
};
use epic::rules::epic_sec_pda::PdaDerivationRule;
use epic::rules::{AnalysisContext, ProgramMetadata, Rule, RuleSeverity};
use epic::types::{FieldDef, StructDef, TypeDef, TypeRef, TypeRegistry};
use epic::Workspace;
use std::collections::{HashMap, HashSet};

// ─────────────────────────────────────────────────────────────────────────────
// Expression/CFG builder helpers — for constructing instruction bodies that
// exercise the usage-based PDA detection (find_program_address /
// create_program_address / invoke_signed / CpiContext::new_with_signer).
// ─────────────────────────────────────────────────────────────────────────────

fn ident(name: &str) -> ExpressionNode {
    ExpressionNode {
        kind: ExpressionKind::Identifier(name.to_string()),
    }
}

fn method_call(
    object: ExpressionNode,
    method: &str,
    arguments: Vec<ExpressionNode>,
) -> ExpressionNode {
    ExpressionNode {
        kind: ExpressionKind::MethodCall {
            object: Box::new(object),
            method: method.to_string(),
            arguments,
        },
    }
}

fn reference(expr: ExpressionNode) -> ExpressionNode {
    ExpressionNode {
        kind: ExpressionKind::Reference {
            expression: Box::new(expr),
            is_mutable: false,
        },
    }
}

fn array(elems: Vec<ExpressionNode>) -> ExpressionNode {
    ExpressionNode {
        kind: ExpressionKind::MethodCall {
            object: Box::new(ExpressionNode {
                kind: ExpressionKind::Unresolved,
            }),
            method: "array".to_string(),
            arguments: elems,
        },
    }
}

/// A free-function / associated-function call, e.g. `Pubkey::find_program_address(..)`
/// or `invoke_signed(..)` — matches how `syn::Expr::Call` lowers in the real IR.
fn call(func: &str, arguments: Vec<ExpressionNode>) -> ExpressionNode {
    ExpressionNode {
        kind: ExpressionKind::MethodCall {
            object: Box::new(ExpressionNode {
                kind: ExpressionKind::Unresolved,
            }),
            method: func.to_string(),
            arguments,
        },
    }
}

/// `account.key().as_ref()` — the common seed-element shape for PDA derivation.
fn key_as_ref(account: &str) -> ExpressionNode {
    method_call(method_call(ident(account), "key", vec![]), "as_ref", vec![])
}

fn semi(expr: ExpressionNode) -> StatementNode {
    StatementNode {
        kind: StatementKind::Semi(expr),
        line_number: 20,
    }
}

fn let_stmt(name: &str, initializer: ExpressionNode) -> StatementNode {
    StatementNode {
        kind: StatementKind::Let {
            name: name.to_string(),
            initializer,
            type_annotation: None,
            is_mutable: false,
        },
        line_number: 20,
    }
}

/// A single-node CFG whose entry node contains `statements` — enough for
/// EPIC-SEC-PDA's usage scan, which does not need real control flow.
fn single_node_cfg(statements: Vec<StatementNode>) -> ControlFlowGraph {
    let mut cfg = ControlFlowGraph::default();
    cfg.entry_node = 0;
    cfg.nodes.insert(
        0,
        CFGNode {
            id: 0,
            statements,
            ir_instructions: vec![],
        },
    );
    cfg
}

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
    build_context_with_cfg(
        fields,
        guard_facts,
        symbol_table,
        account_field_ids,
        ControlFlowGraph::default(),
    )
}

fn build_context_with_cfg(
    fields: Vec<FieldDef>,
    guard_facts: Vec<(GuardFact, FactProvenance)>,
    symbol_table: HashMap<String, SymbolId>,
    account_field_ids: HashSet<SymbolId>,
    cfg: ControlFlowGraph,
) -> AnalysisContext {
    build_context_full(
        fields,
        guard_facts,
        symbol_table,
        account_field_ids,
        cfg,
        "lib.rs".to_string(),
        "test_ix".to_string(),
    )
}

fn build_context_full(
    fields: Vec<FieldDef>,
    guard_facts: Vec<(GuardFact, FactProvenance)>,
    symbol_table: HashMap<String, SymbolId>,
    account_field_ids: HashSet<SymbolId>,
    cfg: ControlFlowGraph,
    file_path: String,
    fn_name: String,
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
        .insert("TestAccounts".to_string(), file_path.clone());

    let instruction_context = InstructionAnalysisContext {
        name: fn_name,
        guard_facts,
        cfg,
        symbol_table,
        account_field_ids,
        file_path,
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

/// Writes a standalone instruction function to a uniquely-named temp file, so
/// EPIC-SEC-PDA's manual-derivation detection (which re-parses the real
/// source file via `syn`, since `find_program_address` result comparisons
/// live in `if`-conditions and tuple-destructured `let`s the shared CFG/IR
/// does not preserve) has something real to read.
fn write_temp_instruction_source(unique: &str, fn_name: &str, body: &str) -> String {
    let path = std::env::temp_dir().join(format!("epic_sec_pda_test_{}.rs", unique));
    let content = format!(
        "pub fn {fn_name}(ctx: Context<TestAccounts>) -> Result<()> {{\n{body}\n    Ok(())\n}}\n"
    );
    std::fs::write(&path, content).expect("failed to write temp instruction source file");
    path.to_string_lossy().to_string()
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
// Test 4: account used in Pubkey::find_program_address, with no PDA fact
// → CRITICAL finding. Field is deliberately named "escrow" — no "pda"
// substring anywhere — to prove detection is usage-based, not name-based.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_pda_used_via_find_program_address_without_pda_fact_finding() {
    let sym = SymbolId(4);
    let mut symbol_table = HashMap::new();
    symbol_table.insert("escrow".to_string(), sym);
    let mut account_field_ids = HashSet::new();
    account_field_ids.insert(sym);

    // Manual-derivation detection re-parses the real source (see
    // `write_temp_instruction_source`'s doc comment), so the CFG here just
    // needs to exist — the actual signal comes from the file below.
    let file_path = write_temp_instruction_source(
        "find_program_address_without_fact",
        "test_ix",
        "let (expected, _bump) = Pubkey::find_program_address(&[b\"escrow\"], &crate::ID);\nif expected != ctx.accounts.escrow.key() {\nreturn Err(MyError::Invalid.into());\n}",
    );

    // No GuardFact::PDA for this account at all.
    let context = build_context_full(
        vec![make_field("escrow")],
        vec![], // no guard facts
        symbol_table,
        account_field_ids,
        ControlFlowGraph::default(),
        file_path,
        "test_ix".to_string(),
    );

    let rule = PdaDerivationRule;
    let diagnostics = rule.check(&context);

    // `find_program_address` is unconditionally canonical, so a manual
    // comparison against its result already rules out account-substitution
    // attacks. This is downgraded to a hardening recommendation (Warning),
    // not a vulnerability (Critical) — see sub-check 1's manual-validation
    // awareness fix.
    assert_eq!(
        diagnostics.len(),
        1,
        "Account verified against a manually derived PDA without a PDA fact should produce exactly 1 finding, got: {:?}",
        diagnostics
    );
    assert_eq!(diagnostics[0].severity, RuleSeverity::Warning);
    assert!(diagnostics[0].rule_id.contains("EPIC-SEC-PDA"));
    assert!(
        diagnostics[0].message.contains("find_program_address"),
        "Message should mention the canonical manual verification: {}",
        diagnostics[0].message
    );
    assert!(
        diagnostics[0].message.contains("escrow"),
        "Message should mention account name: {}",
        diagnostics[0].message
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4d-2: sealevel-attacks 7-bump-seed-canonicalization "insecure" shape —
// manual verification against a `create_program_address` result, where the
// bump is a plain caller-supplied argument, must stay CRITICAL. Unlike
// `find_program_address`, `create_program_address` blindly trusts whatever
// bump it's given, so a comparison against its result provides no protection
// against account substitution. This is the discrimination the manual-
// validation-awareness fix in sub-check 1 must preserve: it only downgrades
// `find_program_address`-verified accounts, never `create_program_address`.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_pda_used_via_create_program_address_stays_critical() {
    let sym = SymbolId(5);
    let mut symbol_table = HashMap::new();
    symbol_table.insert("data".to_string(), sym);
    let mut account_field_ids = HashSet::new();
    account_field_ids.insert(sym);

    let file_path = write_temp_instruction_source(
        "create_program_address_without_fact",
        "set_value",
        "let address = Pubkey::create_program_address(&[key.to_le_bytes().as_ref(), &[bump]], ctx.program_id)?;\nif address != ctx.accounts.data.key() {\nreturn Err(MyError::Invalid.into());\n}",
    );

    let context = build_context_full(
        vec![make_field("data")],
        vec![], // no guard facts
        symbol_table,
        account_field_ids,
        ControlFlowGraph::default(),
        file_path,
        "set_value".to_string(),
    );

    let rule = PdaDerivationRule;
    let diagnostics = rule.check(&context);

    assert_eq!(
        diagnostics.len(),
        1,
        "Account verified against a create_program_address result with a caller-supplied bump should still produce exactly 1 finding, got: {:?}",
        diagnostics
    );
    assert_eq!(
        diagnostics[0].severity,
        RuleSeverity::Critical,
        "create_program_address verification must NOT be downgraded — it doesn't rule out a forged bump"
    );
    assert!(
        diagnostics[0]
            .message
            .contains("without PDA derivation constraint"),
        "Message should still read as the standard missing-constraint finding: {}",
        diagnostics[0].message
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4e: find_program_address seed *ingredients* must NOT be flagged —
// only the account actually compared against the derived pubkey is the PDA.
// Regression test for the false-positive class found on marginfi/squads-v4
// during real-repo validation (seed ingredients like `mint`/`group`/`creator`
// were incorrectly flagged as "should be a PDA").
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_find_program_address_seed_ingredient_not_flagged() {
    let sym_ingredient = SymbolId(23); // "authority" — seed ingredient only
    let sym_derived = SymbolId(24); // "vault" — the actual derived/verified PDA

    let mut symbol_table = HashMap::new();
    symbol_table.insert("authority".to_string(), sym_ingredient);
    symbol_table.insert("vault".to_string(), sym_derived);

    let mut account_field_ids = HashSet::new();
    account_field_ids.insert(sym_ingredient);
    account_field_ids.insert(sym_derived);

    let file_path = write_temp_instruction_source(
        "seed_ingredient_not_flagged",
        "test_ix",
        "let (derived, _bump) = Pubkey::find_program_address(&[b\"vault\", ctx.accounts.authority.key().as_ref()], &crate::ID);\nif derived != ctx.accounts.vault.key() {\nreturn Err(MyError::Invalid.into());\n}",
    );

    // Neither account has a PDA fact — only "vault" should be flagged.
    let context = build_context_full(
        vec![make_field("authority"), make_field("vault")],
        vec![],
        symbol_table,
        account_field_ids,
        ControlFlowGraph::default(),
        file_path,
        "test_ix".to_string(),
    );

    let rule = PdaDerivationRule;
    let diagnostics = rule.check(&context);

    assert_eq!(
        diagnostics.len(),
        1,
        "Only the derived/verified account should be flagged, not seed ingredients: {:?}",
        diagnostics
    );
    assert!(
        diagnostics[0].message.contains("vault"),
        "Finding should name the derived account 'vault': {}",
        diagnostics[0].message
    );
    assert!(
        !diagnostics[0].message.contains("authority"),
        "Finding must not name the seed-ingredient account 'authority': {}",
        diagnostics[0].message
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4b: account used as the signer-seeds argument of invoke_signed, with
// no PDA fact → CRITICAL finding. Field named "bank" — again, no "pda"
// substring — matching the real-world mango-v4/orca-whirlpools style naming
// the naive name heuristic used to miss entirely.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_pda_used_via_invoke_signed_without_pda_fact_finding() {
    let sym = SymbolId(20);
    let mut symbol_table = HashMap::new();
    symbol_table.insert("bank".to_string(), sym);
    let mut account_field_ids = HashSet::new();
    account_field_ids.insert(sym);

    // invoke_signed(&ix, &account_infos, &[&[b"bank", bank.key().as_ref(), &[bump]]]);
    let cfg = single_node_cfg(vec![semi(call(
        "invoke_signed",
        vec![
            reference(ident("ix")),
            reference(ident("account_infos")),
            reference(array(vec![reference(array(vec![key_as_ref("bank")]))])),
        ],
    ))]);

    let context = build_context_with_cfg(
        vec![make_field("bank")],
        vec![],
        symbol_table,
        account_field_ids,
        cfg,
    );

    let rule = PdaDerivationRule;
    let diagnostics = rule.check(&context);

    assert_eq!(
        diagnostics.len(),
        1,
        "Account used as invoke_signed's signer seeds without a PDA fact should produce exactly 1 finding, got: {:?}",
        diagnostics
    );
    assert!(
        diagnostics[0].message.contains("bank"),
        "Message should mention account name: {}",
        diagnostics[0].message
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4c: signer seeds referenced through one level of local-variable
// indirection (the common `let seeds = &[...]; let signer_seeds =
// &[&seeds[..]];` pattern) — resolution must follow the `let` binding to
// find the account reference.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_pda_used_via_signer_seeds_variable_indirection_finding() {
    let sym = SymbolId(21);
    let mut symbol_table = HashMap::new();
    symbol_table.insert("vault".to_string(), sym);
    let mut account_field_ids = HashSet::new();
    account_field_ids.insert(sym);

    // let seeds = &[b"vault", vault.key().as_ref(), &[bump]];
    // let signer_seeds = &[&seeds[..]];
    // CpiContext::new_with_signer(cpi_program, cpi_accounts, signer_seeds);
    let cfg = single_node_cfg(vec![
        let_stmt("seeds", reference(array(vec![key_as_ref("vault")]))),
        let_stmt(
            "signer_seeds",
            reference(array(vec![reference(ident("seeds"))])),
        ),
        semi(call(
            "CpiContext::new_with_signer",
            vec![
                ident("cpi_program"),
                ident("cpi_accounts"),
                ident("signer_seeds"),
            ],
        )),
    ]);

    let context = build_context_with_cfg(
        vec![make_field("vault")],
        vec![],
        symbol_table,
        account_field_ids,
        cfg,
    );

    let rule = PdaDerivationRule;
    let diagnostics = rule.check(&context);

    assert_eq!(
        diagnostics.len(),
        1,
        "Account referenced only via local-variable indirection should still be found: {:?}",
        diagnostics
    );
    assert!(diagnostics[0].message.contains("vault"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4d: account passed as a plain CPI account (not in the signer-seeds
// slot) of CpiContext::new_with_signer → no finding. Confirms detection
// targets the seeds argument specifically, not every argument of a CPI call.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_account_as_cpi_account_not_seeds_no_finding() {
    let sym = SymbolId(22);
    let mut symbol_table = HashMap::new();
    symbol_table.insert("token_program".to_string(), sym);
    let mut account_field_ids = HashSet::new();
    account_field_ids.insert(sym);

    // CpiContext::new_with_signer(token_program, cpi_accounts, signer_seeds);
    // "token_program" sits in the *program* argument slot, not the seeds slot.
    let cfg = single_node_cfg(vec![semi(call(
        "CpiContext::new_with_signer",
        vec![
            ident("token_program"),
            ident("cpi_accounts"),
            reference(array(vec![reference(array(vec![key_as_ref("authority")]))])),
        ],
    ))]);

    let context = build_context_with_cfg(
        vec![make_field("token_program")],
        vec![],
        symbol_table,
        account_field_ids,
        cfg,
    );

    let rule = PdaDerivationRule;
    let diagnostics = rule.check(&context);

    assert!(
        diagnostics.is_empty(),
        "Account passed as a non-seeds CPI argument should not be flagged, got: {:?}",
        diagnostics
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
// Test 6: Multiple accounts — canonical PDA + caller-supplied bump + a
// usage-detected missing-derivation PDA ("vault", no "pda" in the name) +
// a normal account never referenced in any PDA call.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_mixed_accounts() {
    let sym_good = SymbolId(10); // canonical bump → no finding
    let sym_bad_bump = SymbolId(11); // caller-supplied bump → finding
    let sym_no_fact = SymbolId(12); // used as PDA in body, no fact → finding
    let sym_normal = SymbolId(13); // normal account, unused in any PDA call → no finding

    let mut symbol_table = HashMap::new();
    symbol_table.insert("good_pda".to_string(), sym_good);
    symbol_table.insert("bad_bump_pda".to_string(), sym_bad_bump);
    symbol_table.insert("vault".to_string(), sym_no_fact);
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
            Some(FactExpression::Literal(
                "ctx.accounts.args.bump_override".to_string(),
            )),
        ),
        // sym_no_fact ("vault") intentionally has no PDA fact
    ];

    let fields = vec![
        make_field("good_pda"),
        make_field("bad_bump_pda"),
        make_field("vault"),
        make_field("authority"),
    ];

    // "vault" is derived and verified via find_program_address in the
    // instruction body; "authority" never appears in any PDA-derivation/
    // signer-seeds call.
    let file_path = write_temp_instruction_source(
        "mixed_accounts",
        "test_ix",
        "let (derived, _bump) = Pubkey::find_program_address(&[b\"vault\"], &crate::ID);\nif derived != ctx.accounts.vault.key() {\nreturn Err(MyError::Invalid.into());\n}",
    );

    let context = build_context_full(
        fields,
        facts,
        symbol_table,
        account_field_ids,
        ControlFlowGraph::default(),
        file_path,
        "test_ix".to_string(),
    );

    let rule = PdaDerivationRule;
    let diagnostics = rule.check(&context);

    // Expect exactly 2 findings: caller-supplied bump + manual-verification
    // hardening recommendation for "vault" (canonically verified via
    // find_program_address in the body, so no longer CRITICAL).
    assert_eq!(
        diagnostics.len(),
        2,
        "Expected 2 findings (caller bump + vault hardening note), got: {:?}",
        diagnostics
    );

    for d in &diagnostics {
        assert_eq!(d.rule_id, "EPIC-SEC-PDA");
    }

    // Verify we have one of each type, at the right severity.
    let caller_supplied = diagnostics
        .iter()
        .find(|d| d.message.contains("caller-supplied"));
    let manual_verification = diagnostics
        .iter()
        .find(|d| d.message.contains("find_program_address"));

    assert!(
        matches!(caller_supplied, Some(d) if d.severity == RuleSeverity::Critical),
        "Should have a CRITICAL caller-supplied bump finding, got: {:?}",
        diagnostics
    );
    assert!(
        matches!(manual_verification, Some(d) if d.severity == RuleSeverity::Warning),
        "Should have a Warning-level manual-verification finding for 'vault', got: {:?}",
        diagnostics
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Full-pipeline regression tests: `bump = <account>.bump` (canonical stored
// bump, via a real `syn::Expr::Field` parse) vs. `bump = <bare instruction arg>`
// (caller-supplied). These run the real `epic::run_audit` pipeline against
// on-disk fixtures — unlike the synthetic-context tests above, this exercises
// the actual `#[account(...)]` attribute parser (`convert_syn_expr` in
// guards.rs), which is where the false positive on canonical stored bumps was
// found: any `x.bump` field access was converted to `FactExpression::PropertyOf`
// with no way to distinguish it from `x.owner`/`x.key`, and `is_stored_bump_expr`
// treated every `PropertyOf` as unconditionally caller-supplied.
// ─────────────────────────────────────────────────────────────────────────────

fn fixture_path(name: &str) -> String {
    format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name)
}

#[test]
fn test_pda_bump_canonical_fixture_is_clean() {
    let diagnostics = epic::run_audit(&fixture_path("pda-bump-canonical"))
        .expect("run_audit should succeed on a syntactically valid fixture");

    let pda_findings: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.rule_id == "EPIC-SEC-PDA")
        .collect();

    assert!(
        pda_findings.is_empty(),
        "bump = <account>.bump is the canonical safe pattern and must not be flagged, got: {:?}",
        pda_findings
    );
}

#[test]
fn test_pda_bump_seed_suffix_canonical_fixture_is_clean() {
    let diagnostics = epic::run_audit(&fixture_path("pda-bump-seed-suffix-canonical"))
        .expect("run_audit should succeed on a syntactically valid fixture");

    let pda_findings: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.rule_id == "EPIC-SEC-PDA")
        .collect();

    assert!(
        pda_findings.is_empty(),
        "bump = state.reserve_bump_seed (marinade's `_bump_seed` naming convention) \
         is a canonical safe stored bump and must not be flagged, got: {:?}",
        pda_findings
    );
}

#[test]
fn test_pda_bump_caller_supplied_fixture_flags() {
    let diagnostics = epic::run_audit(&fixture_path("pda-bump-caller-supplied"))
        .expect("run_audit should succeed on a syntactically valid fixture");

    let pda_findings: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.rule_id == "EPIC-SEC-PDA")
        .collect();

    assert_eq!(
        pda_findings.len(),
        1,
        "bump = <bare instruction arg> is genuinely caller-supplied and must be flagged exactly once, got: {:?}",
        pda_findings
    );
    assert_eq!(pda_findings[0].severity, RuleSeverity::Critical);
    assert!(
        pda_findings[0].message.contains("caller-supplied"),
        "message should say caller-supplied: {}",
        pda_findings[0].message
    );
    assert!(
        pda_findings[0].message.contains("multisig"),
        "message should name the account: {}",
        pda_findings[0].message
    );
    assert!(
        !pda_findings[0].message.contains(".property"),
        "message must not leak the internal '.property' debug token: {}",
        pda_findings[0].message
    );
    assert_ne!(
        pda_findings[0].location.line, 0,
        "location must be a real line, not the 0 placeholder"
    );
    assert!(
        pda_findings[0]
            .location
            .file
            .ends_with("pda-bump-caller-supplied/src/lib.rs"),
        "location must point at the real fixture file, not a hardcoded 'lib.rs': {}",
        pda_findings[0].location.file
    );
}
