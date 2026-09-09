use epic::ast::{ExpressionKind, ExpressionNode, StatementKind, StatementNode};
use epic::cfg::{
    CFGNode, ControlFlowGraph, FactConfidence, FactExpression, FactProvenance, GuardFact,
    GuardTarget, InstructionAnalysisContext, NodeSSAInfo, SSANodeState, SSAVariable,
    SolanaProperty, SymbolId,
};
use epic::rules::{OwnerValidationRule, RuleEngine};
use std::collections::HashMap;

#[test]
fn test_owner_validation_safe_vs_unsafe() {
    // 1. Setup variables
    let vault_symbol = SymbolId(1);
    let unchecked_symbol = SymbolId(2);

    // 2. Setup CFG with a single block containing statement writes
    // Statement 1: vault = 10;
    // Statement 2: unchecked = 20;
    let write_vault = StatementNode {
        kind: StatementKind::Expr(ExpressionNode {
            kind: ExpressionKind::Assign {
                left: Box::new(ExpressionNode {
                    kind: ExpressionKind::Identifier("vault".to_string()),
                }),
                right: Box::new(ExpressionNode {
                    kind: ExpressionKind::Literal("10".to_string()),
                }),
            },
        }),
        line_number: 10,
    };

    let write_unchecked = StatementNode {
        kind: StatementKind::Expr(ExpressionNode {
            kind: ExpressionKind::Assign {
                left: Box::new(ExpressionNode {
                    kind: ExpressionKind::Identifier("unchecked".to_string()),
                }),
                right: Box::new(ExpressionNode {
                    kind: ExpressionKind::Literal("20".to_string()),
                }),
            },
        }),
        line_number: 11,
    };

    let mut nodes = HashMap::new();
    nodes.insert(
        0,
        CFGNode {
            id: 0,
            ir_instructions: vec![],
            statements: vec![write_vault, write_unchecked],
        },
    );

    // Setup active SSA state for statements
    let mut ssa_states = HashMap::new();
    let mut active_variables = HashMap::new();
    active_variables.insert(
        "vault".to_string(),
        SSAVariable::Versioned {
            name: "vault".to_string(),
            version: 1,
        },
    );
    active_variables.insert(
        "unchecked".to_string(),
        SSAVariable::Versioned {
            name: "unchecked".to_string(),
            version: 1,
        },
    );

    let stmt_state = SSANodeState {
        active_variables,
        variable_types: HashMap::new(),
    };

    ssa_states.insert(
        0,
        NodeSSAInfo {
            start_state: stmt_state.clone(),
            statement_states: vec![stmt_state.clone(), stmt_state.clone()],
            end_state: stmt_state.clone(),
        },
    );

    let cfg = ControlFlowGraph {
        nodes,
        edges: Vec::new(),
        entry_node: 0,
        exit_nodes: vec![0],
        boundary_warnings: Vec::new(),
        ssa_states,
    };

    // 3. Setup guard facts (vault is checked, unchecked is not)
    let guard_facts = vec![
        (
            GuardFact::Owner {
                account: GuardTarget::Account(vault_symbol),
                expected_owner: FactExpression::Literal("program_id".to_string()),
            },
            FactProvenance {
                source_file: "lib.rs".to_string(),
                line_number: 1,
                column_number: 1,
                framework: "Anchor".to_string(),
                confidence_level: FactConfidence::Declared,
                node_id: None,
                statement_index: None,
            },
        ),
        (
            GuardFact::KeyRelation {
                account: GuardTarget::Account(unchecked_symbol),
                field: SolanaProperty::IsWritable,
                target: GuardTarget::Literal("true".to_string()),
            },
            FactProvenance {
                source_file: "lib.rs".to_string(),
                line_number: 1,
                column_number: 1,
                framework: "Anchor".to_string(),
                confidence_level: FactConfidence::Declared,
                node_id: None,
                statement_index: None,
            },
        ),
    ];

    let mut symbol_table = HashMap::new();
    symbol_table.insert("vault".to_string(), vault_symbol);
    symbol_table.insert("unchecked".to_string(), unchecked_symbol);

    let context = InstructionAnalysisContext {
        context_struct_name: "TestContext".to_string(),
        name: "test_instruction".to_string(),
        guard_facts,
        cfg,
        symbol_table,
        account_field_ids: Default::default(),
        file_path: "lib.rs".to_string(),
        context_var_name: "ctx".to_string(),
    };

    // 4. Register parameters inside resolver
    let mut engine = RuleEngine::new();
    engine.register_rule(Box::new(OwnerValidationRule));

    let analysis_context = epic::rules::AnalysisContext {
        program_metadata: epic::rules::ProgramMetadata {
            name: "test_program".to_string(),
            address: None,
        },
        idl_metadata: None,
        ast_graph: epic::Workspace::new(),
        instruction_context: context,
        rule_registry: Vec::new(),
    };

    let diagnostics = engine.run_all(&analysis_context);

    println!("DIAGNOSTICS: {:#?}", diagnostics);

    // Verify results:
    // - Write to `vault` is SAFE (0 findings for symbol 1)
    // - Write to `unchecked` is UNSAFE (1 finding for symbol 2)
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].target_symbol, unchecked_symbol);
    assert_eq!(diagnostics[0].rule_id, "EPIC-SEC-001");
}

#[test]
fn test_owner_validation_wdg_transitive() {
    // Test transitive mutability tracking:
    // let data = unchecked.try_borrow_mut_data();
    // let state = try_from_slice(&data);
    // state = 100; (write to state)
    let unchecked_symbol = SymbolId(1);
    let data_symbol = SymbolId(2);
    let state_symbol = SymbolId(3);

    // Statement 1: let data = unchecked.try_borrow_mut_data();
    let let_data = StatementNode {
        kind: StatementKind::Let {
            name: "data".to_string(),
            initializer: ExpressionNode {
                kind: ExpressionKind::MethodCall {
                    object: Box::new(ExpressionNode {
                        kind: ExpressionKind::Identifier("unchecked".to_string()),
                    }),
                    method: "try_borrow_mut_data".to_string(),
                    arguments: Vec::new(),
                },
            },
            type_annotation: None,
            is_mutable: true,
        },
        line_number: 10,
    };

    // Statement 2: let state = State::try_from_slice(&data);
    let let_state = StatementNode {
        kind: StatementKind::Let {
            name: "state".to_string(),
            initializer: ExpressionNode {
                kind: ExpressionKind::Identifier("data".to_string()),
            },
            type_annotation: None,
            is_mutable: true,
        },
        line_number: 11,
    };

    // Statement 3: state = 100;
    let write_state = StatementNode {
        kind: StatementKind::Expr(ExpressionNode {
            kind: ExpressionKind::Assign {
                left: Box::new(ExpressionNode {
                    kind: ExpressionKind::Identifier("state".to_string()),
                }),
                right: Box::new(ExpressionNode {
                    kind: ExpressionKind::Literal("100".to_string()),
                }),
            },
        }),
        line_number: 12,
    };

    let mut nodes = HashMap::new();
    nodes.insert(
        0,
        CFGNode {
            id: 0,
            ir_instructions: vec![],
            statements: vec![let_data, let_state, write_state],
        },
    );

    let mut ssa_states = HashMap::new();
    let mut active_variables = HashMap::new();
    active_variables.insert(
        "unchecked".to_string(),
        SSAVariable::Versioned {
            name: "unchecked".to_string(),
            version: 1,
        },
    );
    active_variables.insert(
        "data".to_string(),
        SSAVariable::Versioned {
            name: "data".to_string(),
            version: 1,
        },
    );
    active_variables.insert(
        "state".to_string(),
        SSAVariable::Versioned {
            name: "state".to_string(),
            version: 1,
        },
    );

    let stmt_state = SSANodeState {
        active_variables,
        variable_types: HashMap::new(),
    };

    ssa_states.insert(
        0,
        NodeSSAInfo {
            start_state: stmt_state.clone(),
            statement_states: vec![stmt_state.clone(), stmt_state.clone(), stmt_state.clone()],
            end_state: stmt_state.clone(),
        },
    );

    let cfg = ControlFlowGraph {
        nodes,
        edges: Vec::new(),
        entry_node: 0,
        exit_nodes: vec![0],
        boundary_warnings: Vec::new(),
        ssa_states,
    };

    // unchecked account is raw AccountInfo (no default owner check)
    let guard_facts = vec![(
        // Struct has some other fact (e.g. Signer) but no owner check
        GuardFact::Signer(GuardTarget::Account(unchecked_symbol)),
        FactProvenance {
            source_file: "lib.rs".to_string(),
            line_number: 1,
            column_number: 1,
            framework: "Anchor".to_string(),
            confidence_level: FactConfidence::Declared,
            node_id: None,
            statement_index: None,
        },
    )];

    let mut symbol_table = HashMap::new();
    symbol_table.insert("unchecked".to_string(), unchecked_symbol);
    symbol_table.insert("data".to_string(), data_symbol);
    symbol_table.insert("state".to_string(), state_symbol);

    let context = InstructionAnalysisContext {
        context_struct_name: "TestContext".to_string(),
        name: "test_instruction".to_string(),
        guard_facts,
        cfg,
        symbol_table,
        account_field_ids: Default::default(),
        file_path: "lib.rs".to_string(),
        context_var_name: "ctx".to_string(),
    };

    let mut engine = RuleEngine::new();
    engine.register_rule(Box::new(OwnerValidationRule));

    let analysis_context = epic::rules::AnalysisContext {
        program_metadata: epic::rules::ProgramMetadata {
            name: "test_program".to_string(),
            address: None,
        },
        idl_metadata: None,
        ast_graph: epic::Workspace::new(),
        instruction_context: context,
        rule_registry: Vec::new(),
    };

    let diagnostics = engine.run_all(&analysis_context);

    println!("WDG DIAGNOSTICS: {:#?}", diagnostics);

    // Verify: Write on `state` propagated through WDG back to `unchecked`.
    // Since `unchecked` lacks an owner check, it generates a critical finding.
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].target_symbol, unchecked_symbol);
}

#[test]
fn test_post_cpi_reload_rule() {
    use epic::rules::MissingPostCpiReloadRule;

    let vault_symbol = SymbolId(1);

    // Unsafe CFG: CPI call then immediate write
    // Statement 1: CPI (represented as a method call named transfer)
    let cpi_stmt = StatementNode {
        kind: StatementKind::Semi(ExpressionNode {
            kind: ExpressionKind::MethodCall {
                object: Box::new(ExpressionNode {
                    kind: ExpressionKind::Unresolved,
                }),
                method: "token::transfer".to_string(),
                arguments: vec![ExpressionNode {
                    kind: ExpressionKind::Identifier("vault".to_string()),
                }],
            },
        }),
        line_number: 10,
    };

    // Statement 2: vault.amount = 100; (Access)
    let access_stmt = StatementNode {
        kind: StatementKind::Expr(ExpressionNode {
            kind: ExpressionKind::Assign {
                left: Box::new(ExpressionNode {
                    kind: ExpressionKind::FieldAccess {
                        object: Box::new(ExpressionNode {
                            kind: ExpressionKind::Identifier("vault".to_string()),
                        }),
                        field: "amount".to_string(),
                    },
                }),
                right: Box::new(ExpressionNode {
                    kind: ExpressionKind::Literal("100".to_string()),
                }),
            },
        }),
        line_number: 11,
    };

    let mut nodes = HashMap::new();
    nodes.insert(
        0,
        CFGNode {
            id: 0,
            ir_instructions: vec![],
            statements: vec![cpi_stmt.clone(), access_stmt.clone()],
        },
    );

    let mut ssa_states = HashMap::new();
    let mut active_variables = HashMap::new();
    active_variables.insert(
        "vault".to_string(),
        SSAVariable::Versioned {
            name: "vault".to_string(),
            version: 1,
        },
    );

    let stmt_state = SSANodeState {
        active_variables,
        variable_types: HashMap::new(),
    };

    ssa_states.insert(
        0,
        NodeSSAInfo {
            start_state: stmt_state.clone(),
            statement_states: vec![stmt_state.clone(), stmt_state.clone()],
            end_state: stmt_state.clone(),
        },
    );

    let cfg = ControlFlowGraph {
        nodes,
        edges: Vec::new(),
        entry_node: 0,
        exit_nodes: vec![0],
        boundary_warnings: Vec::new(),
        ssa_states,
    };

    let guard_facts = vec![(
        GuardFact::Owner {
            account: GuardTarget::Account(vault_symbol),
            expected_owner: FactExpression::Literal("program_id".to_string()),
        },
        FactProvenance {
            source_file: "lib.rs".to_string(),
            line_number: 1,
            column_number: 1,
            framework: "Anchor".to_string(),
            confidence_level: FactConfidence::Declared,
            node_id: None,
            statement_index: None,
        },
    )];

    let mut symbol_table = HashMap::new();
    symbol_table.insert("vault".to_string(), vault_symbol);

    let context = InstructionAnalysisContext {
        context_struct_name: "TestContext".to_string(),
        name: "test_instruction".to_string(),
        guard_facts,
        cfg,
        symbol_table,
        account_field_ids: Default::default(),
        file_path: "lib.rs".to_string(),
        context_var_name: "ctx".to_string(),
    };

    let mut engine = RuleEngine::new();
    engine.register_rule(Box::new(MissingPostCpiReloadRule));

    let analysis_context = epic::rules::AnalysisContext {
        program_metadata: epic::rules::ProgramMetadata {
            name: "test_program".to_string(),
            address: None,
        },
        idl_metadata: None,
        ast_graph: epic::Workspace::new(),
        instruction_context: context,
        rule_registry: Vec::new(),
    };

    let diagnostics = engine.run_all(&analysis_context);
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].target_symbol, vault_symbol);
    assert_eq!(diagnostics[0].rule_id, "EPIC-SEC-003");
}

// ─── EPIC-SEC-002: IdentOrigin gate tests ────────────────────────────────────
// Shared helper: builds a minimal CFG with one write statement, populates the
// symbol table, and runs SEC-002. The caller controls which SymbolIds end up
// in account_field_ids.
fn run_sec002(
    var_name: &str,
    symbol_id: SymbolId,
    is_account_field: bool,
) -> Vec<epic::rules::RuleDiagnostic> {
    use epic::ast::{ExpressionKind, ExpressionNode, StatementKind, StatementNode};
    use epic::cfg::{
        CFGNode, ControlFlowGraph, FactConfidence, FactExpression, FactProvenance, GuardFact,
        GuardTarget, InstructionAnalysisContext, NodeSSAInfo, SSANodeState, SSAVariable,
    };
    use epic::rules::{RuleEngine, SignerValidationRule};
    use std::collections::{HashMap, HashSet};

    // Write statement: `let <var_name> = some_source.try_borrow_mut_data();`
    // This produces an IRInstruction::Assignment whose target is `var_name`, which
    // is exactly what get_mutable_write_expression_ir() detects via the fallback branch.
    let write_stmt = StatementNode {
        kind: StatementKind::Let {
            name: var_name.to_string(),
            initializer: ExpressionNode {
                kind: ExpressionKind::MethodCall {
                    object: Box::new(ExpressionNode {
                        kind: ExpressionKind::Identifier(var_name.to_string()),
                    }),
                    method: "try_borrow_mut_data".to_string(),
                    arguments: vec![],
                },
            },
            type_annotation: None,
            is_mutable: true,
        },
        line_number: 10,
    };

    let mut nodes = HashMap::new();
    nodes.insert(
        0,
        CFGNode {
            id: 0,
            ir_instructions: vec![],
            statements: vec![write_stmt],
        },
    );

    let mut active_variables = HashMap::new();
    active_variables.insert(
        var_name.to_string(),
        SSAVariable::Versioned {
            name: var_name.to_string(),
            version: 1,
        },
    );
    let stmt_state = SSANodeState {
        active_variables,
        variable_types: HashMap::new(),
    };
    let mut ssa_states = HashMap::new();
    ssa_states.insert(
        0,
        NodeSSAInfo {
            start_state: stmt_state.clone(),
            statement_states: vec![stmt_state.clone()],
            end_state: stmt_state,
        },
    );

    let cfg = ControlFlowGraph {
        nodes,
        edges: vec![],
        entry_node: 0,
        exit_nodes: vec![0],
        boundary_warnings: vec![],
        ssa_states,
    };

    // No guard facts → forces SEC-002 to consider the symbol unguarded
    let guard_facts = vec![(
        GuardFact::Owner {
            account: GuardTarget::Account(symbol_id),
            expected_owner: FactExpression::Literal("program_id".to_string()),
        },
        FactProvenance {
            source_file: "lib.rs".to_string(),
            line_number: 1,
            column_number: 0,
            framework: "Anchor".to_string(),
            confidence_level: FactConfidence::Declared,
            node_id: None,
            statement_index: None,
        },
    )];

    let mut symbol_table = HashMap::new();
    symbol_table.insert(var_name.to_string(), symbol_id);

    let mut account_field_ids = HashSet::new();
    if is_account_field {
        account_field_ids.insert(symbol_id);
    }

    let context = InstructionAnalysisContext {
        context_struct_name: "Ctx".to_string(),
        name: "ix".to_string(),
        guard_facts,
        cfg,
        symbol_table,
        account_field_ids,
        file_path: "lib.rs".to_string(),
        context_var_name: "ctx".to_string(),
    };

    let mut engine = RuleEngine::new();
    engine.register_rule(Box::new(SignerValidationRule));

    let analysis = epic::rules::AnalysisContext {
        program_metadata: epic::rules::ProgramMetadata {
            name: "prog".to_string(),
            address: None,
        },
        idl_metadata: None,
        ast_graph: epic::Workspace::new(),
        instruction_context: context,
        rule_registry: vec![],
    };

    engine.run_all(&analysis)
}

/// A real Anchor `Signer<'info>` field named `authority` with no signer check
/// should STILL fire EPIC-SEC-002.
#[test]
fn test_sec002_account_field_authority_fires() {
    let diags = run_sec002("authority", SymbolId(1), /*is_account_field=*/ true);
    assert!(
        !diags.is_empty(),
        "Expected SEC-002 to fire for a real account field named 'authority'"
    );
    assert_eq!(diags[0].rule_id, "EPIC-SEC-002");
}

/// A local `let authority_seeds = [b\"squad\", ...]` binding should NOT fire
/// SEC-002 — it is a seed array, not an account field.
#[test]
fn test_sec002_seeds_local_does_not_fire() {
    let diags = run_sec002(
        "authority_seeds",
        SymbolId(2),
        /*is_account_field=*/ false,
    );
    assert!(
        diags.is_empty(),
        "Expected SEC-002 to be silent for a local _seeds binding, got: {:#?}",
        diags
    );
}

/// A local `let mut require_group_admin = false;` (bool flag) should NOT fire
/// SEC-002 even though the name contains \"admin\".
#[test]
fn test_sec002_bool_local_does_not_fire() {
    let diags = run_sec002(
        "require_group_admin",
        SymbolId(3),
        /*is_account_field=*/ false,
    );
    assert!(
        diags.is_empty(),
        "Expected SEC-002 to be silent for a bool local named 'require_group_admin', got: {:#?}",
        diags
    );
}

/// A pattern-matched local from `if let Some(admin) = admin_opt` should NOT
/// fire SEC-002 even though the name is \"admin\".
#[test]
fn test_sec002_option_destructured_local_does_not_fire() {
    let diags = run_sec002("admin", SymbolId(4), /*is_account_field=*/ false);
    assert!(
        diags.is_empty(),
        "Expected SEC-002 to be silent for an Option-destructured local 'admin', got: {:#?}",
        diags
    );
}

/// Verify that auditing code containing a struct with multiple separate `impl` blocks
/// (mirroring the SwapLikeJupiter pattern) does not produce duplicate diagnostics.
#[test]
fn test_multiple_impl_blocks_no_duplicate_diagnostics() {
    let source = r#"
use anchor_lang::prelude::*;
use anchor_spl::token::{Token, TokenAccount};

declare_id!("11111111111111111111111111111111");

#[program]
pub mod mock_prog {
    use super::*;

    pub fn ix1(ctx: Context<SwapLikeJupiter>, amt: u64) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SwapLikeJupiter<'info> {
    pub user_authority: Signer<'info>,
    #[account(mut)]
    pub pool_a: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

impl<'info> SwapLikeJupiter<'info> {
    pub fn do_swap(ctx: Context<'info, SwapLikeJupiter<'info>>) -> Result<()> {
        Ok(())
    }
}

impl<'info> SwapLikeJupiter<'info> {
    fn helper_one(&self) {}
    fn helper_two(&self) {}
}
"#;

    let temp_dir = std::env::temp_dir().join("epic_test_multiple_impls");
    let src_dir = temp_dir.join("src");
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(src_dir.join("lib.rs"), source).unwrap();

    let diagnostics = epic::audit::run_audit(temp_dir.to_str().unwrap()).unwrap();

    let _ = std::fs::remove_dir_all(&temp_dir);

    // Count how many times EPIC-SEC-TOKEN fires for pool_a
    let sec_token_count = diagnostics
        .iter()
        .filter(|d| d.rule_id == "EPIC-SEC-TOKEN")
        .count();

    assert_eq!(
        sec_token_count, 1,
        "Expected exactly 1 EPIC-SEC-TOKEN finding despite multiple impl blocks, got: {}",
        sec_token_count
    );
}

/// Verify that EPIC-SEC-TOKEN diagnostics report real non-zero line/column values
/// (not the historic hardcoded 0:0) by running run_audit on an inline source file
/// containing a TokenAccount field without a mint constraint.
#[test]
fn test_sec_token_reports_real_field_location_mint() {
    // The `pool_a` field is on a known line within this source snippet.
    // proc-macro2 with span-locations gives 1-indexed line numbers.
    let source = r#"use anchor_lang::prelude::*;
use anchor_spl::token::{Token, TokenAccount};

declare_id!("11111111111111111111111111111111");

#[program]
pub mod mock_prog {
    use super::*;

    pub fn swap(ctx: Context<TestSwap>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct TestSwap<'info> {
    pub user_authority: Signer<'info>,
    #[account(mut)]
    pub pool_a: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}
"#;

    let temp_dir = std::env::temp_dir().join("epic_test_sec009_loc");
    let src_dir = temp_dir.join("src");
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(src_dir.join("lib.rs"), source).unwrap();

    let diagnostics = epic::audit::run_audit(temp_dir.to_str().unwrap()).unwrap();
    let _ = std::fs::remove_dir_all(&temp_dir);

    let sec_token: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.rule_id == "EPIC-SEC-TOKEN")
        .collect();

    assert!(
        !sec_token.is_empty(),
        "Expected at least one EPIC-SEC-TOKEN finding, got none. Full diagnostics: {:#?}",
        diagnostics
    );

    for diag in &sec_token {
        assert_ne!(
            diag.location.line, 0,
            "EPIC-SEC-TOKEN diagnostic for '{}' should have non-zero line, got location {:?}",
            diag.message, diag.location
        );
    }
}

/// Verify that EPIC-SEC-TOKEN diagnostics report real non-zero line/column values
/// for vault/pool TokenAccount fields lacking authority constraints.
#[test]
fn test_sec_token_reports_real_field_location_auth() {
    let source = r#"use anchor_lang::prelude::*;
use anchor_spl::token::{Token, TokenAccount};

declare_id!("11111111111111111111111111111111");

#[program]
pub mod mock_prog {
    use super::*;

    pub fn deposit(ctx: Context<TestDeposit>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct TestDeposit<'info> {
    pub user_authority: Signer<'info>,
    #[account(mut)]
    pub pool_vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}
"#;

    let temp_dir = std::env::temp_dir().join("epic_test_sec010_loc");
    let src_dir = temp_dir.join("src");
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(src_dir.join("lib.rs"), source).unwrap();

    let diagnostics = epic::audit::run_audit(temp_dir.to_str().unwrap()).unwrap();
    let _ = std::fs::remove_dir_all(&temp_dir);

    let sec_token: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.rule_id == "EPIC-SEC-TOKEN")
        .collect();

    assert!(
        !sec_token.is_empty(),
        "Expected at least one EPIC-SEC-TOKEN finding, got none. Full diagnostics: {:#?}",
        diagnostics
    );

    for diag in &sec_token {
        assert_ne!(
            diag.location.line, 0,
            "EPIC-SEC-TOKEN diagnostic for '{}' should have non-zero line, got location {:?}",
            diag.message, diag.location
        );
    }
}

/// EPIC-SEC-002 must fire when the signer check is conditional (inside an `if`)
/// and the privileged write is a compound assignment (`-=`) outside the `if`.
///
/// This is the core dominance-bypass demo case: the write is NOT dominated by
/// the signer check because an attacker can pass `some_condition = false`.
#[test]
fn test_sec002_assignop_conditional_fires() {
    let source = r#"use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod dominance_bypass {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64, some_condition: bool) -> Result<()> {
        if some_condition {
            require!(ctx.accounts.authority.is_signer, ErrorCode::Unauthorized);
        }
        ctx.accounts.vault.balance -= amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    /// CHECK: unsafe unchecked authority
    #[account(mut)]
    pub authority: AccountInfo<'info>,
    #[account(mut)]
    pub vault: Account<'info, VaultAccount>,
}

#[account]
pub struct VaultAccount {
    pub balance: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized")]
    Unauthorized,
}
"#;

    let temp_dir = std::env::temp_dir().join("epic_test_sec002_assignop_conditional");
    let src_dir = temp_dir.join("src");
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(src_dir.join("lib.rs"), source).unwrap();

    let diagnostics = epic::audit::run_audit(temp_dir.to_str().unwrap()).unwrap();
    let _ = std::fs::remove_dir_all(&temp_dir);

    let sec002: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.rule_id == "EPIC-SEC-002")
        .collect();

    assert!(
        !sec002.is_empty(),
        "Expected EPIC-SEC-002 to fire on conditional signer check + compound-assign write, \
         got none. Full diagnostics: {:#?}",
        diagnostics
    );
}

/// EPIC-SEC-002 must NOT fire when the signer check is unconditional and precedes
/// the compound-assignment write — the write IS dominated, so no finding.
///
/// This guards against false positives introduced by making AssignOp writes visible.
#[test]
fn test_sec002_assignop_unconditional_silent() {
    let source = r#"use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod dominance_safe {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        require!(ctx.accounts.authority.is_signer, ErrorCode::Unauthorized);
        ctx.accounts.vault.balance -= amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(mut)]
    pub vault: Account<'info, VaultAccount>,
}

#[account]
pub struct VaultAccount {
    pub balance: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized")]
    Unauthorized,
}
"#;

    let temp_dir = std::env::temp_dir().join("epic_test_sec002_assignop_unconditional");
    let src_dir = temp_dir.join("src");
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(src_dir.join("lib.rs"), source).unwrap();

    let diagnostics = epic::audit::run_audit(temp_dir.to_str().unwrap()).unwrap();
    let _ = std::fs::remove_dir_all(&temp_dir);

    let sec002: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.rule_id == "EPIC-SEC-002")
        .collect();

    assert!(
        sec002.is_empty(),
        "Expected EPIC-SEC-002 to be silent when signer check unconditionally dominates \
         compound-assign write, got: {:#?}",
        sec002
    );
}
