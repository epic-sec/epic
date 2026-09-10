use epic::ast::{ExpressionKind, ExpressionNode, StatementKind, StatementNode};
use epic::cfg::{
    CFGNode, ControlFlowGraph, FactConfidence, FactExpression, FactProvenance, GuardFact,
    GuardTarget, InstructionAnalysisContext, NodeSSAInfo, SSANodeState, SSAVariable, SymbolId,
};
use epic::rules::{ArbitraryCpiTargetRule, RuleEngine};
use std::collections::HashMap;

#[test]
fn test_arbitrary_cpi_target_rule() {
    let token_prog_symbol = SymbolId(1);

    // Unsafe CFG: CPI call using token_prog directly without validation
    // Statement 1: invoke(&ix, &[token_prog])
    let invoke_stmt = StatementNode {
        kind: StatementKind::Semi(ExpressionNode {
            kind: ExpressionKind::MethodCall {
                object: Box::new(ExpressionNode {
                    kind: ExpressionKind::Unresolved,
                }),
                method: "invoke".to_string(),
                arguments: vec![
                    ExpressionNode {
                        kind: ExpressionKind::Identifier("ix".to_string()),
                    },
                    ExpressionNode {
                        kind: ExpressionKind::Identifier("token_program".to_string()),
                    },
                ],
            },
        }),
        line_number: 10,
    };

    let mut nodes = HashMap::new();
    nodes.insert(
        0,
        CFGNode {
            id: 0,
            ir_instructions: vec![],
            statements: vec![invoke_stmt],
        },
    );

    let mut ssa_states = HashMap::new();
    let mut active_variables = HashMap::new();
    active_variables.insert(
        "token_program".to_string(),
        SSAVariable::Versioned {
            name: "token_program".to_string(),
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
            statement_states: vec![stmt_state.clone()],
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
            account: GuardTarget::Account(token_prog_symbol),
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
    symbol_table.insert("token_program".to_string(), token_prog_symbol);

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
    engine.register_rule(Box::new(ArbitraryCpiTargetRule));

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
    assert_eq!(diagnostics[0].target_symbol, token_prog_symbol);
    assert_eq!(diagnostics[0].rule_id, "EPIC-SEC-005");
}

// ─────────────────────────────────────────────────────────────────────────────
// Full-pipeline regression tests, adapted from sealevel-attacks
// `5-arbitrary-cpi`. Unlike the synthetic-CFG test above, these exercise the
// real dataflow this rule depends on end to end: the target program id lives
// inside `spl_token::instruction::transfer(token_program.key, ...)`, whose
// *return value* — not `token_program` itself — is passed as invoke()'s
// first argument, and `token_program.key` is a raw `AccountInfo` field
// access, not a `.key()` method call. Two independent gaps had to be fixed
// for this to resolve at all:
//   1. `extract_cpi_targets_expr_ir` only ever looked at invoke()'s second
//      argument (the account-infos slice) for CPI targets, never the first
//      (the instruction expression) — so a target embedded in a call that
//      *builds* the instruction was invisible regardless of resolution.
//   2. The resolver's FieldAccess path only matched `ctx.accounts.<field>`
//      exactly, with no fallback for a trailing property segment like
//      `.key` — so even once found, `token_program.key` failed to resolve
//      to the `token_program` symbol.
// ─────────────────────────────────────────────────────────────────────────────

fn fixture_path(name: &str) -> String {
    format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name)
}

#[test]
fn test_arbitrary_cpi_insecure_fixture_flags() {
    let diagnostics = epic::run_audit(&fixture_path("sec005-arbitrary-cpi-insecure"))
        .expect("run_audit should succeed on a syntactically valid fixture");

    let sec005_findings: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.rule_id == "EPIC-SEC-005")
        .collect();

    assert_eq!(
        sec005_findings.len(),
        1,
        "unchecked token_program fed through spl_token::instruction::transfer into invoke() must be flagged exactly once, got: {:?}",
        sec005_findings
    );
    assert!(
        sec005_findings[0].message.contains("token_program"),
        "message should name the unchecked program account: {}",
        sec005_findings[0].message
    );
}

#[test]
fn test_arbitrary_cpi_secure_fixture_is_clean() {
    let diagnostics = epic::run_audit(&fixture_path("sec005-arbitrary-cpi-secure"))
        .expect("run_audit should succeed on a syntactically valid fixture");

    let sec005_findings: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.rule_id == "EPIC-SEC-005")
        .collect();

    assert!(
        sec005_findings.is_empty(),
        "token_program is checked against spl_token::ID dominating the invoke() call and must not be flagged, got: {:?}",
        sec005_findings
    );
}
