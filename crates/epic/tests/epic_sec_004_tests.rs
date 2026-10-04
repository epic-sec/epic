use epic::ast::{ExpressionKind, ExpressionNode, StatementKind, StatementNode};
use epic::cfg::{
    CFGNode, ControlFlowGraph, InstructionAnalysisContext, NodeSSAInfo, SSANodeState, SSAVariable,
};
use epic::rules::{PdaSeedCollisionRule, RuleEngine};
use epic::types::TypeRef;
use std::collections::HashMap;

#[test]
fn test_adjacent_variable_unsafe() {
    // Under test:
    // seeds = [name.as_bytes(), symbol.as_bytes()]
    // Both name and symbol are TypeRef::String (variable length). Adjacent variables => Unsafe.

    // method call for name.as_bytes()
    let name_expr = ExpressionNode {
        kind: ExpressionKind::MethodCall {
            object: Box::new(ExpressionNode {
                kind: ExpressionKind::Identifier("name".to_string()),
            }),
            method: "as_bytes".to_string(),
            arguments: Vec::new(),
        },
    };

    // method call for symbol.as_bytes()
    let symbol_expr = ExpressionNode {
        kind: ExpressionKind::MethodCall {
            object: Box::new(ExpressionNode {
                kind: ExpressionKind::Identifier("symbol".to_string()),
            }),
            method: "as_bytes".to_string(),
            arguments: Vec::new(),
        },
    };

    // find_program_address([name_expr, symbol_expr])
    let find_pda_stmt = StatementNode {
        kind: StatementKind::Semi(ExpressionNode {
            kind: ExpressionKind::MethodCall {
                object: Box::new(ExpressionNode {
                    kind: ExpressionKind::Identifier("Pubkey".to_string()),
                }),
                method: "find_program_address".to_string(),
                arguments: vec![
                    ExpressionNode {
                        kind: ExpressionKind::MethodCall {
                            object: Box::new(ExpressionNode {
                                kind: ExpressionKind::Unresolved,
                            }),
                            method: "array".to_string(),
                            arguments: vec![name_expr, symbol_expr],
                        },
                    },
                    ExpressionNode {
                        kind: ExpressionKind::Identifier("program_id".to_string()),
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
            statements: vec![find_pda_stmt],
        },
    );

    let mut ssa_states = HashMap::new();
    let mut active_variables = HashMap::new();
    active_variables.insert(
        "name".to_string(),
        SSAVariable::Versioned {
            name: "name".to_string(),
            version: 1,
        },
    );
    active_variables.insert(
        "symbol".to_string(),
        SSAVariable::Versioned {
            name: "symbol".to_string(),
            version: 1,
        },
    );

    let mut variable_types = HashMap::new();
    variable_types.insert("name#1".to_string(), TypeRef::String);
    variable_types.insert("symbol#1".to_string(), TypeRef::String);

    let stmt_state = SSANodeState {
        active_variables,
        variable_types,
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

    let context = InstructionAnalysisContext {
        context_struct_name: "TestContext".to_string(),
        name: "test_instruction".to_string(),
        guard_facts: Vec::new(),
        cfg,
        symbol_table: HashMap::new(),
        account_field_ids: Default::default(),
        param_ids: Default::default(),
        file_path: "lib.rs".to_string(),
        context_var_name: "ctx".to_string(),
    };

    let mut engine = RuleEngine::new();
    engine.register_rule(Box::new(PdaSeedCollisionRule));

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
    assert_eq!(diagnostics[0].rule_id, "EPIC-SEC-004");
}

#[test]
fn test_safe_separated_fixed_length() {
    // Under test:
    // seeds = [name.as_bytes(), user_key.as_ref(), symbol.as_bytes()]
    // Separated by user_key (TypeRef::Pubkey, which is fixed-length). => Safe.

    let name_expr = ExpressionNode {
        kind: ExpressionKind::MethodCall {
            object: Box::new(ExpressionNode {
                kind: ExpressionKind::Identifier("name".to_string()),
            }),
            method: "as_bytes".to_string(),
            arguments: Vec::new(),
        },
    };

    let key_expr = ExpressionNode {
        kind: ExpressionKind::MethodCall {
            object: Box::new(ExpressionNode {
                kind: ExpressionKind::Identifier("user_key".to_string()),
            }),
            method: "as_ref".to_string(),
            arguments: Vec::new(),
        },
    };

    let symbol_expr = ExpressionNode {
        kind: ExpressionKind::MethodCall {
            object: Box::new(ExpressionNode {
                kind: ExpressionKind::Identifier("symbol".to_string()),
            }),
            method: "as_bytes".to_string(),
            arguments: Vec::new(),
        },
    };

    let find_pda_stmt = StatementNode {
        kind: StatementKind::Semi(ExpressionNode {
            kind: ExpressionKind::MethodCall {
                object: Box::new(ExpressionNode {
                    kind: ExpressionKind::Identifier("Pubkey".to_string()),
                }),
                method: "find_program_address".to_string(),
                arguments: vec![
                    ExpressionNode {
                        kind: ExpressionKind::MethodCall {
                            object: Box::new(ExpressionNode {
                                kind: ExpressionKind::Unresolved,
                            }),
                            method: "array".to_string(),
                            arguments: vec![name_expr, key_expr, symbol_expr],
                        },
                    },
                    ExpressionNode {
                        kind: ExpressionKind::Identifier("program_id".to_string()),
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
            statements: vec![find_pda_stmt],
        },
    );

    let mut ssa_states = HashMap::new();
    let mut active_variables = HashMap::new();
    active_variables.insert(
        "name".to_string(),
        SSAVariable::Versioned {
            name: "name".to_string(),
            version: 1,
        },
    );
    active_variables.insert(
        "user_key".to_string(),
        SSAVariable::Versioned {
            name: "user_key".to_string(),
            version: 1,
        },
    );
    active_variables.insert(
        "symbol".to_string(),
        SSAVariable::Versioned {
            name: "symbol".to_string(),
            version: 1,
        },
    );

    let mut variable_types = HashMap::new();
    variable_types.insert("name#1".to_string(), TypeRef::String);
    variable_types.insert("user_key#1".to_string(), TypeRef::Pubkey);
    variable_types.insert("symbol#1".to_string(), TypeRef::String);

    let stmt_state = SSANodeState {
        active_variables,
        variable_types,
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

    let context = InstructionAnalysisContext {
        context_struct_name: "TestContext".to_string(),
        name: "test_instruction".to_string(),
        guard_facts: Vec::new(),
        cfg,
        symbol_table: HashMap::new(),
        account_field_ids: Default::default(),
        param_ids: Default::default(),
        file_path: "lib.rs".to_string(),
        context_var_name: "ctx".to_string(),
    };

    let mut engine = RuleEngine::new();
    engine.register_rule(Box::new(PdaSeedCollisionRule));

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
    assert_eq!(diagnostics.len(), 0);
}

#[test]
fn test_safe_separated_literal_delimiter() {
    // Under test:
    // seeds = [name.as_bytes(), b"|", symbol.as_bytes()]
    // Separated by literal b"|" (fixed-length literal bytes). => Safe.

    let name_expr = ExpressionNode {
        kind: ExpressionKind::MethodCall {
            object: Box::new(ExpressionNode {
                kind: ExpressionKind::Identifier("name".to_string()),
            }),
            method: "as_bytes".to_string(),
            arguments: Vec::new(),
        },
    };

    let delim_expr = ExpressionNode {
        kind: ExpressionKind::Literal("b\"|\"".to_string()),
    };

    let symbol_expr = ExpressionNode {
        kind: ExpressionKind::MethodCall {
            object: Box::new(ExpressionNode {
                kind: ExpressionKind::Identifier("symbol".to_string()),
            }),
            method: "as_bytes".to_string(),
            arguments: Vec::new(),
        },
    };

    let find_pda_stmt = StatementNode {
        kind: StatementKind::Semi(ExpressionNode {
            kind: ExpressionKind::MethodCall {
                object: Box::new(ExpressionNode {
                    kind: ExpressionKind::Identifier("Pubkey".to_string()),
                }),
                method: "find_program_address".to_string(),
                arguments: vec![
                    ExpressionNode {
                        kind: ExpressionKind::MethodCall {
                            object: Box::new(ExpressionNode {
                                kind: ExpressionKind::Unresolved,
                            }),
                            method: "array".to_string(),
                            arguments: vec![name_expr, delim_expr, symbol_expr],
                        },
                    },
                    ExpressionNode {
                        kind: ExpressionKind::Identifier("program_id".to_string()),
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
            statements: vec![find_pda_stmt],
        },
    );

    let mut ssa_states = HashMap::new();
    let mut active_variables = HashMap::new();
    active_variables.insert(
        "name".to_string(),
        SSAVariable::Versioned {
            name: "name".to_string(),
            version: 1,
        },
    );
    active_variables.insert(
        "symbol".to_string(),
        SSAVariable::Versioned {
            name: "symbol".to_string(),
            version: 1,
        },
    );

    let mut variable_types = HashMap::new();
    variable_types.insert("name#1".to_string(), TypeRef::String);
    variable_types.insert("symbol#1".to_string(), TypeRef::String);

    let stmt_state = SSANodeState {
        active_variables,
        variable_types,
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

    let context = InstructionAnalysisContext {
        context_struct_name: "TestContext".to_string(),
        name: "test_instruction".to_string(),
        guard_facts: Vec::new(),
        cfg,
        symbol_table: HashMap::new(),
        account_field_ids: Default::default(),
        param_ids: Default::default(),
        file_path: "lib.rs".to_string(),
        context_var_name: "ctx".to_string(),
    };

    let mut engine = RuleEngine::new();
    engine.register_rule(Box::new(PdaSeedCollisionRule));

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
    assert_eq!(diagnostics.len(), 0);
}

#[test]
fn test_epic_advantage_fixed_hash() {
    // Under test:
    // seeds = [name.as_bytes(), &fixed_hash]
    // where fixed_hash is typed as [u8; 32] (fixed-length array). => Safe.

    let name_expr = ExpressionNode {
        kind: ExpressionKind::MethodCall {
            object: Box::new(ExpressionNode {
                kind: ExpressionKind::Identifier("name".to_string()),
            }),
            method: "as_bytes".to_string(),
            arguments: Vec::new(),
        },
    };

    let hash_expr = ExpressionNode {
        kind: ExpressionKind::Reference {
            expression: Box::new(ExpressionNode {
                kind: ExpressionKind::Identifier("fixed_hash".to_string()),
            }),
            is_mutable: false,
        },
    };

    let find_pda_stmt = StatementNode {
        kind: StatementKind::Semi(ExpressionNode {
            kind: ExpressionKind::MethodCall {
                object: Box::new(ExpressionNode {
                    kind: ExpressionKind::Identifier("Pubkey".to_string()),
                }),
                method: "find_program_address".to_string(),
                arguments: vec![
                    ExpressionNode {
                        kind: ExpressionKind::MethodCall {
                            object: Box::new(ExpressionNode {
                                kind: ExpressionKind::Unresolved,
                            }),
                            method: "array".to_string(),
                            arguments: vec![name_expr, hash_expr],
                        },
                    },
                    ExpressionNode {
                        kind: ExpressionKind::Identifier("program_id".to_string()),
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
            statements: vec![find_pda_stmt],
        },
    );

    let mut ssa_states = HashMap::new();
    let mut active_variables = HashMap::new();
    active_variables.insert(
        "name".to_string(),
        SSAVariable::Versioned {
            name: "name".to_string(),
            version: 1,
        },
    );
    active_variables.insert(
        "fixed_hash".to_string(),
        SSAVariable::Versioned {
            name: "fixed_hash".to_string(),
            version: 1,
        },
    );

    let mut variable_types = HashMap::new();
    variable_types.insert("name#1".to_string(), TypeRef::String);
    variable_types.insert(
        "fixed_hash#1".to_string(),
        TypeRef::Array(Box::new(TypeRef::Primitive("u8".to_string())), 32),
    );

    let stmt_state = SSANodeState {
        active_variables,
        variable_types,
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

    let context = InstructionAnalysisContext {
        context_struct_name: "TestContext".to_string(),
        name: "test_instruction".to_string(),
        guard_facts: Vec::new(),
        cfg,
        symbol_table: HashMap::new(),
        account_field_ids: Default::default(),
        param_ids: Default::default(),
        file_path: "lib.rs".to_string(),
        context_var_name: "ctx".to_string(),
    };

    let mut engine = RuleEngine::new();
    engine.register_rule(Box::new(PdaSeedCollisionRule));

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
    assert_eq!(diagnostics.len(), 0);
}
