use epic::cfg::{
    ControlFlowGraph, FactConfidence, FactExpression, FactProvenance, GuardFact, GuardTarget,
    InstructionAnalysisContext, SymbolId,
};
use epic::rules::epic_sec_token::TokenAccountRule;
use epic::rules::{AnalysisContext, ProgramMetadata, Rule, RuleEngine};
use epic::types::{FieldDef, StructDef, TypeDef, TypeRef, TypeRegistry};
use epic::Workspace;
use std::collections::HashMap;

fn create_token_field(name: &str, attrs: Vec<&str>) -> FieldDef {
    FieldDef {
        name: name.to_string(),
        type_ref: TypeRef::Custom("Account<'info, TokenAccount>".to_string()),
        attrs: attrs.iter().map(|s| s.to_string()).collect(),
        line_number: 10,
        column_number: 5,
    }
}

#[test]
fn test_token_account_rule() {
    // We will create a struct with several TokenAccount fields:
    // 1. both_constraints (mint, authority) -> No finding
    // 2. missing_mint (authority only) -> High severity (missing mint)
    // 3. missing_authority (mint only) -> Medium severity (missing authority) - Not named vault/pool!
    // 4. missing_both -> High severity (missing both)

    let fields = vec![
        create_token_field(
            "both_constraints",
            vec!["mint = some_mint", "authority = some_auth"],
        ),
        create_token_field("missing_mint", vec!["authority = some_auth"]),
        create_token_field("missing_authority", vec!["mint = some_mint"]),
        create_token_field("missing_both", vec![]),
    ];

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

    let ast_graph = Workspace { registry };

    let mut symbol_table = HashMap::new();
    symbol_table.insert("both_constraints".to_string(), SymbolId(1));
    symbol_table.insert("missing_mint".to_string(), SymbolId(2));
    symbol_table.insert("missing_authority".to_string(), SymbolId(3));
    symbol_table.insert("missing_both".to_string(), SymbolId(4));

    let instruction_context = InstructionAnalysisContext {
        name: "test_ix".to_string(),
        guard_facts: vec![],
        cfg: ControlFlowGraph::default(),
        symbol_table,
        account_field_ids: std::collections::HashSet::new(),
        file_path: "lib.rs".to_string(),
        context_var_name: "ctx".to_string(),
        context_struct_name: "TestAccounts".to_string(),
    };

    let context = AnalysisContext {
        program_metadata: ProgramMetadata {
            name: "test".to_string(),
            address: None,
        },
        idl_metadata: None,
        ast_graph,
        instruction_context,
        rule_registry: vec![],
    };

    let rule = TokenAccountRule;
    let diagnostics = rule.check(&context);

    // We expect 3 findings
    assert_eq!(diagnostics.len(), 3);

    let missing_mint = diagnostics
        .iter()
        .find(|d| d.message.contains("missing mint constraint"))
        .unwrap();
    assert_eq!(missing_mint.target_symbol, SymbolId(2));
    assert_eq!(missing_mint.severity, epic::rules::RuleSeverity::High);

    let missing_auth = diagnostics
        .iter()
        .find(|d| d.message.contains("missing authority constraint"))
        .unwrap();
    assert_eq!(missing_auth.target_symbol, SymbolId(3));
    assert_eq!(missing_auth.severity, epic::rules::RuleSeverity::Medium);

    let missing_both = diagnostics
        .iter()
        .find(|d| d.message.contains("missing both"))
        .unwrap();
    assert_eq!(missing_both.target_symbol, SymbolId(4));
    assert_eq!(missing_both.severity, epic::rules::RuleSeverity::High);
}
