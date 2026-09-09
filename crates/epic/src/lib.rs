#![allow(clippy::too_many_arguments)]
#![allow(clippy::only_used_in_recursion)]
#![allow(clippy::collapsible_match)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::redundant_pattern_matching)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::manual_strip)]
#![allow(clippy::let_and_return)]

pub mod abi;
pub mod ast;
pub mod audit;
pub mod cfg;
pub mod impact;
pub mod ir_converter;
pub mod layout;
pub mod report;
pub mod rules;
pub mod sarif;
pub mod types;
pub mod ui;
pub mod workspace;

pub use abi::{compare_workspaces, format_diff_results, ChangeType, DiffResult, Severity};
pub use ast::{
    unpack_nested_generics, ExpressionKind, ExpressionNode, FunctionNode, InconclusiveReason,
    InferenceResult, InferenceScope, ParameterNode, StatementKind, StatementNode,
    TypeInferenceEngine,
};
pub use audit::{
    extract_context_struct_name, find_struct_for_context, run_audit, RawFunction,
    RawFunctionVisitor,
};
pub use cfg::{
    extract_guards_from_accounts_struct, CFGBoundaryWarning, CFGBuilder, CFGEdge, CFGNode,
    ControlFlowGraph, DominanceInterval, FactConfidence, FactExpression, FactProvenance, GuardFact,
    GuardFactLocation, GuardTarget, InstructionAnalysisContext, NodeSSAInfo, SSAComputer,
    SSANodeState, SSAVariable, SSAVersionId, SolanaProperty, SymbolId,
};
pub use impact::{
    analyze_impact, format_impact_terminal, generate_aggregated_impact, ImpactAnalysis,
};
pub use rules::{
    AnalysisContext, DominanceChecker, FindingLocation, IdlMetadata, OwnerValidationRule,
    ProgramMetadata, Rule, RuleDiagnostic, RuleEngine, RuleMetadata, RuleSeverity, SymbolResolver,
};
pub use workspace::Workspace;
