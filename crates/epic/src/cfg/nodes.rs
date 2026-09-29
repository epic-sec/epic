use crate::ast::{ExpressionNode, StatementNode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CFGBoundaryWarning {
    LoopDetected,
    MatchExpression,
    TraitDispatch,
    RecursiveFunction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CFGNode {
    pub id: usize,
    pub statements: Vec<StatementNode>,
    #[serde(default)]
    pub ir_instructions: Vec<epic_ir::IRInstruction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CFGEdge {
    pub from: usize,
    pub to: usize,
    pub condition: Option<ExpressionNode>,
    #[serde(default)]
    pub ir_condition: Option<epic_ir::IRExpression>,
    pub is_early_return: bool,
    /// Source line of the branch/early-return statement this edge came from.
    /// `None` for structural merge edges that don't represent a decision.
    #[serde(default)]
    pub line: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ControlFlowGraph {
    pub nodes: HashMap<usize, CFGNode>,
    pub edges: Vec<CFGEdge>,
    pub entry_node: usize,
    pub exit_nodes: Vec<usize>,
    pub boundary_warnings: Vec<CFGBoundaryWarning>,
    #[serde(default)]
    pub ssa_states: HashMap<usize, crate::cfg::ssa::NodeSSAInfo>,
}
