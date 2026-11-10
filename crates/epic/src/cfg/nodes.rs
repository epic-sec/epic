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

impl ControlFlowGraph {
    /// `self.nodes.values()` in node-id order rather than `HashMap`
    /// iteration order.
    ///
    /// `nodes` is a `HashMap`, so its iteration order varies **per process
    /// run** (Rust's default hasher is randomly seeded at startup) — not
    /// just "unspecified" in the abstract, but observably different on two
    /// runs of the same binary over the same unmodified source. A rule that
    /// walks `.values()` directly and keeps only the first match for some
    /// key (the common "report once per resolved path" dedup pattern) ends
    /// up keeping a different match, at a different source line, on every
    /// other run. Two real instances of exactly this were caught by a
    /// stable-output regression test on the 5-protocol sweep corpus; see
    /// `determinism_tests.rs`. Any code that cares which node is visited
    /// first — which a first-wins dedup always does, even when it doesn't
    /// look like it — must go through this, not `.nodes.values()` directly.
    pub fn nodes_sorted(&self) -> Vec<&CFGNode> {
        let mut ids: Vec<&usize> = self.nodes.keys().collect();
        ids.sort_unstable();
        ids.into_iter().map(|id| &self.nodes[id]).collect()
    }
}
