use crate::cfg::ControlFlowGraph;
use std::collections::{HashMap, HashSet, VecDeque};

/// Finds a concrete path of node ids from the CFG's entry to `target_node`
/// that never passes through `avoid_node`.
///
/// This is the witness for a dominance finding: when `avoid_node` (a check)
/// does not dominate `target_node` (a vulnerable write), such a path is
/// guaranteed to exist — that is exactly what non-dominance means. A `None`
/// return means the dominance computation and this search disagree, which is
/// a bug in one of them, not a legitimate "no path" case; callers should
/// surface that loudly rather than silently show no witness.
pub fn find_bypassing_path(
    cfg: &ControlFlowGraph,
    avoid_node: usize,
    target_node: usize,
) -> Option<Vec<usize>> {
    let entry = cfg.entry_node;
    if entry == avoid_node {
        return None;
    }

    let mut came_from: HashMap<usize, usize> = HashMap::new();
    let mut visited: HashSet<usize> = HashSet::new();
    let mut queue: VecDeque<usize> = VecDeque::new();
    visited.insert(entry);
    queue.push_back(entry);

    while let Some(node) = queue.pop_front() {
        if node == target_node {
            let mut path = vec![node];
            let mut cur = node;
            while let Some(&prev) = came_from.get(&cur) {
                path.push(prev);
                cur = prev;
            }
            path.reverse();
            return Some(path);
        }
        for edge in &cfg.edges {
            if edge.from == node && edge.to != avoid_node && visited.insert(edge.to) {
                came_from.insert(edge.to, node);
                queue.push_back(edge.to);
            }
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct DominanceChecker {
    pub intervals: HashMap<usize, (usize, usize)>,
}

impl DominanceChecker {
    pub fn new(cfg: &ControlFlowGraph) -> Self {
        let mut checker = Self {
            intervals: HashMap::new(),
        };
        checker.compute_dominance(cfg);
        checker
    }

    /// Check if statement/node A dominates statement/node B.
    pub fn dominates(
        &self,
        node_a: usize,
        stmt_a: Option<usize>,
        node_b: usize,
        stmt_b: Option<usize>,
    ) -> bool {
        if node_a == node_b {
            match (stmt_a, stmt_b) {
                (Some(a), Some(b)) => {
                    // Preceding statement index dominates
                    a <= b
                }
                (None, Some(_)) => true,
                (Some(_), None) => false,
                (None, None) => true,
            }
        } else {
            self.dominates_node(node_a, node_b)
        }
    }

    pub fn dominates_node(&self, a: usize, b: usize) -> bool {
        if a == b {
            return true;
        }
        match (self.intervals.get(&a), self.intervals.get(&b)) {
            (Some(&(entry_a, exit_a)), Some(&(entry_b, exit_b))) => {
                entry_a <= entry_b && exit_a >= exit_b
            }
            _ => false,
        }
    }

    fn compute_dominance(&mut self, cfg: &ControlFlowGraph) {
        let entry = cfg.entry_node;
        let all_nodes: HashSet<usize> = cfg.nodes.keys().cloned().collect();
        if all_nodes.is_empty() {
            return;
        }

        // 1. Build Predecessor map
        let mut predecessors: HashMap<usize, Vec<usize>> = HashMap::new();
        for edge in &cfg.edges {
            predecessors.entry(edge.to).or_default().push(edge.from);
        }

        // 2. Run Cooper-Harvey-Kennedy Iterative Dominators Algorithm
        let mut dominators: HashMap<usize, HashSet<usize>> = HashMap::new();
        for &node in &all_nodes {
            if node == entry {
                let mut set = HashSet::new();
                set.insert(entry);
                dominators.insert(node, set);
            } else {
                dominators.insert(node, all_nodes.clone());
            }
        }

        let mut changed = true;
        while changed {
            changed = false;
            for &node in &all_nodes {
                if node == entry {
                    continue;
                }
                let preds = match predecessors.get(&node) {
                    Some(p) if !p.is_empty() => p,
                    _ => {
                        let mut new_doms = HashSet::new();
                        new_doms.insert(node);
                        if dominators.get(&node) != Some(&new_doms) {
                            dominators.insert(node, new_doms);
                            changed = true;
                        }
                        continue;
                    }
                };

                let mut new_doms = dominators.get(&preds[0]).cloned().unwrap_or_default();
                for &pred in &preds[1..] {
                    if let Some(pred_doms) = dominators.get(&pred) {
                        new_doms = new_doms.intersection(pred_doms).cloned().collect();
                    }
                }
                new_doms.insert(node);

                if dominators.get(&node) != Some(&new_doms) {
                    dominators.insert(node, new_doms);
                    changed = true;
                }
            }
        }

        // 3. Extract Immediate Dominators (IDoms)
        let mut idoms: HashMap<usize, usize> = HashMap::new();
        for &node in &all_nodes {
            if node == entry {
                continue;
            }
            if let Some(doms) = dominators.get(&node) {
                let mut candidates: Vec<usize> =
                    doms.iter().cloned().filter(|&d| d != node).collect();
                candidates.sort_by(|&a, &b| {
                    let a_dom_b = dominators.get(&b).map(|s| s.contains(&a)).unwrap_or(false);
                    let b_dom_a = dominators.get(&a).map(|s| s.contains(&b)).unwrap_or(false);
                    if a_dom_b && !b_dom_a {
                        std::cmp::Ordering::Less
                    } else if b_dom_a && !a_dom_b {
                        std::cmp::Ordering::Greater
                    } else {
                        std::cmp::Ordering::Equal
                    }
                });
                if let Some(&idom) = candidates.last() {
                    idoms.insert(node, idom);
                }
            }
        }

        // 4. Build Dominator Tree Children relations
        let mut children: HashMap<usize, Vec<usize>> = HashMap::new();
        for (&node, &parent) in &idoms {
            children.entry(parent).or_default().push(node);
        }

        // 5. DFS traversal to assign entry/exit intervals
        let mut counter = 0;
        let mut dfs_intervals = HashMap::new();
        self.dfs_assign(entry, &children, &mut counter, &mut dfs_intervals);
        self.intervals = dfs_intervals;
    }

    fn dfs_assign(
        &self,
        node: usize,
        children: &HashMap<usize, Vec<usize>>,
        counter: &mut usize,
        intervals: &mut HashMap<usize, (usize, usize)>,
    ) {
        let entry = *counter;
        *counter += 1;
        if let Some(children_nodes) = children.get(&node) {
            for &child in children_nodes {
                self.dfs_assign(child, children, counter, intervals);
            }
        }
        let exit = *counter;
        *counter += 1;
        intervals.insert(node, (entry, exit));
    }
}
