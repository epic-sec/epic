use crate::ast::{
    ExpressionKind, ExpressionNode, InferenceResult, InferenceScope, StatementKind, StatementNode,
    TypeInferenceEngine,
};
use crate::cfg::guards::{FactConfidence, GuardFact, InstructionAnalysisContext, SymbolId};
use crate::cfg::ssa::{SSANodeState, SSAVariable};
use crate::rules::{
    AnalysisContext, DominanceChecker, FindingLocation, Rule, RuleDiagnostic, RuleSeverity,
    SymbolResolver,
};
use crate::types::TypeRegistry;
use std::collections::HashMap;

pub struct OwnerValidationRule;

impl Rule for OwnerValidationRule {
    fn id(&self) -> &'static str {
        "EPIC-SEC-001"
    }

    fn name(&self) -> &'static str {
        "Owner Validation Rule"
    }

    fn check(&self, context: &AnalysisContext) -> Vec<RuleDiagnostic> {
        let resolver = context.resolver();
        let dom_checker = context.dominance();
        let instruction_context = &context.instruction_context;
        let mut diagnostics = Vec::new();
        let mut reported_symbols = std::collections::HashSet::new();

        // Write-Dependency Graph (maps derived local symbols to their parent resource symbols)
        let mut parent_map: HashMap<SymbolId, SymbolId> = HashMap::new();

        // Simple DFS post-order topological sort
        let mut visited = std::collections::HashSet::new();
        let mut order = Vec::new();

        fn dfs(
            node_id: usize,
            cfg: &crate::cfg::ControlFlowGraph,
            visited: &mut std::collections::HashSet<usize>,
            order: &mut Vec<usize>,
        ) {
            if !visited.insert(node_id) {
                return;
            }
            for edge in &cfg.edges {
                if edge.from == node_id {
                    dfs(edge.to, cfg, visited, order);
                }
            }
            order.push(node_id);
        }

        dfs(
            instruction_context.cfg.entry_node,
            &instruction_context.cfg,
            &mut visited,
            &mut order,
        );
        order.reverse();

        for node_id in order {
            let node = match instruction_context.cfg.nodes.get(&node_id) {
                Some(n) => n,
                None => continue,
            };

            let node_ssa = match instruction_context.cfg.ssa_states.get(&node_id) {
                Some(s) => s,
                None => continue,
            };

            let mut current_state = node_ssa.start_state.clone();

            let mut version_counters = HashMap::new();
            for var in current_state.active_variables.values() {
                if let SSAVariable::Versioned { name, version } = var {
                    version_counters.insert(name.clone(), *version);
                }
            }

            self.check_statements_recursive(
                &node.statements,
                &mut current_state,
                &mut parent_map,
                &resolver,
                instruction_context,
                &dom_checker,
                node_id,
                &mut diagnostics,
                &mut reported_symbols,
                &mut version_counters,
                &context.ast_graph.registry,
            );
        }

        diagnostics
    }
}

impl OwnerValidationRule {
    fn find_initializer_source(
        &self,
        expr: &ExpressionNode,
        resolver: &SymbolResolver,
        ssa_state: &SSANodeState,
    ) -> Option<SymbolId> {
        match &expr.kind {
            ExpressionKind::MethodCall { object, method, .. } => {
                if method == "try_borrow_mut_data"
                    || method == "borrow_mut"
                    || method == "try_borrow_mut"
                {
                    return resolver.resolve_expr(object, ssa_state);
                }
                self.find_initializer_source(object, resolver, ssa_state)
            }
            ExpressionKind::Reference { expression, .. } => {
                self.find_initializer_source(expression, resolver, ssa_state)
            }
            ExpressionKind::FieldAccess { object, .. } => {
                if let Some(sym) = resolver.resolve_expr(expr, ssa_state) {
                    Some(sym)
                } else {
                    self.find_initializer_source(object, resolver, ssa_state)
                }
            }
            ExpressionKind::Identifier(_) => resolver.resolve_expr(expr, ssa_state),
            ExpressionKind::Try(inner) => self.find_initializer_source(inner, resolver, ssa_state),
            _ => None,
        }
    }

    fn get_mutable_write_expression<'a>(
        &self,
        stmt: &'a StatementNode,
    ) -> Option<&'a ExpressionNode> {
        match &stmt.kind {
            StatementKind::Expr(expr) | StatementKind::Semi(expr) => {
                self.get_expr_write_target(expr)
            }
            StatementKind::Let { initializer, .. } => self.get_expr_write_target(initializer),
            _ => None,
        }
    }

    fn get_expr_write_target<'a>(&self, expr: &'a ExpressionNode) -> Option<&'a ExpressionNode> {
        match &expr.kind {
            ExpressionKind::Assign { left, .. } => Some(left),
            ExpressionKind::MethodCall { object, method, .. } => {
                if method == "borrow_mut"
                    || method == "try_borrow_mut"
                    || method == "try_borrow_mut_data"
                {
                    Some(object)
                } else {
                    None
                }
            }
            ExpressionKind::Try(inner) => self.get_expr_write_target(inner),
            _ => None,
        }
    }

    fn trace_to_root(
        &self,
        mut sym: SymbolId,
        parent_map: &HashMap<SymbolId, SymbolId>,
    ) -> SymbolId {
        let mut visited = std::collections::HashSet::new();
        while let Some(&parent) = parent_map.get(&sym) {
            if !visited.insert(sym) {
                break;
            }
            sym = parent;
        }
        sym
    }

    fn is_account_symbol(&self, sym: SymbolId, context: &InstructionAnalysisContext) -> bool {
        context.guard_facts.iter().any(|(fact, _)| match fact {
            GuardFact::Owner { account, .. }
            | GuardFact::Signer(account)
            | GuardFact::KeyRelation { account, .. }
            | GuardFact::PDA { account, .. }
            | GuardFact::Initialized { account, .. }
            | GuardFact::Resized { account, .. }
            | GuardFact::Deallocated { account, .. } => account.symbol_id() == Some(sym),
            _ => false,
        })
    }

    fn has_dominating_owner_check(
        &self,
        sym: SymbolId,
        node_id: usize,
        stmt_idx: usize,
        context: &InstructionAnalysisContext,
        dom_checker: &DominanceChecker,
    ) -> bool {
        context.guard_facts.iter().any(|(fact, prov)| {
            if let GuardFact::Owner {
                account,
                expected_owner,
            } = fact
            {
                if account.symbol_id() == Some(sym) && self.is_valid_expected_owner(expected_owner)
                {
                    let fact_node = prov.node_id.unwrap_or(0);
                    let fact_stmt = prov.statement_index;
                    return dom_checker.dominates(fact_node, fact_stmt, node_id, Some(stmt_idx));
                }
            }
            false
        })
    }

    fn is_valid_expected_owner(&self, expected_owner: &crate::cfg::guards::FactExpression) -> bool {
        match expected_owner {
            crate::cfg::guards::FactExpression::Literal(val) => {
                val == "program_id"
                    || val == "ID"
                    || val == "crate::ID"
                    || val == "super::ID"
                    || val == "spl_token"
                    || val == "token_program"
                    || val.ends_with("::ID")
                    || val.ends_with("::id")
                    || val.len() >= 32
            }
            crate::cfg::guards::FactExpression::Unknown => false,
            _ => true,
        }
    }

    fn check_statements_recursive(
        &self,
        stmts: &[StatementNode],
        current_state: &mut SSANodeState,
        parent_map: &mut HashMap<SymbolId, SymbolId>,
        resolver: &SymbolResolver,
        instruction_context: &InstructionAnalysisContext,
        dom_checker: &DominanceChecker,
        node_id: usize,
        diagnostics: &mut Vec<RuleDiagnostic>,
        reported_symbols: &mut std::collections::HashSet<SymbolId>,
        version_counters: &mut HashMap<String, usize>,
        registry: &TypeRegistry,
    ) {
        for stmt in stmts {
            match &stmt.kind {
                StatementKind::Let {
                    name, initializer, ..
                } => {
                    let next_ver = version_counters.entry(name.clone()).or_insert(0);
                    *next_ver += 1;
                    let ver_num = *next_ver;
                    let ssa_var = SSAVariable::Versioned {
                        name: name.clone(),
                        version: ver_num,
                    };

                    let mut inference_scope = InferenceScope::new();
                    for (v_name, active_var) in &current_state.active_variables {
                        if let Some(ty) = current_state.variable_types.get(&active_var.to_string())
                        {
                            inference_scope.insert(v_name.clone(), ty.clone());
                        }
                    }

                    let engine = TypeInferenceEngine::new(registry, &inference_scope);
                    if let InferenceResult::Ok(type_ref) = engine.infer(initializer) {
                        current_state
                            .variable_types
                            .insert(ssa_var.to_string(), type_ref);
                    }

                    current_state.active_variables.insert(name.clone(), ssa_var);

                    // Track WDG parent mapping
                    let local_sym = resolver.get_symbol_by_name(name);
                    if let Some(l_sym) = local_sym {
                        if let Some(parent_sym) =
                            self.find_initializer_source(initializer, resolver, current_state)
                        {
                            parent_map.insert(l_sym, parent_sym);
                        }
                    }
                }
                StatementKind::Expr(expr) | StatementKind::Semi(expr) => {
                    // Task 5 reassignment tracking
                    if let ExpressionKind::Assign { left, right } = &expr.kind {
                        if let ExpressionKind::Identifier(name) = &left.kind {
                            if current_state.active_variables.contains_key(name) {
                                let next_ver = version_counters.entry(name.clone()).or_insert(0);
                                *next_ver += 1;
                                let ver_num = *next_ver;
                                let ssa_var = SSAVariable::Versioned {
                                    name: name.clone(),
                                    version: ver_num,
                                };

                                let mut inference_scope = InferenceScope::new();
                                for (v_name, active_var) in &current_state.active_variables {
                                    if let Some(ty) =
                                        current_state.variable_types.get(&active_var.to_string())
                                    {
                                        inference_scope.insert(v_name.clone(), ty.clone());
                                    }
                                }

                                let engine = TypeInferenceEngine::new(registry, &inference_scope);
                                if let InferenceResult::Ok(type_ref) = engine.infer(right) {
                                    current_state
                                        .variable_types
                                        .insert(ssa_var.to_string(), type_ref);
                                }

                                current_state.active_variables.insert(name.clone(), ssa_var);

                                // Track reassignments in WDG!
                                let local_sym = resolver.get_symbol_by_name(name);
                                if let Some(l_sym) = local_sym {
                                    if let Some(parent_sym) =
                                        self.find_initializer_source(right, resolver, current_state)
                                    {
                                        parent_map.insert(l_sym, parent_sym);
                                    }
                                }
                            }
                        }
                    }
                }
                StatementKind::Block(inner_stmts) => {
                    let mut before_block_versions = HashMap::new();
                    for (name, val) in &current_state.active_variables {
                        before_block_versions.insert(name.clone(), val.clone());
                    }

                    let mut block_declared = Vec::new();
                    for inner_stmt in inner_stmts {
                        if let StatementKind::Let { name, .. } = &inner_stmt.kind {
                            block_declared.push(name.clone());
                        }
                    }

                    let mut before_block_parents = HashMap::new();
                    for name in &block_declared {
                        if let Some(sym) = resolver.get_symbol_by_name(name) {
                            if let Some(&parent) = parent_map.get(&sym) {
                                before_block_parents.insert(sym, parent);
                            }
                        }
                    }

                    // Task 3 recursive traversal
                    self.check_statements_recursive(
                        inner_stmts,
                        current_state,
                        parent_map,
                        resolver,
                        instruction_context,
                        dom_checker,
                        node_id,
                        diagnostics,
                        reported_symbols,
                        version_counters,
                        registry,
                    );

                    // Task 4 shadow pop restoration of active variables and parent maps
                    for name in &block_declared {
                        if let Some(old_val) = before_block_versions.get(name) {
                            current_state
                                .active_variables
                                .insert(name.clone(), old_val.clone());
                        } else {
                            current_state.active_variables.remove(name);
                        }

                        if let Some(sym) = resolver.get_symbol_by_name(name) {
                            if let Some(&parent) = before_block_parents.get(&sym) {
                                parent_map.insert(sym, parent);
                            } else {
                                parent_map.remove(&sym);
                            }
                        }
                    }
                }
                _ => {}
            }

            // Detect pointer reassignments (aliases) to avoid false positive writes
            let mut skip_write_check = false;
            if let StatementKind::Expr(expr) | StatementKind::Semi(expr) = &stmt.kind {
                if let ExpressionKind::Assign { left, right } = &expr.kind {
                    if let ExpressionKind::Identifier(_) = &left.kind {
                        if let Some(right_sym) =
                            self.find_initializer_source(right, resolver, current_state)
                        {
                            let root_sym = self.trace_to_root(right_sym, parent_map);
                            if self.is_account_symbol(root_sym, instruction_context) {
                                skip_write_check = true;
                            }
                        }
                    }
                }
            }

            // Second, check for mutable write vulnerability
            if !skip_write_check {
                if let Some(write_expr) = self.get_mutable_write_expression(stmt) {
                    if let Some(base_sym) = resolver.resolve_expr(write_expr, current_state) {
                        let root_sym = self.trace_to_root(base_sym, parent_map);
                        if self.is_account_symbol(root_sym, instruction_context)
                            && !self.has_dominating_owner_check(
                                root_sym,
                                node_id,
                                0, // check dominance against node 0 (conservative & safe)
                                instruction_context,
                                dom_checker,
                            )
                            && reported_symbols.insert(root_sym)
                        {
                            let sym_name = resolver
                                .name_to_symbol
                                .iter()
                                .find(|(_, &id)| id == root_sym)
                                .map(|(name, _)| name.clone())
                                .unwrap_or_else(|| format!("{:?}", root_sym));
                            diagnostics.push(RuleDiagnostic {
                                        rule_id: self.id().to_string(),
                                        severity: RuleSeverity::Critical,
                                        message: format!(
                                            "Mutable write to account '{}' lacks program owner verification.",
                                            sym_name
                                        ),
                                        location: FindingLocation {
                                            file: instruction_context.file_path.clone(),
                                            line: stmt.line_number,
                                            column: 0,
                                            node_id,
                                            statement_index: None,
                                        },
                                        confidence: FactConfidence::Asserted,
                                        target_symbol: root_sym,
                                    });
                        }
                    }
                }
            }
        }
    }
}
