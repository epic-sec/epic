use crate::ast::{
    ExpressionKind, InferenceResult, InferenceScope, StatementKind, StatementNode,
    TypeInferenceEngine,
};
use crate::cfg::guards::{FactConfidence, GuardFact, InstructionAnalysisContext, SymbolId};
use crate::cfg::ssa::{SSANodeState, SSAVariable};
use crate::rules::{
    AnalysisContext, FindingLocation, Rule, RuleDiagnostic, RuleSeverity, SymbolResolver,
};
use crate::types::TypeRegistry;
use std::collections::HashMap;
use std::collections::HashSet;

pub struct MissingPostCpiReloadRule;

impl Rule for MissingPostCpiReloadRule {
    fn id(&self) -> &'static str {
        "EPIC-SEC-003"
    }

    fn name(&self) -> &'static str {
        "Missing Post-CPI Reload Rule"
    }

    fn check(&self, context: &AnalysisContext) -> Vec<RuleDiagnostic> {
        let resolver = context.resolver();
        let instruction_context = &context.instruction_context;
        let mut diagnostics = Vec::new();
        let mut reported_symbols = HashSet::new();

        // Write-Dependency Graph (maps derived local symbols to their parent resource symbols)
        let mut parent_map: HashMap<SymbolId, SymbolId> = HashMap::new();

        // Simple DFS post-order topological sort to process CFG basic blocks
        let mut visited = HashSet::new();
        let mut order = Vec::new();

        fn dfs(
            node_id: usize,
            cfg: &crate::cfg::ControlFlowGraph,
            visited: &mut HashSet<usize>,
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

        // Pass 1: Build the parent maps (variable alias WDG tracking)
        for &node_id in &order {
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

            self.build_parent_maps_recursive(
                &node.statements,
                &mut current_state,
                &mut parent_map,
                &resolver,
                &mut version_counters,
                &context.ast_graph.registry,
            );
        }

        // Pass 2: Extract all CPI calls, account reloads, and state accesses per basic block
        let mut cpi_locations = Vec::new(); // elements are (node_id, stmt_index, HashSet<SymbolId>)
        let mut reload_locations: HashMap<SymbolId, Vec<(usize, usize)>> = HashMap::new();
        let mut access_locations: HashMap<SymbolId, Vec<(usize, usize, usize)>> = HashMap::new(); // (node_id, stmt_idx, line_number)

        for &node_id in &order {
            let node = match instruction_context.cfg.nodes.get(&node_id) {
                Some(n) => n,
                None => continue,
            };

            let node_ssa = match instruction_context.cfg.ssa_states.get(&node_id) {
                Some(s) => s,
                None => continue,
            };

            let mut current_state = node_ssa.start_state.clone();

            for (stmt_idx, stmt) in node.statements.iter().enumerate() {
                // Determine active variables for the SSA state at this statement
                // Note: current_state matches statement start state

                let ir_instrs = crate::ir_converter::convert_statement_node_to_ir(stmt);

                let is_cpi = ir_instrs
                    .iter()
                    .any(|instr| self.is_cpi_instruction_ir(instr));
                if is_cpi {
                    let mut cpi_accessed = HashSet::new();
                    for instr in &ir_instrs {
                        for sym in self.find_accessed_symbols_ir(
                            instr,
                            &resolver,
                            &current_state,
                            &parent_map,
                        ) {
                            cpi_accessed.insert(sym);
                        }
                    }
                    cpi_locations.push((node_id, stmt_idx, cpi_accessed));
                }

                // Check for reload calls in expression
                for instr in &ir_instrs {
                    let expr_reloads =
                        self.find_reload_symbols_ir(instr, &resolver, &current_state, &parent_map);
                    for reloaded_sym in expr_reloads {
                        if self.is_account_symbol(reloaded_sym, instruction_context) {
                            reload_locations
                                .entry(reloaded_sym)
                                .or_default()
                                .push((node_id, stmt_idx));
                        }
                    }
                }

                // Check for state accesses (reads or writes)
                for instr in &ir_instrs {
                    let expr_accesses = self.find_accessed_symbols_ir(
                        instr,
                        &resolver,
                        &current_state,
                        &parent_map,
                    );
                    for accessed_sym in expr_accesses {
                        if self.is_account_symbol(accessed_sym, instruction_context) {
                            access_locations.entry(accessed_sym).or_default().push((
                                node_id,
                                stmt_idx,
                                stmt.line_number,
                            ));
                        }
                    }
                }

                // Update active variables for let assignments
                self.update_ssa_state_for_stmt(
                    stmt,
                    &mut current_state,
                    &context.ast_graph.registry,
                    &resolver,
                );
            }
        }

        // Pass 3: Perform path-sensitive reachability analysis for each account
        if cpi_locations.is_empty() {
            return diagnostics;
        }

        // Sort by SymbolId for deterministic diagnostic ordering.
        // access_locations is a HashMap so its iteration order is random; sorting
        // by SymbolId produces the same sequence of findings across every run.
        let mut sorted_accesses: Vec<(SymbolId, Vec<(usize, usize, usize)>)> =
            access_locations.into_iter().collect();
        sorted_accesses.sort_by_key(|(sym, _)| sym.0);

        for (acc_sym, accesses) in sorted_accesses {
            let empty_reloads = Vec::new();
            let reloads = reload_locations.get(&acc_sym).unwrap_or(&empty_reloads);

            for (node_access, stmt_access, line_number) in accesses {
                // Check if any path from a CPI call reaches this access without a reload in between
                for (node_cpi, stmt_cpi, cpi_accessed_symbols) in &cpi_locations {
                    if !cpi_accessed_symbols.contains(&acc_sym) {
                        continue;
                    }
                    let mut path_visited = HashSet::new();
                    if self.is_access_reachable_from_cpi_without_reload(
                        *node_cpi,
                        *stmt_cpi,
                        node_access,
                        stmt_access,
                        reloads,
                        &instruction_context.cfg,
                        &mut path_visited,
                    ) {
                        // Locate the original account name from symbol table for clear messaging
                        let mut acc_name = format!("SymbolId({})", acc_sym.0);
                        for (name, &symbol_id) in &instruction_context.symbol_table {
                            if symbol_id == acc_sym {
                                acc_name = name.clone();
                                break;
                            }
                        }

                        if reported_symbols.insert(acc_sym) {
                            diagnostics.push(RuleDiagnostic {
                                rule_id: self.id().to_string(),
                                severity: RuleSeverity::Critical,
                                message: format!(
                                    "State access to '{}' occurs after a CPI mutation without reloading. The account's in-memory data layout may be stale.",
                                    acc_name
                                ),
                                location: FindingLocation {
                                    file: instruction_context.file_path.clone(),
                                    line: line_number,
                                    column: 0,
                                    node_id: node_access,
                                    statement_index: Some(stmt_access),
                                },
                                confidence: FactConfidence::Asserted,
                                target_symbol: acc_sym,
                            });
                        }
                    }
                }
            }
        }

        diagnostics
    }
}

impl MissingPostCpiReloadRule {
    fn trace_to_root(
        &self,
        mut sym: SymbolId,
        parent_map: &HashMap<SymbolId, SymbolId>,
    ) -> SymbolId {
        let mut visited = HashSet::new();
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

    fn build_parent_maps_recursive(
        &self,
        stmts: &[StatementNode],
        current_state: &mut SSANodeState,
        parent_map: &mut HashMap<SymbolId, SymbolId>,
        resolver: &SymbolResolver,
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

                    let local_sym = resolver.get_symbol_by_name(name);
                    if let Some(l_sym) = local_sym {
                        let ir_initializer =
                            crate::ir_converter::convert_expr_node_to_ir(initializer);
                        if let Some(parent_sym) = self.find_initializer_source_ir(
                            &ir_initializer,
                            resolver,
                            current_state,
                        ) {
                            parent_map.insert(l_sym, parent_sym);
                        }
                    }
                }
                StatementKind::Expr(expr) | StatementKind::Semi(expr) => {
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

                                let local_sym = resolver.get_symbol_by_name(name);
                                if let Some(l_sym) = local_sym {
                                    let ir_right =
                                        crate::ir_converter::convert_expr_node_to_ir(right);
                                    if let Some(parent_sym) = self.find_initializer_source_ir(
                                        &ir_right,
                                        resolver,
                                        current_state,
                                    ) {
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

                    self.build_parent_maps_recursive(
                        inner_stmts,
                        current_state,
                        parent_map,
                        resolver,
                        version_counters,
                        registry,
                    );

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
        }
    }

    fn find_initializer_source_ir(
        &self,
        expr: &epic_ir::IRExpression,
        resolver: &SymbolResolver,
        ssa_state: &SSANodeState,
    ) -> Option<SymbolId> {
        match expr {
            epic_ir::IRExpression::Call { target, method, .. } => {
                if let Some(m) = method {
                    if m == "try_borrow_mut_data" || m == "borrow_mut" || m == "try_borrow_mut" {
                        return resolver.resolve_expr_ir(target, ssa_state);
                    }
                }
                self.find_initializer_source_ir(target, resolver, ssa_state)
            }
            epic_ir::IRExpression::Reference { expression, .. } => {
                self.find_initializer_source_ir(expression, resolver, ssa_state)
            }
            epic_ir::IRExpression::Try(inner) => {
                self.find_initializer_source_ir(inner, resolver, ssa_state)
            }
            epic_ir::IRExpression::FieldAccess { object, .. } => {
                if let Some(sym) = resolver.resolve_expr_ir(expr, ssa_state) {
                    Some(sym)
                } else {
                    self.find_initializer_source_ir(object, resolver, ssa_state)
                }
            }
            epic_ir::IRExpression::Variable(_) => resolver.resolve_expr_ir(expr, ssa_state),
            _ => None,
        }
    }

    fn is_cpi_instruction_ir(&self, instr: &epic_ir::IRInstruction) -> bool {
        match instr {
            epic_ir::IRInstruction::Expr(expr) => self.is_cpi_expression_ir(expr),
            epic_ir::IRInstruction::Assignment(assign) => self.is_cpi_expression_ir(&assign.value),
            _ => false,
        }
    }

    fn is_cpi_expression_ir(&self, expr: &epic_ir::IRExpression) -> bool {
        match expr {
            epic_ir::IRExpression::Call {
                method,
                target,
                arguments,
            } => {
                if let Some(m) = method {
                    let name = m.to_lowercase();
                    if (name.contains("invoke")
                        || name.contains("transfer")
                        || name.contains("mint_to")
                        || name.contains("burn")
                        || name.contains("cpi")
                        || name.contains("cross_program_invocation"))
                        && !name.contains("reload")
                    {
                        return true;
                    }
                }
                self.is_cpi_expression_ir(target)
                    || arguments.iter().any(|arg| self.is_cpi_expression_ir(arg))
            }
            epic_ir::IRExpression::FieldAccess { object, .. } => self.is_cpi_expression_ir(object),
            epic_ir::IRExpression::BinaryOp { lhs, rhs, .. } => {
                self.is_cpi_expression_ir(lhs) || self.is_cpi_expression_ir(rhs)
            }
            epic_ir::IRExpression::Reference { expression, .. } => {
                self.is_cpi_expression_ir(expression)
            }
            epic_ir::IRExpression::Dereference(inner) => self.is_cpi_expression_ir(inner),
            epic_ir::IRExpression::Try(inner) => self.is_cpi_expression_ir(inner),
            epic_ir::IRExpression::Assign { left, right } => {
                self.is_cpi_expression_ir(left) || self.is_cpi_expression_ir(right)
            }
            _ => false,
        }
    }

    fn find_reload_symbols_ir(
        &self,
        instr: &epic_ir::IRInstruction,
        resolver: &SymbolResolver,
        ssa_state: &SSANodeState,
        parent_map: &HashMap<SymbolId, SymbolId>,
    ) -> Vec<SymbolId> {
        match instr {
            epic_ir::IRInstruction::Expr(expr) => {
                self.find_reload_symbols_expr_ir(expr, resolver, ssa_state, parent_map)
            }
            epic_ir::IRInstruction::Assignment(assign) => {
                self.find_reload_symbols_expr_ir(&assign.value, resolver, ssa_state, parent_map)
            }
            _ => Vec::new(),
        }
    }

    fn find_reload_symbols_expr_ir(
        &self,
        expr: &epic_ir::IRExpression,
        resolver: &SymbolResolver,
        ssa_state: &SSANodeState,
        parent_map: &HashMap<SymbolId, SymbolId>,
    ) -> Vec<SymbolId> {
        let mut reloads = Vec::new();
        match expr {
            epic_ir::IRExpression::Call {
                method,
                target,
                arguments,
            } => {
                if let Some(m) = method {
                    if m == "reload" || m.ends_with("::reload") {
                        if let Some(base_sym) = resolver.resolve_expr_ir(target, ssa_state) {
                            let root_sym = self.trace_to_root(base_sym, parent_map);
                            reloads.push(root_sym);
                        }
                        for arg in arguments {
                            if let Some(base_sym) = resolver.resolve_expr_ir(arg, ssa_state) {
                                let root_sym = self.trace_to_root(base_sym, parent_map);
                                reloads.push(root_sym);
                            }
                        }
                    }
                }
                reloads.extend(
                    self.find_reload_symbols_expr_ir(target, resolver, ssa_state, parent_map),
                );
                for arg in arguments {
                    reloads.extend(
                        self.find_reload_symbols_expr_ir(arg, resolver, ssa_state, parent_map),
                    );
                }
            }
            epic_ir::IRExpression::FieldAccess { object, .. } => {
                reloads.extend(
                    self.find_reload_symbols_expr_ir(object, resolver, ssa_state, parent_map),
                );
            }
            epic_ir::IRExpression::BinaryOp { lhs, rhs, .. } => {
                reloads
                    .extend(self.find_reload_symbols_expr_ir(lhs, resolver, ssa_state, parent_map));
                reloads
                    .extend(self.find_reload_symbols_expr_ir(rhs, resolver, ssa_state, parent_map));
            }
            epic_ir::IRExpression::Reference { expression, .. } => {
                reloads.extend(
                    self.find_reload_symbols_expr_ir(expression, resolver, ssa_state, parent_map),
                );
            }
            epic_ir::IRExpression::Dereference(inner) => {
                reloads.extend(
                    self.find_reload_symbols_expr_ir(inner, resolver, ssa_state, parent_map),
                );
            }
            epic_ir::IRExpression::Try(inner) => {
                reloads.extend(
                    self.find_reload_symbols_expr_ir(inner, resolver, ssa_state, parent_map),
                );
            }
            epic_ir::IRExpression::Assign { left, right } => {
                reloads.extend(
                    self.find_reload_symbols_expr_ir(left, resolver, ssa_state, parent_map),
                );
                reloads.extend(
                    self.find_reload_symbols_expr_ir(right, resolver, ssa_state, parent_map),
                );
            }
            _ => {}
        }
        reloads
    }

    fn find_accessed_symbols_ir(
        &self,
        instr: &epic_ir::IRInstruction,
        resolver: &SymbolResolver,
        ssa_state: &SSANodeState,
        parent_map: &HashMap<SymbolId, SymbolId>,
    ) -> Vec<SymbolId> {
        match instr {
            epic_ir::IRInstruction::Expr(expr) => {
                self.find_accessed_symbols_expr_ir(expr, resolver, ssa_state, parent_map)
            }
            epic_ir::IRInstruction::Assignment(assign) => {
                let mut accesses = self.find_accessed_symbols_expr_ir(
                    &assign.value,
                    resolver,
                    ssa_state,
                    parent_map,
                );
                // The target of the assignment is also accessed
                let target_expr = epic_ir::IRExpression::Variable(assign.target.clone());
                accesses.extend(self.find_accessed_symbols_expr_ir(
                    &target_expr,
                    resolver,
                    ssa_state,
                    parent_map,
                ));
                accesses
            }
            _ => Vec::new(),
        }
    }

    fn find_accessed_symbols_expr_ir(
        &self,
        expr: &epic_ir::IRExpression,
        resolver: &SymbolResolver,
        ssa_state: &SSANodeState,
        parent_map: &HashMap<SymbolId, SymbolId>,
    ) -> Vec<SymbolId> {
        let mut accesses = Vec::new();
        match expr {
            epic_ir::IRExpression::FieldAccess { object, field } => {
                if field != "key" && field != "key_ref" {
                    if let Some(base_sym) = resolver.resolve_expr_ir(expr, ssa_state) {
                        let root_sym = self.trace_to_root(base_sym, parent_map);
                        accesses.push(root_sym);
                    } else if let Some(base_sym) = resolver.resolve_expr_ir(object, ssa_state) {
                        let root_sym = self.trace_to_root(base_sym, parent_map);
                        accesses.push(root_sym);
                    }
                }
                accesses.extend(
                    self.find_accessed_symbols_expr_ir(object, resolver, ssa_state, parent_map),
                );
            }
            epic_ir::IRExpression::Call {
                method,
                target,
                arguments,
            } => {
                if let Some(m) = method {
                    if m == "reload" || m.ends_with("::reload") {
                        // Do not recurse into reload calls as they are validation markers
                    } else {
                        if m != "key" && m != "key_ref" {
                            if let Some(base_sym) = resolver.resolve_expr_ir(target, ssa_state) {
                                let root_sym = self.trace_to_root(base_sym, parent_map);
                                accesses.push(root_sym);
                            }
                        }
                        accesses.extend(self.find_accessed_symbols_expr_ir(
                            target, resolver, ssa_state, parent_map,
                        ));
                        for arg in arguments {
                            accesses.extend(self.find_accessed_symbols_expr_ir(
                                arg, resolver, ssa_state, parent_map,
                            ));
                        }
                    }
                } else {
                    accesses.extend(
                        self.find_accessed_symbols_expr_ir(target, resolver, ssa_state, parent_map),
                    );
                    for arg in arguments {
                        accesses.extend(
                            self.find_accessed_symbols_expr_ir(
                                arg, resolver, ssa_state, parent_map,
                            ),
                        );
                    }
                }
            }
            epic_ir::IRExpression::Variable(name) => {
                if name != "key" && name != "true" && name != "false" {
                    if let Some(base_sym) = resolver.resolve_expr_ir(expr, ssa_state) {
                        let root_sym = self.trace_to_root(base_sym, parent_map);
                        accesses.push(root_sym);
                    }
                }
            }
            epic_ir::IRExpression::BinaryOp { lhs, rhs, .. } => {
                accesses.extend(
                    self.find_accessed_symbols_expr_ir(lhs, resolver, ssa_state, parent_map),
                );
                accesses.extend(
                    self.find_accessed_symbols_expr_ir(rhs, resolver, ssa_state, parent_map),
                );
            }
            epic_ir::IRExpression::Reference { expression, .. } => {
                accesses.extend(
                    self.find_accessed_symbols_expr_ir(expression, resolver, ssa_state, parent_map),
                );
            }
            epic_ir::IRExpression::Dereference(inner) => {
                accesses.extend(
                    self.find_accessed_symbols_expr_ir(inner, resolver, ssa_state, parent_map),
                );
            }
            epic_ir::IRExpression::Try(inner) => {
                accesses.extend(
                    self.find_accessed_symbols_expr_ir(inner, resolver, ssa_state, parent_map),
                );
            }
            epic_ir::IRExpression::Assign { left, right } => {
                accesses.extend(
                    self.find_accessed_symbols_expr_ir(left, resolver, ssa_state, parent_map),
                );
                accesses.extend(
                    self.find_accessed_symbols_expr_ir(right, resolver, ssa_state, parent_map),
                );
            }
            _ => {}
        }
        accesses
    }

    fn update_ssa_state_for_stmt(
        &self,
        stmt: &StatementNode,
        current_state: &mut SSANodeState,
        registry: &TypeRegistry,
        _resolver: &SymbolResolver,
    ) {
        match &stmt.kind {
            StatementKind::Let {
                name, initializer, ..
            } => {
                let ssa_var = SSAVariable::Versioned {
                    name: name.clone(),
                    version: 0, // placeholder since active lookup matches name
                };
                let mut inference_scope = InferenceScope::new();
                for (v_name, active_var) in &current_state.active_variables {
                    if let Some(ty) = current_state.variable_types.get(&active_var.to_string()) {
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
            }
            StatementKind::Expr(expr) | StatementKind::Semi(expr) => {
                if let ExpressionKind::Assign { left, right } = &expr.kind {
                    if let ExpressionKind::Identifier(name) = &left.kind {
                        if current_state.active_variables.contains_key(name) {
                            let ssa_var = SSAVariable::Versioned {
                                name: name.clone(),
                                version: 0,
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
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Path-sensitive reachability check: searches for a path from a CPI statement
    /// to an access statement that does NOT contain any reload of the account.
    fn is_access_reachable_from_cpi_without_reload(
        &self,
        node_cpi: usize,
        stmt_cpi: usize,
        node_access: usize,
        stmt_access: usize,
        reloads: &[(usize, usize)],
        cfg: &crate::cfg::ControlFlowGraph,
        visited: &mut HashSet<usize>,
    ) -> bool {
        // If start and target are the same node
        if node_cpi == node_access {
            if stmt_cpi < stmt_access {
                // Check if any reload occurs strictly between the CPI and the access
                let has_reload_between = reloads
                    .iter()
                    .any(|&(rn, rs)| rn == node_cpi && rs > stmt_cpi && rs < stmt_access);
                return !has_reload_between;
            }
            return false;
        }

        // If a reload happens in node_cpi AFTER the CPI call, the path leaving node_cpi is blocked
        let has_reload_after_cpi_in_start = reloads
            .iter()
            .any(|&(rn, rs)| rn == node_cpi && rs > stmt_cpi);
        if has_reload_after_cpi_in_start {
            return false;
        }

        // Start path traversal DFS
        self.traverse_reachability_dfs(node_cpi, node_access, stmt_access, reloads, cfg, visited)
    }

    fn traverse_reachability_dfs(
        &self,
        current_node: usize,
        target_node: usize,
        stmt_access: usize,
        reloads: &[(usize, usize)],
        cfg: &crate::cfg::ControlFlowGraph,
        visited: &mut HashSet<usize>,
    ) -> bool {
        if !visited.insert(current_node) {
            return false;
        }

        // If we reached the target node containing the access
        if current_node == target_node {
            // Path is vulnerable if there is no reload in the target node BEFORE the access
            let has_reload_before_access = reloads
                .iter()
                .any(|&(rn, rs)| rn == target_node && rs < stmt_access);
            return !has_reload_before_access;
        }

        // If this intermediate node contains a reload, the path is blocked here
        let has_reload_in_node = reloads.iter().any(|&(rn, _)| rn == current_node);
        if has_reload_in_node {
            return false;
        }

        // Traverse to successors
        for edge in &cfg.edges {
            if edge.from == current_node
                && self.traverse_reachability_dfs(
                    edge.to,
                    target_node,
                    stmt_access,
                    reloads,
                    cfg,
                    visited,
                )
            {
                return true;
            }
        }

        false
    }
}
