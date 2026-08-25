use crate::ast::{
    ExpressionKind, InferenceResult, InferenceScope, StatementKind, StatementNode,
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

pub struct SignerValidationRule;

impl Rule for SignerValidationRule {
    fn id(&self) -> &'static str {
        "EPIC-SEC-002"
    }

    fn name(&self) -> &'static str {
        "Signer Validation Rule"
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

        // Locate authority-like accounts from the accounts struct ONLY.
        // We consult account_field_ids to skip any local let-bindings, parameter
        // destructures, seed-byte arrays, or primitive flags that happen to share
        // an authority-sounding name (e.g. `authority_seeds`, `require_group_admin`,
        // `if let Some(admin) = admin_opt`).
        let mut authority_like_symbols = Vec::new();
        for (name, &symbol_id) in &instruction_context.symbol_table {
            // ── Origin gate ──────────────────────────────────────────────────
            // Only proceed if this identifier is a real Anchor account field.
            // Everything that isn't an account field (local bindings, params,
            // seed arrays) is silently skipped — no diagnostic, no fallback.
            if !instruction_context.account_field_ids.contains(&symbol_id) {
                continue;
            }

            let name_lower = name.to_lowercase();

            if name_lower.contains("bump")
                || name_lower.ends_with("_index")
                || name_lower == "program_id"
            {
                continue;
            }

            let mut is_pda = false;
            for (fact, _) in &instruction_context.guard_facts {
                if let GuardFact::PDA { account, .. } = fact {
                    if account.symbol_id() == Some(symbol_id) {
                        is_pda = true;
                        break;
                    }
                }
            }
            if is_pda {
                continue;
            }

            // Match typical names representing privileged authorities
            if name_lower.contains("authority")
                || name_lower.contains("admin")
                || name_lower.contains("owner")
                || name_lower.contains("manager")
                || name_lower.contains("signer")
                || name_lower.contains("initializer")
                || name_lower.contains("upgrader")
                || name_lower.contains("delegate")
            {
                authority_like_symbols.push((name.clone(), symbol_id));
            }
        }

        // Sort by name for deterministic diagnostic ordering.
        // symbol_table is a HashMap so its iteration order is random; we must
        // sort before processing to guarantee stable finding numbers across runs.
        authority_like_symbols.sort_by(|(a, _), (b, _)| a.cmp(b));

        // If there are no authority-like accounts, nothing needs to be checked
        if authority_like_symbols.is_empty() {
            return diagnostics;
        }

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
                &authority_like_symbols,
            );
        }

        diagnostics
    }
}

impl SignerValidationRule {
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
            epic_ir::IRExpression::FieldAccess { object, .. } => {
                if let Some(sym) = resolver.resolve_expr_ir(expr, ssa_state) {
                    Some(sym)
                } else {
                    self.find_initializer_source_ir(object, resolver, ssa_state)
                }
            }
            epic_ir::IRExpression::Variable(_) => resolver.resolve_expr_ir(expr, ssa_state),
            _ => None, // Note: Reference and Try aren't explicit in IR yet, they are lowered
        }
    }

    fn get_mutable_write_expression_ir(
        &self,
        instr: &epic_ir::IRInstruction,
    ) -> Option<epic_ir::IRExpression> {
        match instr {
            epic_ir::IRInstruction::Assignment(assign) => self
                .get_expr_write_target_ir(&assign.value)
                .or(Some(epic_ir::IRExpression::Variable(assign.target.clone()))),
            epic_ir::IRInstruction::Expr(expr) => self.get_expr_write_target_ir(expr),
            _ => None,
        }
    }

    fn get_expr_write_target_ir(
        &self,
        expr: &epic_ir::IRExpression,
    ) -> Option<epic_ir::IRExpression> {
        match expr {
            epic_ir::IRExpression::Call { target, method, .. } => {
                if let Some(m) = method {
                    if m == "borrow_mut" || m == "try_borrow_mut" || m == "try_borrow_mut_data" {
                        return Some(*target.clone());
                    }
                }
                None
            }
            // Compound and plain assignments: `ctx.accounts.vault.balance -= amount`
            // (lowered from syn::Expr::AssignOp / syn::Expr::Assign).
            // Walk the left-hand FieldAccess chain to find the ctx.accounts.<name>
            // account reference — that is the resource being mutated.
            epic_ir::IRExpression::Assign { left, .. } => {
                self.extract_account_from_field_path(left)
            }
            _ => None,
        }
    }

    /// Walk a nested FieldAccess expression and return the shallowest sub-expression
    /// that refers to a `ctx.accounts.<account>` account field.
    ///
    /// Examples:
    ///   ctx.accounts.vault.balance  → FieldAccess { ctx.accounts.vault, "balance" }
    ///                                → we return FieldAccess { ctx.accounts, "vault" }
    ///                                  i.e. the expression resolving to `vault`
    fn extract_account_from_field_path(
        &self,
        expr: &epic_ir::IRExpression,
    ) -> Option<epic_ir::IRExpression> {
        match expr {
            epic_ir::IRExpression::FieldAccess { object, field: _ } => {
                // If the object already resolves to ctx.accounts, this node IS the
                // account field reference we want (e.g. FieldAccess{ctx.accounts, "vault"}).
                if self.is_ctx_accounts(object) {
                    return Some(expr.clone());
                }
                // Otherwise keep descending — the account reference is deeper.
                self.extract_account_from_field_path(object)
            }
            _ => None,
        }
    }

    /// Return true if this IR expression represents `ctx.accounts`.
    fn is_ctx_accounts(&self, expr: &epic_ir::IRExpression) -> bool {
        match expr {
            epic_ir::IRExpression::FieldAccess { object, field } => {
                field == "accounts" && matches!(object.as_ref(), epic_ir::IRExpression::Variable(v) if v == "ctx")
            }
            _ => false,
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

    fn has_dominating_signer_check(
        &self,
        sym: SymbolId,
        node_id: usize,
        stmt_idx: usize,
        context: &InstructionAnalysisContext,
        dom_checker: &DominanceChecker,
        parent_map: &HashMap<SymbolId, SymbolId>,
    ) -> bool {
        context.guard_facts.iter().any(|(fact, prov)| {
            if let GuardFact::Signer(account) = fact {
                if let Some(acc_sym) = account.symbol_id() {
                    let root_acc_sym = self.trace_to_root(acc_sym, parent_map);
                    if root_acc_sym == sym {
                        let fact_node = prov.node_id.unwrap_or(0);
                        let fact_stmt = prov.statement_index;
                        return dom_checker.dominates(
                            fact_node,
                            fact_stmt,
                            node_id,
                            Some(stmt_idx),
                        );
                    }
                }
            }
            false
        })
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
        authority_like_symbols: &[(String, SymbolId)],
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

                                // Track reassignments in WDG!
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
                        authority_like_symbols,
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

            // Check if this statement performs a state modification (mutable write)
            let ir_instrs = crate::ir_converter::convert_statement_node_to_ir(stmt);
            for write_instr in ir_instrs {
                if let Some(write_expr) = self.get_mutable_write_expression_ir(&write_instr) {
                    if let Some(base_sym) = resolver.resolve_expr_ir(&write_expr, current_state) {
                        let _root_sym = self.trace_to_root(base_sym, parent_map);

                        // For each authority-like account, check if its signer validation dominates this write.
                        for (auth_name, auth_sym) in authority_like_symbols {
                            let root_auth_sym = self.trace_to_root(*auth_sym, parent_map);
                            if !self.has_dominating_signer_check(
                                root_auth_sym,
                                node_id,
                                0, // check dominance against node 0 (conservative & safe)
                                instruction_context,
                                dom_checker,
                                parent_map,
                            ) && reported_symbols.insert(root_auth_sym)
                            {
                                diagnostics.push(RuleDiagnostic {
                                        rule_id: self.id().to_string(),
                                        severity: RuleSeverity::Critical,
                                        message: format!(
                                            "Privileged instruction mutation lacks signer verification for authority-like account '{}'.",
                                            auth_name
                                        ),
                                        location: FindingLocation {
                                            file: instruction_context.file_path.clone(),
                                            line: stmt.line_number,
                                            column: 0,
                                            node_id,
                                            statement_index: None,
                                        },
                                        confidence: FactConfidence::Asserted,
                                        target_symbol: root_auth_sym,
                                    });
                            }
                        }
                    }
                }
            }
        }
    }
}
