use crate::ast::{
    ExpressionKind, ExpressionNode, InferenceResult, InferenceScope, StatementKind, StatementNode,
    TypeInferenceEngine,
};
use crate::cfg::guards::{FactConfidence, SymbolId};
use crate::cfg::ssa::{SSANodeState, SSAVariable};
use crate::rules::{
    AnalysisContext, DominanceChecker, FindingLocation, Rule, RuleDiagnostic, RuleSeverity,
    SymbolResolver,
};
use crate::types::{StructDef, TypeDef, TypeRef, TypeRegistry};
use std::collections::HashMap;
use std::collections::HashSet;

pub struct ArbitraryCpiTargetRule;

impl Rule for ArbitraryCpiTargetRule {
    fn id(&self) -> &'static str {
        "EPIC-SEC-005"
    }

    fn name(&self) -> &'static str {
        "Arbitrary CPI Target Program Validation"
    }

    fn check(&self, context: &AnalysisContext) -> Vec<RuleDiagnostic> {
        let resolver = context.resolver();
        let dom_checker = context.dominance();
        let instruction_context = &context.instruction_context;
        let mut diagnostics = Vec::new();
        let mut reported_symbols = HashSet::new();

        // Write-Dependency Graph for tracking aliases in SSA form
        let mut var_to_parent_var: HashMap<SSAVariable, SSAVariable> = HashMap::new();
        let mut var_to_root_symbol: HashMap<SSAVariable, SymbolId> = HashMap::new();

        // Perform topological sort on CFG
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

        // Locate accounts struct definition to check static validation (Program type and attributes)
        let struct_def = self.find_context_struct(context);

        // Pass 1: Build parent maps (variable aliases)
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
                &mut var_to_parent_var,
                &mut var_to_root_symbol,
                &resolver,
                &mut version_counters,
                &context.ast_graph.registry,
                struct_def,
                instruction_context,
            );
        }

        // Pass 2: Search for CPI statements and inspect target programs
        for &node_id in &order {
            let node = match instruction_context.cfg.nodes.get(&node_id) {
                Some(n) => n,
                None => continue,
            };

            let node_ssa = match instruction_context.cfg.ssa_states.get(&node_id) {
                Some(s) => s,
                None => continue,
            };

            for (stmt_idx, stmt) in node.statements.iter().enumerate() {
                let state_before = if stmt_idx == 0 {
                    &node_ssa.start_state
                } else {
                    &node_ssa.statement_states[stmt_idx - 1]
                };

                // If this is a CPI statement, extract all target program candidates
                let ir_instrs = crate::ir_converter::convert_statement_node_to_ir(stmt);
                for instr in &ir_instrs {
                    let target_exprs = self.get_cpi_targets_ir(instr);
                    for target_expr in target_exprs {
                        if let Some(root_sym) = self.get_root_symbol_ir(
                            target_expr,
                            state_before,
                            &resolver,
                            &var_to_parent_var,
                            &var_to_root_symbol,
                        ) {
                            // Locate program names associated with this root symbol
                            let mut program_names = Vec::new();
                            for (name, &symbol_id) in &instruction_context.symbol_table {
                                if symbol_id == root_sym {
                                    program_names.push(name.clone());
                                }
                            }

                            // Also check if any active variables trace to this root symbol
                            for (var_name, ssa_var) in &state_before.active_variables {
                                if let Some(r_sym) = self.trace_ssa_to_root(
                                    ssa_var.clone(),
                                    &var_to_parent_var,
                                    &var_to_root_symbol,
                                ) {
                                    if r_sym == root_sym {
                                        program_names.push(var_name.clone());
                                    }
                                }
                            }

                            // Determine if it is a program that needs validation
                            let is_prog = program_names
                                .iter()
                                .any(|name| self.is_program_symbol(name, struct_def));

                            if is_prog {
                                // Check static validations
                                let mut is_validated = false;

                                if let Some(s_def) = struct_def {
                                    for name in &program_names {
                                        if let Some(field) =
                                            s_def.fields.iter().find(|f| &f.name == name)
                                        {
                                            if self.is_struct_field_validated(field) {
                                                is_validated = true;
                                                break;
                                            }
                                        }
                                    }
                                }

                                // Check dominant imperative checks if not statically validated
                                if !is_validated
                                    && self.is_validation_dominating(
                                        root_sym,
                                        node_id,
                                        stmt_idx,
                                        &instruction_context.cfg,
                                        &dom_checker,
                                        &resolver,
                                        &var_to_parent_var,
                                        &var_to_root_symbol,
                                    )
                                {
                                    is_validated = true;
                                }

                                if !is_validated && reported_symbols.insert(root_sym) {
                                    let mut prog_name = format!("SymbolId({})", root_sym.0);
                                    for (name, &symbol_id) in &instruction_context.symbol_table {
                                        if symbol_id == root_sym {
                                            prog_name = name.clone();
                                            break;
                                        }
                                    }

                                    diagnostics.push(RuleDiagnostic {
                                        rule_id: self.id().to_string(),
                                        severity: RuleSeverity::Critical,
                                        message: format!(
                                            "Arbitrary CPI target program validation missing for program account '{}'. The program must be validated via static types (Program<'info, T>) or imperative checks (require!) dominating the invocation.",
                                            prog_name
                                        ),
                                        location: FindingLocation {
                                            file: instruction_context.file_path.clone(),
                                            line: stmt.line_number,
                                            column: 0,
                                            node_id,
                                            statement_index: Some(stmt_idx),
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

        diagnostics
    }
}

impl ArbitraryCpiTargetRule {
    fn trace_ssa_to_root(
        &self,
        mut var: SSAVariable,
        var_to_parent_var: &HashMap<SSAVariable, SSAVariable>,
        var_to_root_symbol: &HashMap<SSAVariable, SymbolId>,
    ) -> Option<SymbolId> {
        let mut visited = HashSet::new();
        while !visited.contains(&var) {
            visited.insert(var.clone());
            if let Some(&root_sym) = var_to_root_symbol.get(&var) {
                return Some(root_sym);
            }
            if let Some(parent) = var_to_parent_var.get(&var) {
                var = parent.clone();
            } else {
                break;
            }
        }
        None
    }

    fn is_root_symbol(
        &self,
        sym_id: SymbolId,
        _resolver: &SymbolResolver,
        struct_def: Option<&StructDef>,
        instruction_context: &crate::cfg::guards::InstructionAnalysisContext,
    ) -> bool {
        for (name, &id) in &instruction_context.symbol_table {
            if id == sym_id {
                if let Some(s) = struct_def {
                    if s.fields.iter().any(|f| f.name == *name) {
                        return true;
                    }
                }
                if self.is_program_symbol(name, struct_def) {
                    return true;
                }
            }
        }
        false
    }

    fn find_active_variable_ir(
        &self,
        expr: &epic_ir::IRExpression,
        ssa_state: &SSANodeState,
    ) -> Option<SSAVariable> {
        match expr {
            epic_ir::IRExpression::Variable(name) => ssa_state.active_variables.get(name).cloned(),
            epic_ir::IRExpression::Call { target, method, .. } => {
                if let Some(m) = method {
                    if m == "to_account_info" || m == "as_ref" || m == "clone" {
                        return self.find_active_variable_ir(target, ssa_state);
                    }
                }
                self.find_active_variable_ir(target, ssa_state)
            }
            epic_ir::IRExpression::Reference { expression, .. } => {
                self.find_active_variable_ir(expression, ssa_state)
            }
            epic_ir::IRExpression::FieldAccess { object, .. } => {
                self.find_active_variable_ir(object, ssa_state)
            }
            epic_ir::IRExpression::Try(inner) => self.find_active_variable_ir(inner, ssa_state),
            _ => None,
        }
    }

    fn get_root_symbol_ir(
        &self,
        expr: &epic_ir::IRExpression,
        state_before: &SSANodeState,
        resolver: &SymbolResolver,
        var_to_parent_var: &HashMap<SSAVariable, SSAVariable>,
        var_to_root_symbol: &HashMap<SSAVariable, SymbolId>,
    ) -> Option<SymbolId> {
        if let Some(ssa_var) = self.find_active_variable_ir(expr, state_before) {
            if let Some(root_sym) =
                self.trace_ssa_to_root(ssa_var, var_to_parent_var, var_to_root_symbol)
            {
                return Some(root_sym);
            }
        }
        resolver.resolve_expr_ir(expr, state_before)
    }

    fn find_context_struct<'a>(&self, context: &'a AnalysisContext) -> Option<&'a StructDef> {
        let inst_name = &context.instruction_context.name;
        // Convert snake_case to TitleCase
        let mut title_case = String::new();
        let mut next_upper = true;
        for c in inst_name.chars() {
            if c == '_' {
                next_upper = true;
            } else if next_upper {
                title_case.push(c.to_ascii_uppercase());
                next_upper = false;
            } else {
                title_case.push(c);
            }
        }

        let mut search_names = vec![title_case.clone()];
        if title_case.starts_with("Handle") && title_case.len() > 6 {
            search_names.push(title_case[6..].to_string());
        }
        if title_case.starts_with("Process") && title_case.len() > 7 {
            search_names.push(title_case[7..].to_string());
        }

        for name in search_names {
            if let Some((_abs_path, s)) = crate::audit::find_struct_by_name(
                &context.ast_graph.registry,
                &context.program_metadata.name,
                &[],
                &name,
            ) {
                return Some(s);
            }
        }

        // Sorted fallback — deterministic key order.
        let mut sorted_defs: Vec<(&String, &TypeDef)> = context
            .ast_graph
            .registry
            .definitions
            .iter()
            .collect();
        sorted_defs.sort_by_key(|(k, _)| k.as_str());

        for (_, def) in sorted_defs {
            if let TypeDef::Struct(s) = def {
                let mut match_count = 0;
                for field in &s.fields {
                    if context
                        .instruction_context
                        .symbol_table
                        .contains_key(&field.name)
                    {
                        match_count += 1;
                    }
                }
                if match_count > 0 && match_count == s.fields.len() {
                    return Some(s);
                }
            }
        }
        None
    }

    fn is_program_symbol(&self, sym_name: &str, struct_def: Option<&StructDef>) -> bool {
        let name_lower = sym_name.to_lowercase();
        if name_lower.contains("program") || name_lower.contains("prog") {
            return true;
        }
        if let Some(s) = struct_def {
            if let Some(field) = s.fields.iter().find(|f| f.name == sym_name) {
                if let TypeRef::Custom(t) | TypeRef::Resolved(t) = &field.type_ref {
                    if t.starts_with("Program")
                        || t.contains("Program<")
                        || t.starts_with("Interface")
                        || t.contains("Interface<")
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn is_struct_field_validated(&self, field: &crate::types::FieldDef) -> bool {
        if let TypeRef::Custom(name) | TypeRef::Resolved(name) = &field.type_ref {
            if name.starts_with("Program")
                || name.contains("Program<")
                || name.starts_with("Interface")
                || name.contains("Interface<")
                || name.starts_with("InterfaceAccount")
                || name.contains("InterfaceAccount<")
            {
                return true;
            }
        }
        for attr in &field.attrs {
            let attr_lower = attr.to_lowercase();
            if attr_lower.contains("address") || attr_lower.contains("constraint") {
                return true;
            }
        }
        false
    }

    fn build_parent_maps_recursive(
        &self,
        stmts: &[StatementNode],
        current_state: &mut SSANodeState,
        var_to_parent_var: &mut HashMap<SSAVariable, SSAVariable>,
        var_to_root_symbol: &mut HashMap<SSAVariable, SymbolId>,
        resolver: &SymbolResolver,
        version_counters: &mut HashMap<String, usize>,
        registry: &TypeRegistry,
        struct_def: Option<&StructDef>,
        instruction_context: &crate::cfg::guards::InstructionAnalysisContext,
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

                    let ir_initializer = crate::ir_converter::convert_expr_node_to_ir(initializer);
                    let resolved_sym = resolver.resolve_expr_ir(&ir_initializer, current_state);
                    let parent_var = self.find_active_variable_ir(&ir_initializer, current_state);

                    current_state
                        .active_variables
                        .insert(name.clone(), ssa_var.clone());

                    if let Some(sym) = resolved_sym {
                        if self.is_root_symbol(sym, resolver, struct_def, instruction_context) {
                            var_to_root_symbol.insert(ssa_var, sym);
                        } else if let Some(p_var) = parent_var {
                            var_to_parent_var.insert(ssa_var, p_var);
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

                                let ir_right = crate::ir_converter::convert_expr_node_to_ir(right);
                                let resolved_sym =
                                    resolver.resolve_expr_ir(&ir_right, current_state);
                                let parent_var =
                                    self.find_active_variable_ir(&ir_right, current_state);

                                current_state
                                    .active_variables
                                    .insert(name.clone(), ssa_var.clone());

                                if let Some(sym) = resolved_sym {
                                    if self.is_root_symbol(
                                        sym,
                                        resolver,
                                        struct_def,
                                        instruction_context,
                                    ) {
                                        var_to_root_symbol.insert(ssa_var, sym);
                                    } else if let Some(p_var) = parent_var {
                                        var_to_parent_var.insert(ssa_var, p_var);
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

                    self.build_parent_maps_recursive(
                        inner_stmts,
                        current_state,
                        var_to_parent_var,
                        var_to_root_symbol,
                        resolver,
                        version_counters,
                        registry,
                        struct_def,
                        instruction_context,
                    );

                    for name in &block_declared {
                        if let Some(old_val) = before_block_versions.get(name) {
                            current_state
                                .active_variables
                                .insert(name.clone(), old_val.clone());
                        } else {
                            current_state.active_variables.remove(name);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn get_cpi_targets_ir<'a>(
        &self,
        instr: &'a epic_ir::IRInstruction,
    ) -> Vec<&'a epic_ir::IRExpression> {
        let mut targets = Vec::new();
        match instr {
            epic_ir::IRInstruction::Expr(expr) => {
                self.extract_cpi_targets_expr_ir(expr, &mut targets);
            }
            epic_ir::IRInstruction::Assignment(assign) => {
                self.extract_cpi_targets_expr_ir(&assign.value, &mut targets);
            }
            _ => {}
        }
        targets
    }

    fn extract_cpi_targets_expr_ir<'a>(
        &self,
        expr: &'a epic_ir::IRExpression,
        targets: &mut Vec<&'a epic_ir::IRExpression>,
    ) {
        match expr {
            epic_ir::IRExpression::Call {
                method,
                target,
                arguments,
            } => {
                if let Some(m) = method {
                    let is_invoke = m.contains("invoke") || m.contains("invoke_signed");
                    let is_new = m == "new"
                        || m.ends_with("::new")
                        || m == "new_with_signer"
                        || m.ends_with("::new_with_signer");

                    if is_invoke {
                        if arguments.len() >= 2 {
                            let slice = &arguments[1];
                            self.collect_slice_targets_ir(slice, targets);
                        }
                    } else if is_new {
                        if !arguments.is_empty() {
                            targets.push(&arguments[0]);
                        }
                    } else {
                        self.extract_cpi_targets_expr_ir(target, targets);
                        for arg in arguments {
                            self.extract_cpi_targets_expr_ir(arg, targets);
                        }
                    }
                } else {
                    self.extract_cpi_targets_expr_ir(target, targets);
                    for arg in arguments {
                        self.extract_cpi_targets_expr_ir(arg, targets);
                    }
                }
            }
            epic_ir::IRExpression::Try(inner) => {
                self.extract_cpi_targets_expr_ir(inner, targets);
            }
            epic_ir::IRExpression::Reference { expression, .. } => {
                self.extract_cpi_targets_expr_ir(expression, targets);
            }
            epic_ir::IRExpression::Assign { left, right } => {
                self.extract_cpi_targets_expr_ir(left, targets);
                self.extract_cpi_targets_expr_ir(right, targets);
            }
            _ => {}
        }
    }

    fn collect_slice_targets_ir<'a>(
        &self,
        expr: &'a epic_ir::IRExpression,
        targets: &mut Vec<&'a epic_ir::IRExpression>,
    ) {
        match expr {
            epic_ir::IRExpression::Reference { expression, .. } => {
                self.collect_slice_targets_ir(expression, targets);
            }
            epic_ir::IRExpression::Call {
                method, arguments, ..
            } => {
                if let Some(m) = method {
                    if m == "array" {
                        for arg in arguments {
                            self.collect_slice_targets_ir(arg, targets);
                        }
                    } else {
                        targets.push(expr);
                    }
                } else {
                    targets.push(expr);
                }
            }
            epic_ir::IRExpression::Variable(_) | epic_ir::IRExpression::FieldAccess { .. } => {
                targets.push(expr);
            }
            _ => {}
        }
    }

    fn get_validated_root_symbols(
        &self,
        stmt: &StatementNode,
        resolver: &SymbolResolver,
        ssa_state: &SSANodeState,
        var_to_parent_var: &HashMap<SSAVariable, SSAVariable>,
        var_to_root_symbol: &HashMap<SSAVariable, SymbolId>,
    ) -> Vec<SymbolId> {
        let mut validated = Vec::new();

        let is_val = match &stmt.kind {
            StatementKind::MacroCall { name, .. } => {
                let n_lower = name.to_lowercase();
                n_lower.contains("require") || n_lower.contains("assert")
            }
            StatementKind::Expr(expr) | StatementKind::Semi(expr) => {
                let expr_str = expr_to_string(expr);
                expr_str.contains("require") || expr_str.contains("assert")
            }
            _ => false,
        };

        if is_val {
            let stmt_str = match &stmt.kind {
                StatementKind::MacroCall { raw_args, .. } => raw_args.clone(),
                StatementKind::Expr(expr) | StatementKind::Semi(expr) => expr_to_string(expr),
                _ => "".to_string(),
            };

            for (var_name, &sym_id) in &resolver.name_to_symbol {
                let pattern1 = var_name;
                let pattern2 = format!("{}.", var_name);
                if stmt_str.contains(pattern1) || stmt_str.contains(&pattern2) {
                    if let Some(ssa_var) = ssa_state.active_variables.get(var_name) {
                        if let Some(root) = self.trace_ssa_to_root(
                            ssa_var.clone(),
                            var_to_parent_var,
                            var_to_root_symbol,
                        ) {
                            validated.push(root);
                        } else {
                            validated.push(sym_id);
                        }
                    } else {
                        validated.push(sym_id);
                    }
                }
            }
        }

        validated
    }

    fn is_edge_condition_validating(
        &self,
        cond: &ExpressionNode,
        target_root: SymbolId,
        resolver: &SymbolResolver,
        ssa_state: &SSANodeState,
        var_to_parent_var: &HashMap<SSAVariable, SSAVariable>,
        var_to_root_symbol: &HashMap<SSAVariable, SymbolId>,
    ) -> bool {
        let cond_str = expr_to_string(cond);
        for (var_name, &sym_id) in &resolver.name_to_symbol {
            let pattern1 = var_name;
            let pattern2 = format!("{}.", var_name);
            if cond_str.contains(pattern1) || cond_str.contains(&pattern2) {
                let root = if let Some(ssa_var) = ssa_state.active_variables.get(var_name) {
                    self.trace_ssa_to_root(ssa_var.clone(), var_to_parent_var, var_to_root_symbol)
                        .unwrap_or(sym_id)
                } else {
                    sym_id
                };
                if root == target_root {
                    return true;
                }
            }
        }
        false
    }

    fn is_validation_dominating(
        &self,
        target_root: SymbolId,
        cpi_node: usize,
        cpi_stmt: usize,
        cfg: &crate::cfg::ControlFlowGraph,
        dom_checker: &DominanceChecker,
        resolver: &SymbolResolver,
        var_to_parent_var: &HashMap<SSAVariable, SSAVariable>,
        var_to_root_symbol: &HashMap<SSAVariable, SymbolId>,
    ) -> bool {
        for (&node_id, node) in &cfg.nodes {
            let node_ssa = match cfg.ssa_states.get(&node_id) {
                Some(s) => s,
                None => continue,
            };
            for (stmt_idx, stmt) in node.statements.iter().enumerate() {
                let state_before = if stmt_idx == 0 {
                    &node_ssa.start_state
                } else {
                    &node_ssa.statement_states[stmt_idx - 1]
                };
                let validated_roots = self.get_validated_root_symbols(
                    stmt,
                    resolver,
                    state_before,
                    var_to_parent_var,
                    var_to_root_symbol,
                );
                if validated_roots.contains(&target_root)
                    && dom_checker.dominates(node_id, Some(stmt_idx), cpi_node, Some(cpi_stmt))
                {
                    return true;
                }
            }
        }

        for &node_id in cfg.nodes.keys() {
            let node_ssa = match cfg.ssa_states.get(&node_id) {
                Some(s) => s,
                None => continue,
            };
            for edge in &cfg.edges {
                if edge.from == node_id {
                    if let Some(cond) = &edge.condition {
                        if self.is_edge_condition_validating(
                            cond,
                            target_root,
                            resolver,
                            &node_ssa.end_state,
                            var_to_parent_var,
                            var_to_root_symbol,
                        ) {
                            let other_edge = cfg
                                .edges
                                .iter()
                                .find(|e| e.from == node_id && e.to != edge.to);

                            let then_terminates = self.is_node_terminating(edge.to, cfg);
                            let else_terminates = if let Some(oe) = other_edge {
                                self.is_node_terminating(oe.to, cfg)
                            } else {
                                false
                            };

                            if (then_terminates || else_terminates)
                                && dom_checker.dominates(node_id, None, cpi_node, Some(cpi_stmt))
                            {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    fn is_node_terminating(&self, node_id: usize, cfg: &crate::cfg::ControlFlowGraph) -> bool {
        if let Some(node) = cfg.nodes.get(&node_id) {
            for stmt in &node.statements {
                match &stmt.kind {
                    StatementKind::Expr(expr) | StatementKind::Semi(expr) => {
                        let expr_str = expr_to_string(expr);
                        if expr_str.contains("return")
                            || expr_str.contains("panic")
                            || expr_str.contains("Err")
                        {
                            return true;
                        }
                    }
                    StatementKind::MacroCall { name, .. } => {
                        if name == "panic" || name == "unreachable" || name == "err" {
                            return true;
                        }
                    }
                    _ => {}
                }
            }
        }
        let outgoing: Vec<&crate::cfg::CFGEdge> =
            cfg.edges.iter().filter(|e| e.from == node_id).collect();
        if outgoing.is_empty() {
            return cfg.exit_nodes.contains(&node_id);
        }
        if outgoing
            .iter()
            .all(|e| e.is_early_return || cfg.exit_nodes.contains(&e.to))
        {
            return true;
        }
        false
    }
}

fn expr_to_string(expr: &ExpressionNode) -> String {
    match &expr.kind {
        ExpressionKind::Identifier(name) => name.clone(),
        ExpressionKind::Literal(val) => val.clone(),
        ExpressionKind::FieldAccess { object, field } => {
            format!("{}.{}", expr_to_string(object), field)
        }
        ExpressionKind::MethodCall { object, method, .. } => {
            format!("{}.{}()", expr_to_string(object), method)
        }
        ExpressionKind::Reference { expression, .. } => expr_to_string(expression),
        ExpressionKind::Dereference(expression) => expr_to_string(expression),
        ExpressionKind::Try(expression) => expr_to_string(expression),
        ExpressionKind::BinaryOp { op, lhs, rhs } => {
            format!("{} {} {}", expr_to_string(lhs), op, expr_to_string(rhs))
        }
        _ => "".to_string(),
    }
}
