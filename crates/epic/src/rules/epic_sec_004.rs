use crate::ast::{
    ExpressionKind, ExpressionNode, InferenceResult, InferenceScope, StatementKind,
    TypeInferenceEngine,
};
use crate::cfg::guards::{FactConfidence, SymbolId};
use crate::cfg::ssa::SSANodeState;
use crate::rules::{
    AnalysisContext, FindingLocation, Rule, RuleDiagnostic, RuleSeverity, SymbolResolver,
};
use crate::types::{StructDef, TypeDef, TypeRef, TypeRegistry};
use std::collections::HashMap;
use std::collections::HashSet;
use syn::visit::Visit;

pub struct PdaSeedCollisionRule;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedLength {
    Fixed,
    Variable,
    Unknown,
}

struct ConstCollector {
    constants: HashMap<String, ExpressionNode>,
}

impl<'ast> Visit<'ast> for ConstCollector {
    fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
        let name = node.ident.to_string();
        let converted = crate::cfg::builder::convert_expr(&node.expr);
        self.constants.insert(name, converted);
        syn::visit::visit_item_const(self, node);
    }
}

impl Rule for PdaSeedCollisionRule {
    fn id(&self) -> &'static str {
        "EPIC-SEC-004"
    }

    fn name(&self) -> &'static str {
        "PDA Cryptographic Seed Collision Risk"
    }

    fn check(&self, context: &AnalysisContext) -> Vec<RuleDiagnostic> {
        let resolver = context.resolver();
        let instruction_context = &context.instruction_context;
        let mut diagnostics = Vec::new();

        // 1. Collect all local and module constants in the file
        let mut constants = HashMap::new();
        if let Ok(content) = std::fs::read_to_string(&instruction_context.file_path) {
            if let Ok(file) = syn::parse_file(&content) {
                let mut collector = ConstCollector {
                    constants: HashMap::new(),
                };
                collector.visit_file(&file);
                constants = collector.constants;
            }
        }

        let struct_def = self.find_context_struct(context);

        // 2. Perform topological sort on CFG to process nodes sequentially
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

        // Check 1: Imperative PDA derivations in CFG statements
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

                let expr_opt = match &stmt.kind {
                    StatementKind::Expr(expr) | StatementKind::Semi(expr) => Some(expr),
                    StatementKind::Let { initializer, .. } => Some(initializer),
                    _ => None,
                };

                if let Some(expr) = expr_opt {
                    self.check_expr_for_pda_seeds(
                        expr,
                        state_before,
                        &context.ast_graph.registry,
                        &resolver,
                        &constants,
                        stmt.line_number,
                        node_id,
                        Some(stmt_idx),
                        &instruction_context.cfg,
                        &mut diagnostics,
                    );
                }
            }
        }

        // Check 2: Anchor Account attributes (macro constraints)
        if let Some(s_def) = struct_def {
            for field in &s_def.fields {
                for attr in &field.attrs {
                    if let Some(seeds_array_str) = self.extract_seeds_array_string(attr) {
                        if let Ok(syn_expr) = syn::parse_str::<syn::Expr>(&seeds_array_str) {
                            if let syn::Expr::Array(expr_array) = syn_expr {
                                let seeds: Vec<ExpressionNode> = expr_array
                                    .elems
                                    .iter()
                                    .map(crate::cfg::builder::convert_expr)
                                    .collect();

                                // For Anchor macro attributes, we evaluate seeds at the start of the entry node
                                if let Some(entry_ssa) = instruction_context
                                    .cfg
                                    .ssa_states
                                    .get(&instruction_context.cfg.entry_node)
                                {
                                    self.check_seeds_slice(
                                        &seeds,
                                        &entry_ssa.start_state,
                                        &context.ast_graph.registry,
                                        &resolver,
                                        &constants,
                                        0, // line is fallback
                                        instruction_context.cfg.entry_node,
                                        None,
                                        &instruction_context.cfg,
                                        &mut diagnostics,
                                    );
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

impl PdaSeedCollisionRule {
    fn extract_seeds_array_string(&self, attr: &str) -> Option<String> {
        if let Some(pos) = attr.find("seeds = ") {
            let after_seeds = &attr[pos + "seeds = ".len()..];
            if after_seeds.starts_with('[') {
                let mut depth = 0;
                let mut end_idx = None;
                for (idx, c) in after_seeds.char_indices() {
                    if c == '[' {
                        depth += 1;
                    } else if c == ']' {
                        depth -= 1;
                        if depth == 0 {
                            end_idx = Some(idx);
                            break;
                        }
                    }
                }
                if let Some(end) = end_idx {
                    return Some(after_seeds[..=end].to_string());
                }
            }
        }
        None
    }

    fn check_expr_for_pda_seeds(
        &self,
        expr: &ExpressionNode,
        ssa_state: &SSANodeState,
        registry: &TypeRegistry,
        resolver: &SymbolResolver,
        constants: &HashMap<String, ExpressionNode>,
        line: usize,
        node_id: usize,
        stmt_idx: Option<usize>,
        cfg: &crate::cfg::ControlFlowGraph,
        diagnostics: &mut Vec<RuleDiagnostic>,
    ) {
        match &expr.kind {
            ExpressionKind::MethodCall {
                method, arguments, ..
            } => {
                let is_pda = method.contains("find_program_address")
                    || method.contains("create_program_address");
                if is_pda && !arguments.is_empty() {
                    if let Some(seeds) = self.extract_array_elements(&arguments[0]) {
                        self.check_seeds_slice(
                            seeds,
                            ssa_state,
                            registry,
                            resolver,
                            constants,
                            line,
                            node_id,
                            stmt_idx,
                            cfg,
                            diagnostics,
                        );
                    }
                } else {
                    for arg in arguments {
                        self.check_expr_for_pda_seeds(
                            arg,
                            ssa_state,
                            registry,
                            resolver,
                            constants,
                            line,
                            node_id,
                            stmt_idx,
                            cfg,
                            diagnostics,
                        );
                    }
                }
            }
            ExpressionKind::Reference { expression, .. } => {
                self.check_expr_for_pda_seeds(
                    expression,
                    ssa_state,
                    registry,
                    resolver,
                    constants,
                    line,
                    node_id,
                    stmt_idx,
                    cfg,
                    diagnostics,
                );
            }
            ExpressionKind::Try(inner) => {
                self.check_expr_for_pda_seeds(
                    inner,
                    ssa_state,
                    registry,
                    resolver,
                    constants,
                    line,
                    node_id,
                    stmt_idx,
                    cfg,
                    diagnostics,
                );
            }
            _ => {}
        }
    }

    fn extract_array_elements<'a>(
        &self,
        expr: &'a ExpressionNode,
    ) -> Option<&'a Vec<ExpressionNode>> {
        match &expr.kind {
            ExpressionKind::Reference { expression, .. } => self.extract_array_elements(expression),
            ExpressionKind::MethodCall {
                method, arguments, ..
            } => {
                if method == "array" {
                    Some(arguments)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn check_seeds_slice(
        &self,
        seeds: &[ExpressionNode],
        ssa_state: &SSANodeState,
        registry: &TypeRegistry,
        resolver: &SymbolResolver,
        constants: &HashMap<String, ExpressionNode>,
        line: usize,
        node_id: usize,
        stmt_idx: Option<usize>,
        cfg: &crate::cfg::ControlFlowGraph,
        diagnostics: &mut Vec<RuleDiagnostic>,
    ) {
        if seeds.len() < 2 {
            return;
        }

        for i in 0..seeds.len() - 1 {
            let len_a = self.classify_seed(
                &seeds[i], ssa_state, registry, resolver, constants, cfg, node_id, stmt_idx,
            );
            let len_b = self.classify_seed(
                &seeds[i + 1],
                ssa_state,
                registry,
                resolver,
                constants,
                cfg,
                node_id,
                stmt_idx,
            );

            if (len_a == SeedLength::Variable || len_a == SeedLength::Unknown)
                && (len_b == SeedLength::Variable || len_b == SeedLength::Unknown)
            {
                let expr_a_str = expr_to_string(&seeds[i]);
                let expr_b_str = expr_to_string(&seeds[i + 1]);

                diagnostics.push(RuleDiagnostic {
                    rule_id: self.id().to_string(),
                    severity: RuleSeverity::High,
                    message: format!(
                        "Potential PDA cryptographic seed collision risk. Adjacent variable-length seeds '{}' and '{}' can merge ambiguously. Insert a fixed-length seed or literal delimiter between them.",
                        expr_a_str,
                        expr_b_str
                    ),
                    location: FindingLocation {
                        file: resolver.context_var_name.clone(), // fallback, will be re-mapped by audit
                        line,
                        column: 0,
                        node_id,
                        statement_index: stmt_idx,
                    },
                    confidence: FactConfidence::Asserted,
                    target_symbol: SymbolId(0), // generic symbol ID
                });
            }
        }
    }

    fn find_initializer(
        &self,
        target_name: &str,
        cfg: &crate::cfg::ControlFlowGraph,
        node_id: usize,
        stmt_idx: Option<usize>,
    ) -> Option<ExpressionNode> {
        let node = cfg.nodes.get(&node_id)?;
        let start = match stmt_idx {
            Some(idx) => idx,
            None => node.statements.len(),
        };

        for i in (0..start).rev() {
            let stmt = &node.statements[i];
            match &stmt.kind {
                StatementKind::Let {
                    name, initializer, ..
                } => {
                    if name == target_name {
                        return Some(initializer.clone());
                    }
                }
                StatementKind::Expr(expr) | StatementKind::Semi(expr) => {
                    if let ExpressionKind::Assign { left, right } = &expr.kind {
                        if let ExpressionKind::Identifier(name) = &left.kind {
                            if name == target_name {
                                return Some((**right).clone());
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn classify_seed(
        &self,
        expr: &ExpressionNode,
        ssa_state: &SSANodeState,
        registry: &TypeRegistry,
        resolver: &SymbolResolver,
        constants: &HashMap<String, ExpressionNode>,
        cfg: &crate::cfg::ControlFlowGraph,
        node_id: usize,
        stmt_idx: Option<usize>,
    ) -> SeedLength {
        match &expr.kind {
            ExpressionKind::Literal(val) => {
                if val.starts_with("b\"") || val.starts_with("b'") || val.starts_with("\"") {
                    SeedLength::Fixed
                } else if val.parse::<u64>().is_ok() || val.parse::<i64>().is_ok() {
                    SeedLength::Fixed
                } else {
                    SeedLength::Unknown
                }
            }
            ExpressionKind::Identifier(name) => {
                if let Some(const_expr) = constants.get(name) {
                    return self.classify_seed(
                        const_expr, ssa_state, registry, resolver, constants, cfg, node_id,
                        stmt_idx,
                    );
                }

                if let Some(init_expr) = self.find_initializer(name, cfg, node_id, stmt_idx) {
                    return self.classify_seed(
                        &init_expr, ssa_state, registry, resolver, constants, cfg, node_id,
                        stmt_idx,
                    );
                }

                if let Some(ssa_var) = ssa_state.active_variables.get(name) {
                    if let Some(ty) = ssa_state.variable_types.get(&ssa_var.to_string()) {
                        return self.type_to_seed_length(ty);
                    }
                }

                if let Some(_sym) = resolver.get_symbol_by_name(name) {
                    let name_lower = name.to_lowercase();
                    if name_lower.contains("key")
                        || name_lower.contains("pubkey")
                        || name_lower.contains("authority")
                    {
                        return SeedLength::Fixed;
                    }
                }

                SeedLength::Unknown
            }
            ExpressionKind::MethodCall { object, method, .. } => {
                if method == "array" {
                    return SeedLength::Fixed;
                }
                if method == "to_le_bytes" || method == "to_be_bytes" {
                    return SeedLength::Fixed;
                }
                if method == "as_bytes"
                    || method == "as_ref"
                    || method == "as_slice"
                    || method == "clone"
                {
                    let obj_len = self.classify_seed(
                        object, ssa_state, registry, resolver, constants, cfg, node_id, stmt_idx,
                    );
                    if obj_len != SeedLength::Unknown {
                        return obj_len;
                    }
                }

                let mut inference_scope = InferenceScope::new();
                for (v_name, active_var) in &ssa_state.active_variables {
                    if let Some(ty) = ssa_state.variable_types.get(&active_var.to_string()) {
                        inference_scope.insert(v_name.clone(), ty.clone());
                    }
                }
                let engine = TypeInferenceEngine::new(registry, &inference_scope);
                if let InferenceResult::Ok(type_ref) = engine.infer(expr) {
                    return self.type_to_seed_length(&type_ref);
                }

                SeedLength::Unknown
            }
            ExpressionKind::Reference { expression, .. } => self.classify_seed(
                expression, ssa_state, registry, resolver, constants, cfg, node_id, stmt_idx,
            ),
            ExpressionKind::Try(inner) => self.classify_seed(
                inner, ssa_state, registry, resolver, constants, cfg, node_id, stmt_idx,
            ),
            ExpressionKind::FieldAccess { object, field } => {
                if field == "key" {
                    return SeedLength::Fixed;
                }

                let mut inference_scope = InferenceScope::new();
                for (v_name, active_var) in &ssa_state.active_variables {
                    if let Some(ty) = ssa_state.variable_types.get(&active_var.to_string()) {
                        inference_scope.insert(v_name.clone(), ty.clone());
                    }
                }
                let engine = TypeInferenceEngine::new(registry, &inference_scope);
                if let InferenceResult::Ok(type_ref) = engine.infer(expr) {
                    return self.type_to_seed_length(&type_ref);
                }

                // Fallback check on object
                let obj_len = self.classify_seed(
                    object, ssa_state, registry, resolver, constants, cfg, node_id, stmt_idx,
                );
                if obj_len == SeedLength::Fixed
                    && (field.contains("key") || field.contains("authority"))
                {
                    return SeedLength::Fixed;
                }

                SeedLength::Unknown
            }
            _ => SeedLength::Unknown,
        }
    }

    fn type_to_seed_length(&self, ty: &TypeRef) -> SeedLength {
        match ty {
            TypeRef::Pubkey => SeedLength::Fixed,
            TypeRef::Primitive(name) => {
                let n = name.as_str();
                if n == "u8"
                    || n == "u16"
                    || n == "u32"
                    || n == "u64"
                    || n == "u128"
                    || n == "i8"
                    || n == "i16"
                    || n == "i32"
                    || n == "i64"
                    || n == "i128"
                {
                    SeedLength::Fixed
                } else {
                    SeedLength::Unknown
                }
            }
            TypeRef::Array(inner, _) => self.type_to_seed_length(inner),
            TypeRef::String => SeedLength::Variable,
            TypeRef::Vec(_) => SeedLength::Variable,
            _ => SeedLength::Unknown,
        }
    }

    fn find_context_struct<'a>(&self, context: &'a AnalysisContext) -> Option<&'a StructDef> {
        let inst_name = &context.instruction_context.name;
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

        // Sorted fallback: iterate definitions in deterministic key order so the
        // field-count match produces the same result across runs.
        let mut sorted_defs: Vec<(&String, &TypeDef)> =
            context.ast_graph.registry.definitions.iter().collect();
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
