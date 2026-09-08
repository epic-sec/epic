use crate::ast::{ExpressionKind, ExpressionNode, StatementKind, StatementNode};
use crate::cfg::nodes::{CFGBoundaryWarning, CFGEdge, CFGNode, ControlFlowGraph};

pub struct CFGBuilder {
    pub graph: ControlFlowGraph,
    next_node_id: usize,
}

impl Default for CFGBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CFGBuilder {
    pub fn new() -> Self {
        let mut graph = ControlFlowGraph::default();
        graph.entry_node = 0;
        let entry_node = CFGNode {
            id: 0,
            statements: Vec::new(),
            ir_instructions: Vec::new(),
        };
        graph.nodes.insert(0, entry_node);
        Self {
            graph,
            next_node_id: 1,
        }
    }

    fn new_node_id(&mut self) -> usize {
        let id = self.next_node_id;
        self.next_node_id += 1;
        id
    }

    fn add_node(&mut self, id: usize) {
        self.graph.nodes.entry(id).or_insert_with(|| CFGNode {
            id,
            statements: Vec::new(),
            ir_instructions: Vec::new(),
        });
    }

    fn add_edge(
        &mut self,
        from: usize,
        to: usize,
        condition: Option<ExpressionNode>,
        is_early_return: bool,
    ) {
        let ir_condition = condition
            .as_ref()
            .map(crate::ir_converter::convert_expr_node_to_ir);
        self.graph.edges.push(CFGEdge {
            from,
            to,
            condition,
            ir_condition,
            is_early_return,
        });
    }

    /// Compiles a set of syn statements into the Control Flow Graph.
    /// Returns the terminal node ID of this block execution.
    pub fn compile_statements(
        &mut self,
        stmts: &[syn::Stmt],
        current_node: usize,
    ) -> anyhow::Result<usize> {
        let final_node = self.compile_statements_inner(stmts, current_node)?;
        if !self.graph.exit_nodes.contains(&final_node) {
            self.graph.exit_nodes.push(final_node);
        }
        Ok(final_node)
    }

    fn compile_statements_inner(
        &mut self,
        stmts: &[syn::Stmt],
        mut current_node: usize,
    ) -> anyhow::Result<usize> {
        for stmt in stmts {
            self.scan_boundary_warnings(stmt);

            // P0 Correctness Fix: Detect terminal return/panic expressions and stop block compilation
            if is_terminating_stmt(stmt) {
                let converted = convert_stmt(stmt);
                let ir_instrs = crate::ir_converter::convert_statement_node_to_ir(&converted);
                let node = self.graph.nodes.get_mut(&current_node).unwrap();
                node.statements.push(converted);
                node.ir_instructions.extend(ir_instrs);
                if !self.graph.exit_nodes.contains(&current_node) {
                    self.graph.exit_nodes.push(current_node);
                }
                return Ok(current_node);
            }

            match stmt {
                syn::Stmt::Expr(expr, _semi) => {
                    if let syn::Expr::If(expr_if) = expr {
                        // Handle If statement branch split
                        let then_node = self.new_node_id();
                        let else_node = self.new_node_id();
                        let merge_node = self.new_node_id();

                        self.add_node(then_node);
                        self.add_node(else_node);
                        self.add_node(merge_node);

                        let cond = convert_expr(&expr_if.cond);

                        // Branch edges
                        self.add_edge(current_node, then_node, Some(cond.clone()), false);
                        self.add_edge(current_node, else_node, None, false);

                        // Compile then block
                        let then_end =
                            self.compile_statements_inner(&expr_if.then_branch.stmts, then_node)?;

                        // Compile else block if it exists
                        let else_end = if let Some((_, else_expr)) = &expr_if.else_branch {
                            if let syn::Expr::Block(expr_block) = &**else_expr {
                                self.compile_statements_inner(&expr_block.block.stmts, else_node)?
                            } else if let syn::Expr::If(inner_if) = &**else_expr {
                                // Support nested else-if structures
                                let synthetic_stmt =
                                    syn::Stmt::Expr(syn::Expr::If(inner_if.clone()), None);
                                self.compile_statements_inner(&[synthetic_stmt], else_node)?
                            } else {
                                else_node
                            }
                        } else {
                            else_node
                        };

                        // P0 Correctness Fix: Do not connect return / terminal exit nodes to the merge node
                        if !self.graph.exit_nodes.contains(&then_end) {
                            self.add_edge(then_end, merge_node, None, false);
                        }
                        if !self.graph.exit_nodes.contains(&else_end) {
                            self.add_edge(else_end, merge_node, None, false);
                        }

                        current_node = merge_node;
                    } else if let syn::Expr::ForLoop(expr_for) = expr {
                        current_node =
                            self.compile_statements_inner(&expr_for.body.stmts, current_node)?;
                    } else if let syn::Expr::While(expr_while) = expr {
                        current_node =
                            self.compile_statements_inner(&expr_while.body.stmts, current_node)?;
                    } else if let syn::Expr::Loop(expr_loop) = expr {
                        current_node =
                            self.compile_statements_inner(&expr_loop.body.stmts, current_node)?;
                    } else if let syn::Expr::Block(expr_block) = expr {
                        if has_branching_control_flow(&expr_block.block.stmts) {
                            current_node = self
                                .compile_statements_inner(&expr_block.block.stmts, current_node)?;
                        } else {
                            let converted = convert_stmt(stmt);
                            let ir_instrs =
                                crate::ir_converter::convert_statement_node_to_ir(&converted);
                            let node = self.graph.nodes.get_mut(&current_node).unwrap();
                            node.statements.push(converted);
                            node.ir_instructions.extend(ir_instrs);
                        }
                    } else {
                        // P1 Correctness Fix: Model sequential try checkpoints for multiple Try operators
                        let mut tries = Vec::new();
                        find_tries(expr, &mut tries);

                        if !tries.is_empty() {
                            for _ in tries {
                                let early_return_node = self.new_node_id();
                                let sequential_node = self.new_node_id();

                                self.add_node(early_return_node);
                                self.add_node(sequential_node);

                                self.add_edge(current_node, early_return_node, None, true);
                                self.add_edge(current_node, sequential_node, None, false);

                                self.graph.exit_nodes.push(early_return_node);
                                current_node = sequential_node;
                            }
                        }

                        let converted = convert_stmt(stmt);
                        let ir_instrs =
                            crate::ir_converter::convert_statement_node_to_ir(&converted);
                        let node = self.graph.nodes.get_mut(&current_node).unwrap();
                        node.statements.push(converted);
                        node.ir_instructions.extend(ir_instrs);
                    }
                }
                syn::Stmt::Local(local) => {
                    let mut tries = Vec::new();
                    if let Some(init) = &local.init {
                        find_tries(&init.expr, &mut tries);
                    }

                    if !tries.is_empty() {
                        for _ in tries {
                            let early_return_node = self.new_node_id();
                            let sequential_node = self.new_node_id();

                            self.add_node(early_return_node);
                            self.add_node(sequential_node);

                            self.add_edge(current_node, early_return_node, None, true);
                            self.add_edge(current_node, sequential_node, None, false);

                            self.graph.exit_nodes.push(early_return_node);
                            current_node = sequential_node;
                        }
                    }

                    let converted = convert_stmt(stmt);
                    let ir_instrs = crate::ir_converter::convert_statement_node_to_ir(&converted);
                    let node = self.graph.nodes.get_mut(&current_node).unwrap();
                    node.statements.push(converted);
                    node.ir_instructions.extend(ir_instrs);
                }
                _ => {
                    let converted = convert_stmt(stmt);
                    let ir_instrs = crate::ir_converter::convert_statement_node_to_ir(&converted);
                    let node = self.graph.nodes.get_mut(&current_node).unwrap();
                    node.statements.push(converted);
                    node.ir_instructions.extend(ir_instrs);
                }
            }
        }

        Ok(current_node)
    }

    fn scan_boundary_warnings(&mut self, stmt: &syn::Stmt) {
        match stmt {
            syn::Stmt::Expr(expr, _) => {
                self.scan_expr_warnings(expr);
            }
            syn::Stmt::Local(local) => {
                if let Some(init) = &local.init {
                    self.scan_expr_warnings(&init.expr);
                }
            }
            _ => {}
        }
    }

    fn scan_expr_warnings(&mut self, expr: &syn::Expr) {
        match expr {
            syn::Expr::Loop(_) | syn::Expr::While(_) | syn::Expr::ForLoop(_) => {
                if !self
                    .graph
                    .boundary_warnings
                    .contains(&CFGBoundaryWarning::LoopDetected)
                {
                    self.graph
                        .boundary_warnings
                        .push(CFGBoundaryWarning::LoopDetected);
                }
            }
            syn::Expr::Match(_) => {
                if !self
                    .graph
                    .boundary_warnings
                    .contains(&CFGBoundaryWarning::MatchExpression)
                {
                    self.graph
                        .boundary_warnings
                        .push(CFGBoundaryWarning::MatchExpression);
                }
            }
            syn::Expr::MethodCall(mc) => {
                if mc.method == "check_recursive" {
                    self.graph
                        .boundary_warnings
                        .push(CFGBoundaryWarning::RecursiveFunction);
                }
            }
            _ => {}
        }
    }
}

// === Conversions Helpers ===

pub fn is_terminating_stmt(stmt: &syn::Stmt) -> bool {
    match stmt {
        syn::Stmt::Expr(expr, _) => is_terminating_expr(expr),
        syn::Stmt::Macro(stmt_macro) => {
            let name = stmt_macro
                .mac
                .path
                .segments
                .last()
                .unwrap()
                .ident
                .to_string();
            name == "panic"
                || name == "assert"
                || name == "assert_eq"
                || name == "assert_ne"
                || name == "unreachable"
        }
        _ => false,
    }
}

pub fn is_terminating_expr(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Return(_) => true,
        syn::Expr::Macro(expr_macro) => {
            let name = expr_macro
                .mac
                .path
                .segments
                .last()
                .unwrap()
                .ident
                .to_string();
            name == "panic"
                || name == "assert"
                || name == "assert_eq"
                || name == "assert_ne"
                || name == "unreachable"
        }
        _ => false,
    }
}

pub fn find_tries(expr: &syn::Expr, list: &mut Vec<syn::ExprTry>) {
    match expr {
        syn::Expr::Try(expr_try) => {
            find_tries(&expr_try.expr, list);
            list.push(expr_try.clone());
        }
        syn::Expr::Field(field) => {
            find_tries(&field.base, list);
        }
        syn::Expr::MethodCall(method) => {
            find_tries(&method.receiver, list);
            for arg in &method.args {
                find_tries(arg, list);
            }
        }
        syn::Expr::Binary(bin) => {
            find_tries(&bin.left, list);
            find_tries(&bin.right, list);
        }
        syn::Expr::Reference(r) => {
            find_tries(&r.expr, list);
        }
        syn::Expr::Cast(c) => {
            find_tries(&c.expr, list);
        }
        syn::Expr::Index(i) => {
            find_tries(&i.expr, list);
            find_tries(&i.index, list);
        }
        syn::Expr::Call(call) => {
            find_tries(&call.func, list);
            for arg in &call.args {
                find_tries(arg, list);
            }
        }
        _ => {}
    }
}

pub fn has_try_operator(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Try(_) => true,
        syn::Expr::Field(field) => has_try_operator(&field.base),
        syn::Expr::MethodCall(method) => {
            has_try_operator(&method.receiver) || method.args.iter().any(has_try_operator)
        }
        syn::Expr::Binary(bin) => has_try_operator(&bin.left) || has_try_operator(&bin.right),
        syn::Expr::Reference(r) => has_try_operator(&r.expr),
        syn::Expr::Cast(c) => has_try_operator(&c.expr),
        syn::Expr::Index(i) => has_try_operator(&i.expr) || has_try_operator(&i.index),
        _ => false,
    }
}

pub fn convert_expr(expr: &syn::Expr) -> ExpressionNode {
    match expr {
        syn::Expr::Path(expr_path) => {
            let name = quote::quote!(#expr_path).to_string().replace(" ", "");
            ExpressionNode {
                kind: ExpressionKind::Identifier(name),
            }
        }
        syn::Expr::Lit(expr_lit) => {
            let lit = quote::quote!(#expr_lit).to_string().replace(" ", "");
            ExpressionNode {
                kind: ExpressionKind::Literal(lit),
            }
        }
        syn::Expr::Field(expr_field) => {
            let object = convert_expr(&expr_field.base);
            let field = match &expr_field.member {
                syn::Member::Named(ident) => ident.to_string(),
                syn::Member::Unnamed(index) => index.index.to_string(),
            };
            ExpressionNode {
                kind: ExpressionKind::FieldAccess {
                    object: Box::new(object),
                    field,
                },
            }
        }
        syn::Expr::MethodCall(expr_method) => {
            let object = convert_expr(&expr_method.receiver);
            let method = expr_method.method.to_string();
            let arguments = expr_method.args.iter().map(convert_expr).collect();
            ExpressionNode {
                kind: ExpressionKind::MethodCall {
                    object: Box::new(object),
                    method,
                    arguments,
                },
            }
        }
        syn::Expr::Binary(expr_binary) => {
            // Compound assignment operators (-=, +=, *=, /=, etc.)
            // In syn 2.x these are Expr::Binary with BinOp::SubAssign /
            // BinOp::AddAssign / etc. Lower them to ExpressionKind::Assign so
            // the write target is visible to EPIC-SEC-002's dominance check.
            // The arithmetic semantics of the operator are irrelevant here.
            if matches!(
                expr_binary.op,
                syn::BinOp::AddAssign(_)
                    | syn::BinOp::SubAssign(_)
                    | syn::BinOp::MulAssign(_)
                    | syn::BinOp::DivAssign(_)
                    | syn::BinOp::RemAssign(_)
                    | syn::BinOp::BitAndAssign(_)
                    | syn::BinOp::BitOrAssign(_)
                    | syn::BinOp::BitXorAssign(_)
                    | syn::BinOp::ShlAssign(_)
                    | syn::BinOp::ShrAssign(_)
            ) {
                let left = convert_expr(&expr_binary.left);
                let right = convert_expr(&expr_binary.right);
                ExpressionNode {
                    kind: ExpressionKind::Assign {
                        left: Box::new(left),
                        right: Box::new(right),
                    },
                }
            } else {
                let op = match &expr_binary.op {
                    syn::BinOp::Eq(_) => "==".to_string(),
                    syn::BinOp::Ne(_) => "!=".to_string(),
                    syn::BinOp::Lt(_) => "<".to_string(),
                    syn::BinOp::Gt(_) => ">".to_string(),
                    _ => {
                        let bin_op = &expr_binary.op;
                        quote::quote!(#bin_op).to_string().replace(" ", "")
                    }
                };
                let lhs = convert_expr(&expr_binary.left);
                let rhs = convert_expr(&expr_binary.right);
                ExpressionNode {
                    kind: ExpressionKind::BinaryOp {
                        op,
                        lhs: Box::new(lhs),
                        rhs: Box::new(rhs),
                    },
                }
            }
        }
        syn::Expr::Reference(expr_ref) => {
            let expression = convert_expr(&expr_ref.expr);
            let is_mutable = expr_ref.mutability.is_some();
            ExpressionNode {
                kind: ExpressionKind::Reference {
                    expression: Box::new(expression),
                    is_mutable,
                },
            }
        }
        syn::Expr::Try(expr_try) => {
            let expression = convert_expr(&expr_try.expr);
            ExpressionNode {
                kind: ExpressionKind::Try(Box::new(expression)),
            }
        }
        syn::Expr::Assign(expr_assign) => {
            let left = convert_expr(&expr_assign.left);
            let right = convert_expr(&expr_assign.right);
            ExpressionNode {
                kind: ExpressionKind::Assign {
                    left: Box::new(left),
                    right: Box::new(right),
                },
            }
        }
        syn::Expr::Unary(expr_unary) => {
            let op = match &expr_unary.op {
                syn::UnOp::Not(_) => "!".to_string(),
                syn::UnOp::Neg(_) => "-".to_string(),
                syn::UnOp::Deref(_) => "*".to_string(),
                _ => "unknown".to_string(),
            };
            if op == "!" {
                let expression = convert_expr(&expr_unary.expr);
                ExpressionNode {
                    kind: ExpressionKind::BinaryOp {
                        op: "!".to_string(),
                        lhs: Box::new(expression),
                        rhs: Box::new(ExpressionNode {
                            kind: ExpressionKind::Unresolved,
                        }),
                    },
                }
            } else if op == "*" {
                ExpressionNode {
                    kind: ExpressionKind::Dereference(Box::new(convert_expr(&expr_unary.expr))),
                }
            } else {
                ExpressionNode {
                    kind: ExpressionKind::Unresolved,
                }
            }
        }
        syn::Expr::Call(expr_call) => {
            let func = &expr_call.func;
            let func_str = quote::quote!(#func).to_string().replace(" ", "");
            let arguments = expr_call.args.iter().map(convert_expr).collect();
            ExpressionNode {
                kind: ExpressionKind::MethodCall {
                    object: Box::new(ExpressionNode {
                        kind: ExpressionKind::Unresolved,
                    }),
                    method: func_str,
                    arguments,
                },
            }
        }
        syn::Expr::Array(expr_array) => {
            let arguments = expr_array.elems.iter().map(convert_expr).collect();
            ExpressionNode {
                kind: ExpressionKind::MethodCall {
                    object: Box::new(ExpressionNode {
                        kind: ExpressionKind::Unresolved,
                    }),
                    method: "array".to_string(),
                    arguments,
                },
            }
        }
        syn::Expr::Index(expr_index) => {
            // Slicing/indexing (e.g. `seeds[..]`) is transparent to identifier
            // tracking here — pass through the base expression rather than
            // erasing it to `Unresolved`, so callers that walk the tree for
            // account references (e.g. EPIC-SEC-PDA's usage-based detection)
            // can still see through `&seeds[..]`-style signer-seed slicing.
            convert_expr(&expr_index.expr)
        }
        _ => ExpressionNode {
            kind: ExpressionKind::Unresolved,
        },
    }
}

pub fn convert_stmt(stmt: &syn::Stmt) -> StatementNode {
    use syn::spanned::Spanned;
    let line_number = stmt.span().start().line;
    let kind = match stmt {
        syn::Stmt::Local(local) => {
            let name = if let syn::Pat::Ident(pat_ident) = &local.pat {
                pat_ident.ident.to_string()
            } else {
                "destructured".to_string()
            };
            let is_mutable = if let syn::Pat::Ident(pat_ident) = &local.pat {
                pat_ident.mutability.is_some()
            } else {
                false
            };
            let initializer = if let Some(init) = &local.init {
                convert_expr(&init.expr)
            } else {
                ExpressionNode {
                    kind: ExpressionKind::Unresolved,
                }
            };
            StatementKind::Let {
                name,
                initializer,
                type_annotation: None,
                is_mutable,
            }
        }
        syn::Stmt::Expr(expr, semi) => {
            if let syn::Expr::Block(expr_block) = expr {
                let inner_stmts = expr_block.block.stmts.iter().map(convert_stmt).collect();
                StatementKind::Block(inner_stmts)
            } else if semi.is_some() {
                StatementKind::Semi(convert_expr(expr))
            } else {
                StatementKind::Expr(convert_expr(expr))
            }
        }
        syn::Stmt::Macro(stmt_macro) => {
            let name = stmt_macro
                .mac
                .path
                .segments
                .last()
                .unwrap()
                .ident
                .to_string();
            let tokens = &stmt_macro.mac.tokens;
            let raw_args = quote::quote!(#tokens).to_string();
            StatementKind::MacroCall { name, raw_args }
        }
        _ => StatementKind::Expr(ExpressionNode {
            kind: ExpressionKind::Unresolved,
        }),
    };
    StatementNode { kind, line_number }
}

fn has_branching_control_flow_stmt(stmt: &syn::Stmt) -> bool {
    match stmt {
        syn::Stmt::Expr(expr, _) => has_branching_control_flow_expr(expr),
        syn::Stmt::Local(local) => {
            if let Some(init) = &local.init {
                has_branching_control_flow_expr(&init.expr)
            } else {
                false
            }
        }
        syn::Stmt::Macro(stmt_macro) => {
            let name = stmt_macro
                .mac
                .path
                .segments
                .last()
                .unwrap()
                .ident
                .to_string();
            name == "panic"
                || name == "assert"
                || name == "assert_eq"
                || name == "assert_ne"
                || name == "unreachable"
                || name == "require"
                || name == "require_eq"
                || name == "require_keys_eq"
        }
        _ => false,
    }
}

fn has_branching_control_flow_expr(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::If(_) | syn::Expr::Return(_) => true,
        syn::Expr::Try(_) => true,
        syn::Expr::Block(expr_block) => has_branching_control_flow(&expr_block.block.stmts),
        syn::Expr::Macro(expr_macro) => {
            let name = expr_macro
                .mac
                .path
                .segments
                .last()
                .unwrap()
                .ident
                .to_string();
            name == "panic"
                || name == "assert"
                || name == "assert_eq"
                || name == "assert_ne"
                || name == "unreachable"
                || name == "require"
                || name == "require_eq"
                || name == "require_keys_eq"
        }
        syn::Expr::Field(field) => has_branching_control_flow_expr(&field.base),
        syn::Expr::MethodCall(method) => {
            has_branching_control_flow_expr(&method.receiver)
                || method.args.iter().any(has_branching_control_flow_expr)
        }
        syn::Expr::Binary(bin) => {
            has_branching_control_flow_expr(&bin.left)
                || has_branching_control_flow_expr(&bin.right)
        }
        syn::Expr::Reference(r) => has_branching_control_flow_expr(&r.expr),
        syn::Expr::Cast(c) => has_branching_control_flow_expr(&c.expr),
        syn::Expr::Index(i) => {
            has_branching_control_flow_expr(&i.expr) || has_branching_control_flow_expr(&i.index)
        }
        syn::Expr::Assign(assign) => {
            has_branching_control_flow_expr(&assign.left)
                || has_branching_control_flow_expr(&assign.right)
        }
        _ => false,
    }
}

fn has_branching_control_flow(stmts: &[syn::Stmt]) -> bool {
    stmts.iter().any(has_branching_control_flow_stmt)
}
