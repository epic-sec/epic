//! Stage 1 of interprocedural guard analysis: a crate-wide call graph.
//!
//! Unlike `audit::RawFunctionVisitor` (which only keeps functions with a
//! `Context<T>` parameter — i.e. instruction handlers), this collects EVERY
//! function and method in the crate, including helpers like
//! `check_sol_leg(parent: &Initialize, ...)` that instruction handlers call
//! into but that EPIC's per-instruction pipeline has never seen before.
//!
//! Scope (first version, per the design): single crate, no cross-crate
//! resolution; direct calls only (`foo(x)`, `self.method(x)`,
//! `ctx.accounts.validate()`) — no trait dispatch, function pointers, or
//! closures; name-based resolution — if a callee name matches more than one
//! function in the crate, the call is left unresolved rather than guessed.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use syn::visit::Visit;
use walkdir::WalkDir;

/// Identifies a function/method uniquely enough for single-crate, name-based
/// call resolution: its source file plus its own name. Two functions with
/// the same name in the same file (e.g. two inherent `impl` blocks both
/// defining `fn new`) collide under this key — rare enough to accept for a
/// first version, and resolution already refuses to guess across *files*.
pub type FunctionId = String;

fn function_id(file_path: &str, name: &str) -> FunctionId {
    format!("{}::{}", file_path, name)
}

#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub file_path: String,
    /// Parameter names in declaration order. A method's `&self`/`&mut self`
    /// receiver is recorded as `"self"` at position 0, so a call's argument
    /// list (receiver prepended for method calls) lines up with this
    /// positionally.
    pub params: Vec<String>,
    pub stmts: Vec<syn::Stmt>,
}

/// One direct call from `caller` to `callee`, with the call-site argument
/// expressions in order. `args[i]` is the expression passed for
/// `callee.params[i]` — for a method call, `args[0]` is the receiver
/// expression, lining up with the synthesized `"self"` parameter.
#[derive(Debug, Clone)]
pub struct CallSite {
    pub caller: FunctionId,
    pub callee: FunctionId,
    pub args: Vec<syn::Expr>,
    pub line: usize,
}

#[derive(Debug, Default)]
pub struct CallGraph {
    pub functions: HashMap<FunctionId, FunctionInfo>,
    pub calls: Vec<CallSite>,
}

impl CallGraph {
    pub fn get(&self, id: &str) -> Option<&FunctionInfo> {
        self.functions.get(id)
    }

    pub fn calls_from<'a>(&'a self, caller: &'a str) -> impl Iterator<Item = &'a CallSite> {
        self.calls.iter().filter(move |c| c.caller == caller)
    }

    pub fn calls_to<'a>(&'a self, callee: &'a str) -> impl Iterator<Item = &'a CallSite> {
        self.calls.iter().filter(move |c| c.callee == callee)
    }
}

/// Collects every free function and method definition in a file.
struct DefinitionVisitor<'a> {
    file_path: &'a str,
    functions: Vec<FunctionInfo>,
}

impl DefinitionVisitor<'_> {
    fn record(&mut self, name: String, sig: &syn::Signature, stmts: &[syn::Stmt]) {
        let mut params = Vec::new();
        for input in &sig.inputs {
            match input {
                syn::FnArg::Receiver(_) => params.push("self".to_string()),
                syn::FnArg::Typed(pat_type) => {
                    if let syn::Pat::Ident(pat_ident) = &*pat_type.pat {
                        params.push(pat_ident.ident.to_string());
                    } else {
                        params.push("_".to_string());
                    }
                }
            }
        }
        self.functions.push(FunctionInfo {
            name,
            file_path: self.file_path.to_string(),
            params,
            stmts: stmts.to_vec(),
        });
    }
}

impl<'ast> Visit<'ast> for DefinitionVisitor<'_> {
    fn visit_item_fn(&mut self, i: &'ast syn::ItemFn) {
        self.record(i.sig.ident.to_string(), &i.sig, &i.block.stmts);
        syn::visit::visit_item_fn(self, i);
    }

    fn visit_impl_item_fn(&mut self, i: &'ast syn::ImplItemFn) {
        self.record(i.sig.ident.to_string(), &i.sig, &i.block.stmts);
        syn::visit::visit_impl_item_fn(self, i);
    }
}

/// Extracts direct-call sites (`foo(x)` / `self.method(x)`) from a single
/// function's body, resolving callees by bare name against `by_name`.
struct CallVisitor<'a> {
    caller: FunctionId,
    by_name: &'a HashMap<String, Vec<FunctionId>>,
    calls: Vec<CallSite>,
}

impl<'ast> Visit<'ast> for CallVisitor<'_> {
    fn visit_expr_call(&mut self, i: &'ast syn::ExprCall) {
        use syn::spanned::Spanned;
        if let syn::Expr::Path(p) = &*i.func {
            if let Some(last) = p.path.segments.last() {
                let name = last.ident.to_string();
                if let Some(callee) = self.resolve(&name) {
                    self.calls.push(CallSite {
                        caller: self.caller.clone(),
                        callee,
                        args: i.args.iter().cloned().collect(),
                        line: i.span().start().line,
                    });
                }
            }
        }
        syn::visit::visit_expr_call(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &'ast syn::ExprMethodCall) {
        use syn::spanned::Spanned;
        let name = i.method.to_string();
        if let Some(callee) = self.resolve(&name) {
            let mut args = vec![(*i.receiver).clone()];
            args.extend(i.args.iter().cloned());
            self.calls.push(CallSite {
                caller: self.caller.clone(),
                callee,
                args,
                line: i.span().start().line,
            });
        }
        syn::visit::visit_expr_method_call(self, i);
    }
}

impl CallVisitor<'_> {
    /// Resolves a bare callee name to a single function, refusing to guess
    /// when the name is ambiguous (more than one definition in the crate)
    /// or unknown (external crate, trait dispatch, etc).
    fn resolve(&self, name: &str) -> Option<FunctionId> {
        match self.by_name.get(name) {
            Some(candidates) if candidates.len() == 1 => Some(candidates[0].clone()),
            _ => None,
        }
    }
}

/// Builds the call graph for every `.rs` file under `root_path`.
pub fn build_call_graph(root_path: &str) -> CallGraph {
    let root = Path::new(root_path);
    let mut functions: HashMap<FunctionId, FunctionInfo> = HashMap::new();

    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if entry.path().extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        let file_path = entry.path().to_string_lossy().into_owned();
        let Ok(content) = fs::read_to_string(&file_path) else {
            continue;
        };
        let Ok(file_ast) = syn::parse_str::<syn::File>(&content) else {
            continue;
        };

        let mut visitor = DefinitionVisitor {
            file_path: &file_path,
            functions: Vec::new(),
        };
        visitor.visit_file(&file_ast);
        for f in visitor.functions {
            functions.insert(function_id(&f.file_path, &f.name), f);
        }
    }

    // Name -> candidate FunctionIds, for ambiguity-aware resolution.
    let mut by_name: HashMap<String, Vec<FunctionId>> = HashMap::new();
    for (id, f) in &functions {
        by_name.entry(f.name.clone()).or_default().push(id.clone());
    }

    let mut calls = Vec::new();
    for (id, f) in &functions {
        let mut call_visitor = CallVisitor {
            caller: id.clone(),
            by_name: &by_name,
            calls: Vec::new(),
        };
        for stmt in &f.stmts {
            call_visitor.visit_stmt(stmt);
        }
        calls.extend(call_visitor.calls);
    }

    CallGraph { functions, calls }
}
