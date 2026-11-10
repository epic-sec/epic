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
/// call resolution: its source file, the type of its enclosing inherent
/// `impl` block (empty for a free function), and its own name.
///
/// Was file+name only, until the typed-method-resolution work (stage 1 of
/// interprocedural writes-through-`&mut self`) measured the real cost of
/// that: an Anchor state file routinely defines several structs with their
/// own `impl` blocks that happen to share a method name across them —
/// confirmed on squads-v4's `state.rs`, where `Ms::init`,
/// `MsTransaction::init`, and `MsInstruction::init` all collided under the
/// old file+name key, silently discarding two of the three definitions
/// before `resolve_typed` ever got a chance to tell them apart by type.
/// Bare-name resolution (`resolve`) happened to be unaffected in practice —
/// it refuses "init" anyway, since other files in the crate define their
/// own `init` too — which is exactly why this went unmeasured until a
/// resolution path that's *supposed* to disambiguate by type needed the
/// definitions it disambiguates between to not already be gone.
pub type FunctionId = String;

pub fn function_id(file_path: &str, impl_type: Option<&str>, name: &str) -> FunctionId {
    format!("{}::{}::{}", file_path, impl_type.unwrap_or(""), name)
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
    /// The bare name of the type this method is defined on, for a method
    /// inside an inherent `impl <Type> { .. }` block (`impl<'info>
    /// Deposit<'info> { pub fn process(&mut self, ..) }` -> `"Deposit"`).
    /// `None` for a free function, or a method inside a *trait* impl
    /// (`impl Accounts<'info> for Deposit<'info>` — Anchor's own derived
    /// boilerplate, not something a handler calls directly by name).
    ///
    /// This is what makes `(receiver_type, method_name)` resolution
    /// possible at all: bare-name resolution alone can't tell apart the
    /// ~30 different `process`/`update` methods a typical Anchor program
    /// defines, one per `Accounts` struct or per account state type — see
    /// `CallGraph::resolve_typed`.
    pub impl_type: Option<String>,
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
    /// `(impl_type, method_name) -> candidate FunctionIds`, the second
    /// resolution path `resolve_typed` uses. Built once in
    /// `build_call_graph` alongside `functions`, same ambiguity-refusing
    /// shape as `by_name` in `CallVisitor` — ambiguous within this map
    /// means two inherent `impl` blocks for the *same* type both define a
    /// method of the same name (rare: `#[cfg(..)]`-gated duplicate impls),
    /// not the ~30-way bare-name ambiguity `resolve_typed` exists to get
    /// around.
    by_type_method: HashMap<(String, String), Vec<FunctionId>>,
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

    /// Resolves `receiver_type.method_name(..)` to a single function —
    /// `ctx.accounts.process(..)` where `receiver_type` is the handler's
    /// own `Context<T>` struct name, or `position.update(..)` where
    /// `receiver_type` is the account field's own declared type. Refuses
    /// to guess on ambiguity or an unknown type, same convention as
    /// `CallVisitor::resolve`'s bare-name path.
    pub fn resolve_typed(&self, receiver_type: &str, method_name: &str) -> Option<&FunctionId> {
        match self
            .by_type_method
            .get(&(receiver_type.to_string(), method_name.to_string()))
        {
            Some(candidates) if candidates.len() == 1 => candidates.first(),
            _ => None,
        }
    }
}

/// Collects every free function and method definition in a file.
struct DefinitionVisitor<'a> {
    file_path: &'a str,
    functions: Vec<FunctionInfo>,
    /// Set while visiting the body of an inherent `impl <Type> { .. }`
    /// block; `None` outside any impl, or inside a *trait* impl (`impl
    /// Accounts<'info> for X` — Anchor's derived boilerplate, never
    /// something a handler calls by name, so deliberately not tracked).
    current_impl_type: Option<String>,
}

/// The bare type name an `impl` block is for — `impl<'info> Deposit<'info>`
/// -> `"Deposit"`. Only inherent impls (`item.trait_.is_none()`) carry a
/// name worth indexing; a trait impl's Self type is still real, but its
/// methods are never the target of a direct `receiver.method(..)` call a
/// handler would write by hand.
fn inherent_impl_type_name(item: &syn::ItemImpl) -> Option<String> {
    if item.trait_.is_some() {
        return None;
    }
    if let syn::Type::Path(type_path) = &*item.self_ty {
        type_path.path.segments.last().map(|s| s.ident.to_string())
    } else {
        None
    }
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
            impl_type: self.current_impl_type.clone(),
        });
    }
}

impl<'ast> Visit<'ast> for DefinitionVisitor<'_> {
    fn visit_item_fn(&mut self, i: &'ast syn::ItemFn) {
        self.record(i.sig.ident.to_string(), &i.sig, &i.block.stmts);
        syn::visit::visit_item_fn(self, i);
    }

    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        let outer = self.current_impl_type.take();
        self.current_impl_type = inherent_impl_type_name(i);
        syn::visit::visit_item_impl(self, i);
        self.current_impl_type = outer;
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
            current_impl_type: None,
        };
        visitor.visit_file(&file_ast);
        for f in visitor.functions {
            functions.insert(
                function_id(&f.file_path, f.impl_type.as_deref(), &f.name),
                f,
            );
        }
    }

    // Name -> candidate FunctionIds, for ambiguity-aware resolution.
    let mut by_name: HashMap<String, Vec<FunctionId>> = HashMap::new();
    for (id, f) in &functions {
        by_name.entry(f.name.clone()).or_default().push(id.clone());
    }

    // (impl_type, method_name) -> candidate FunctionIds — the typed
    // resolution path `resolve_typed` uses to get around `by_name`'s
    // ambiguity refusal for the one-`process`/`update`-per-type idiom.
    let mut by_type_method: HashMap<(String, String), Vec<FunctionId>> = HashMap::new();
    for (id, f) in &functions {
        if let Some(ty) = &f.impl_type {
            by_type_method
                .entry((ty.clone(), f.name.clone()))
                .or_default()
                .push(id.clone());
        }
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

    CallGraph {
        functions,
        calls,
        by_type_method,
    }
}
