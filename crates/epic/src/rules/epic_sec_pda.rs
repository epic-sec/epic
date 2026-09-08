use crate::ast::{ExpressionKind, ExpressionNode, StatementKind, StatementNode};
use crate::cfg::guards::{FactConfidence, FactExpression, GuardFact, GuardTarget, InstructionAnalysisContext, SymbolId};
use crate::rules::{AnalysisContext, FindingLocation, Rule, RuleDiagnostic, RuleSeverity};
use std::collections::{HashMap, HashSet};
use syn::visit::Visit;

/// EPIC-SEC-PDA — Consolidated PDA Derivation and Bump Canonicality Rule.
///
/// Sub-check 1 (Missing PDA Derivation Gate):
///   For each account in the Anchor `#[derive(Accounts)]` struct, if the
///   account is referenced by *usage* as a PDA — it appears as an argument to
///   `Pubkey::find_program_address`/`create_program_address`, or inside the
///   signer-seeds array passed to `CpiContext::new_with_signer`/
///   `invoke_signed` — but no `GuardFact::PDA` was extracted for it (i.e. the
///   `#[account(...)]` attribute has no `seeds = [...] , bump`), fire a
///   CRITICAL finding. Detection is usage-based, not name-based: a field
///   named `bank`, `vault`, or `config` is caught the same way a field named
///   `*_pda*` would be, so long as the instruction body actually derives or
///   signs for it as a PDA.
///
/// Sub-check 2 (Non-Canonical Bump):
///   For each `GuardFact::PDA { bump, .. }`, classify the bump:
///   - `bump: None`                  → bare `bump` keyword, canonical, SAFE.
///   - `bump: Some(expr)` where expr resolves to a stored-bump field (e.g.
///     `some_account.bump`) → stored-bump, SAFE.
///   - `bump: Some(expr)` otherwise  → caller-supplied (instruction data), UNSAFE.
pub struct PdaDerivationRule;

// ─────────────────────────────────────────────────────────────────────────────
// Bump classification helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Known instruction-data/argument container name prefixes.
/// Bumps coming from these are caller-supplied — always unsafe.
const INSTRUCTION_DATA_PREFIXES: &[&str] = &[
    "ix", "args", "params", "data", "instruction", "input", "inputs", "request",
];

/// Returns `true` when the base object of a `.bump` field access looks like an
/// instruction-data container (and thus the bump is caller-supplied).
fn object_is_instruction_data(object_name: &str) -> bool {
    let n = object_name.trim().to_lowercase();
    INSTRUCTION_DATA_PREFIXES
        .iter()
        .any(|prefix| n == *prefix || n.starts_with(&format!("{}_", prefix)) || n.ends_with(&format!("_{}", prefix)))
}

/// Returns `true` when `expr` looks like a stored-on-chain bump reference.
///
/// Canonical rule:
/// - `bump` alone (the identifier) → stored-canonical, safe.
/// - `<account_field>.bump` where `<account_field>` is a known Anchor account → stored, safe.
/// - `<instruction_data_container>.bump` → caller-supplied, unsafe.
/// - Anything else → treat conservatively as caller-supplied.
fn is_stored_bump_expr(expr: &FactExpression, symbol_table: &HashMap<String, SymbolId>) -> bool {
    match expr {
        // SolanaProperty enum has no Bump variant; treat as unsafe.
        FactExpression::PropertyOf { .. } => false,

        FactExpression::Literal(val) => {
            let v = val.trim();
            // Bare "bump" identifier → canonical, safe.
            if v == "bump" {
                return true;
            }
            // "object.bump" pattern.
            if let Some(object) = v.strip_suffix(".bump") {
                // object must be a known account field (in symbol_table) AND not an
                // instruction-data container to be considered stored.
                let is_account = symbol_table.contains_key(object);
                let is_ix_data = object_is_instruction_data(object);
                return is_account && !is_ix_data;
            }
            false
        }

        FactExpression::Target(target) => match target {
            GuardTarget::Literal(name) => {
                let n = name.trim();
                if n == "bump" {
                    return true;
                }
                if let Some(object) = n.strip_suffix(".bump") {
                    let is_account = symbol_table.contains_key(object);
                    let is_ix_data = object_is_instruction_data(object);
                    return is_account && !is_ix_data;
                }
                false
            }
            // Variable / Account targets correspond to account-level symbols;
            // conservatively safe (they reference on-chain data).
            _ => true,
        },

        // Binary-op bump expressions are unusual; treat as unsafe.
        FactExpression::BinaryOp { .. } => false,

        FactExpression::Unknown => false,
    }
}

fn is_caller_supplied_bump(expr: &FactExpression, symbol_table: &HashMap<String, SymbolId>) -> bool {
    !is_stored_bump_expr(expr, symbol_table)
}

// ─────────────────────────────────────────────────────────────────────────────
// Reverse-lookup: SymbolId → field name
// ─────────────────────────────────────────────────────────────────────────────

fn symbol_name(target: &GuardTarget, symbol_table: &HashMap<String, SymbolId>) -> Option<String> {
    let sym_id = target.symbol_id()?;
    symbol_table
        .iter()
        .find(|(_, &v)| v == sym_id)
        .map(|(k, _)| k.clone())
}

// ─────────────────────────────────────────────────────────────────────────────
// PDA usage detection — by call-site role, not by field name
//
// Two independent signals feed the "used as PDA" set for an instruction:
//
//   1. Signer-seeds usage (CFG-based, over the already-built IR): an account
//      referenced inside the seeds argument of `invoke_signed`/
//      `CpiContext::new_with_signer` is treated as PDA-like. This is a
//      reasonably reliable signal because that argument exists *specifically*
//      to prove an account can sign for itself.
//
//   2. Manual-derivation usage (best-effort re-parse of the source file): an
//      account is treated as PDA-like only when it is the one *compared*
//      against the pubkey returned by `find_program_address`/
//      `create_program_address` — not merely any account whose key happens to
//      feed the seeds. Seed *ingredients* (e.g. `mint`, `authority`, `group`)
//      are extremely common and are not themselves PDAs, so naively collecting
//      every identifier referenced in a `find_program_address` seeds array
//      produces false positives on real code (confirmed against marginfi and
//      squads-v4 during validation — `mint`/`group`/`creator`/`member` are
//      seed ingredients for a *different* account's PDA, not PDAs themselves).
// ─────────────────────────────────────────────────────────────────────────────

fn is_signer_seeds_call(method: &str) -> bool {
    method.contains("invoke_signed") || method == "new_with_signer" || method.ends_with("::new_with_signer")
}

/// Bound on how many levels of local `let` indirection to follow when
/// resolving an identifier back to its initializer (e.g. `let signer_seeds =
/// &[&seeds[..]];` referencing an earlier `let seeds = &[...];`). Cycle-safe
/// via the `resolving` guard set regardless of this bound.
const MAX_RESOLUTION_DEPTH: usize = 6;

/// Walks an expression tree, collecting the names of accounts it references —
/// resolving simple local-variable indirection along the way. Only two shapes
/// count as an account reference: a bare identifier (covers destructured
/// `let vault = &ctx.accounts.vault;` locals) or a `<ctx>.accounts.<field>`
/// path. Plain field accesses on anything else (e.g. `bank.group`, a field on
/// *loaded account data*, not the Accounts struct) are deliberately excluded
/// — otherwise an on-chain data field happening to share a name with an
/// unrelated Accounts-struct field produces a false match.
fn collect_referenced_account_names(
    expr: &ExpressionNode,
    ctx_var: &str,
    let_bindings: &HashMap<String, ExpressionNode>,
    depth: usize,
    resolving: &mut HashSet<String>,
    out: &mut HashSet<String>,
) {
    match &expr.kind {
        ExpressionKind::Identifier(name) => {
            out.insert(name.clone());
            if depth < MAX_RESOLUTION_DEPTH {
                if let Some(bound) = let_bindings.get(name) {
                    if resolving.insert(name.clone()) {
                        collect_referenced_account_names(bound, ctx_var, let_bindings, depth + 1, resolving, out);
                        resolving.remove(name);
                    }
                }
            }
        }
        ExpressionKind::Literal(_) | ExpressionKind::Unresolved => {}
        ExpressionKind::FieldAccess { object, field } => {
            if let ExpressionKind::FieldAccess {
                object: inner_obj,
                field: inner_field,
            } = &object.kind
            {
                if inner_field == "accounts" {
                    if let ExpressionKind::Identifier(name) = &inner_obj.kind {
                        if name == ctx_var {
                            out.insert(field.clone());
                        }
                    }
                }
            }
            collect_referenced_account_names(object, ctx_var, let_bindings, depth, resolving, out);
        }
        ExpressionKind::MethodCall {
            object, arguments, ..
        } => {
            collect_referenced_account_names(object, ctx_var, let_bindings, depth, resolving, out);
            for arg in arguments {
                collect_referenced_account_names(arg, ctx_var, let_bindings, depth, resolving, out);
            }
        }
        ExpressionKind::BinaryOp { lhs, rhs, .. } => {
            collect_referenced_account_names(lhs, ctx_var, let_bindings, depth, resolving, out);
            collect_referenced_account_names(rhs, ctx_var, let_bindings, depth, resolving, out);
        }
        ExpressionKind::Reference { expression, .. }
        | ExpressionKind::Dereference(expression)
        | ExpressionKind::Try(expression) => {
            collect_referenced_account_names(expression, ctx_var, let_bindings, depth, resolving, out);
        }
        ExpressionKind::Assign { left, right } => {
            collect_referenced_account_names(left, ctx_var, let_bindings, depth, resolving, out);
            collect_referenced_account_names(right, ctx_var, let_bindings, depth, resolving, out);
        }
    }
}

/// Recursively finds every signer-seeds call within `expr` and folds the
/// account names referenced in its seeds argument (the last argument) into
/// `used`. Recurses into nested calls regardless of match, so a
/// `CpiContext::new_with_signer(..)` buried inside `token::transfer(..)` is
/// still found.
fn scan_expr_for_signer_seeds_calls(
    expr: &ExpressionNode,
    ctx_var: &str,
    let_bindings: &HashMap<String, ExpressionNode>,
    used: &mut HashSet<String>,
) {
    match &expr.kind {
        ExpressionKind::MethodCall {
            object,
            method,
            arguments,
        } => {
            if is_signer_seeds_call(method) {
                if let Some(target_arg) = arguments.last() {
                    let mut resolving = HashSet::new();
                    collect_referenced_account_names(target_arg, ctx_var, let_bindings, 0, &mut resolving, used);
                }
            }
            scan_expr_for_signer_seeds_calls(object, ctx_var, let_bindings, used);
            for arg in arguments {
                scan_expr_for_signer_seeds_calls(arg, ctx_var, let_bindings, used);
            }
        }
        ExpressionKind::FieldAccess { object, .. } => {
            scan_expr_for_signer_seeds_calls(object, ctx_var, let_bindings, used)
        }
        ExpressionKind::BinaryOp { lhs, rhs, .. } => {
            scan_expr_for_signer_seeds_calls(lhs, ctx_var, let_bindings, used);
            scan_expr_for_signer_seeds_calls(rhs, ctx_var, let_bindings, used);
        }
        ExpressionKind::Reference { expression, .. }
        | ExpressionKind::Dereference(expression)
        | ExpressionKind::Try(expression) => {
            scan_expr_for_signer_seeds_calls(expression, ctx_var, let_bindings, used)
        }
        ExpressionKind::Assign { left, right } => {
            scan_expr_for_signer_seeds_calls(left, ctx_var, let_bindings, used);
            scan_expr_for_signer_seeds_calls(right, ctx_var, let_bindings, used);
        }
        ExpressionKind::Identifier(_) | ExpressionKind::Literal(_) | ExpressionKind::Unresolved => {}
    }
}

fn collect_let_bindings_from_stmts(
    stmts: &[StatementNode],
    bindings: &mut HashMap<String, ExpressionNode>,
) {
    for stmt in stmts {
        match &stmt.kind {
            StatementKind::Let {
                name, initializer, ..
            } => {
                // First definition wins — deterministic given the caller
                // iterates nodes/statements in a fixed order, and avoids
                // flip-flopping between branch-local redefinitions of the
                // same name across repeated audit runs.
                bindings.entry(name.clone()).or_insert_with(|| initializer.clone());
            }
            StatementKind::Block(inner) => collect_let_bindings_from_stmts(inner, bindings),
            StatementKind::Expr(_) | StatementKind::Semi(_) | StatementKind::MacroCall { .. } => {}
        }
    }
}

fn collect_signer_seeds_usage_from_stmts(
    stmts: &[StatementNode],
    ctx_var: &str,
    let_bindings: &HashMap<String, ExpressionNode>,
    used: &mut HashSet<String>,
) {
    for stmt in stmts {
        match &stmt.kind {
            StatementKind::Let { initializer, .. } => {
                scan_expr_for_signer_seeds_calls(initializer, ctx_var, let_bindings, used);
            }
            StatementKind::Expr(expr) | StatementKind::Semi(expr) => {
                scan_expr_for_signer_seeds_calls(expr, ctx_var, let_bindings, used);
            }
            StatementKind::Block(inner) => {
                collect_signer_seeds_usage_from_stmts(inner, ctx_var, let_bindings, used);
            }
            StatementKind::MacroCall { .. } => {}
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Manual-derivation usage detection — best-effort re-parse of the raw source
//
// The pre-built IR loses two things a `find_program_address` verification
// idiom depends on: tuple-destructured `let` bindings (`let (pda, bump) = ..`
// collapses to an anonymous "destructured" binding) and `if`-condition
// expressions (stored on CFG edges, not in any node's statement list). Rather
// than widen the shared IR — which every other rule also consumes — this
// re-parses just the target function from its own source file with `syn` and
// walks the real AST. It only ever *adds* detections; if the file can't be
// read or the function can't be found, it contributes nothing and sub-check 1
// falls back to the signer-seeds signal alone.
// ─────────────────────────────────────────────────────────────────────────────

struct FunctionFinder {
    name: String,
    found: Option<Vec<syn::Stmt>>,
}

impl<'ast> Visit<'ast> for FunctionFinder {
    fn visit_item_fn(&mut self, i: &'ast syn::ItemFn) {
        if self.found.is_none() && i.sig.ident == self.name {
            self.found = Some(i.block.stmts.clone());
        }
        syn::visit::visit_item_fn(self, i);
    }

    fn visit_impl_item_fn(&mut self, i: &'ast syn::ImplItemFn) {
        if self.found.is_none() && i.sig.ident == self.name {
            self.found = Some(i.block.stmts.clone());
        }
        syn::visit::visit_impl_item_fn(self, i);
    }
}

fn is_pda_derivation_call_expr(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Call(call) => {
            let func = &call.func;
            let func_str = quote::quote!(#func).to_string().replace(' ', "");
            func_str.contains("find_program_address") || func_str.contains("create_program_address")
        }
        syn::Expr::Try(t) => is_pda_derivation_call_expr(&t.expr),
        syn::Expr::Paren(p) => is_pda_derivation_call_expr(&p.expr),
        syn::Expr::Reference(r) => is_pda_derivation_call_expr(&r.expr),
        _ => false,
    }
}

fn collect_pat_idents(pat: &syn::Pat, out: &mut HashSet<String>) {
    match pat {
        syn::Pat::Ident(pi) => {
            out.insert(pi.ident.to_string());
        }
        syn::Pat::Tuple(t) => {
            for elem in &t.elems {
                collect_pat_idents(elem, out);
            }
        }
        syn::Pat::Type(pt) => collect_pat_idents(&pt.pat, out),
        syn::Pat::Reference(pr) => collect_pat_idents(&pr.pat, out),
        _ => {}
    }
}

struct DerivationVarCollector<'a> {
    vars: &'a mut HashSet<String>,
}

impl<'a, 'ast> Visit<'ast> for DerivationVarCollector<'a> {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let Some(init) = &local.init {
            if is_pda_derivation_call_expr(&init.expr) {
                collect_pat_idents(&local.pat, self.vars);
            }
        }
        syn::visit::visit_local(self, local);
    }
}

/// Resolves a `.key()` receiver down to an account name: either a bare local
/// identifier, or a `<ctx_var>.accounts.<field>` path (unwrapping
/// `.to_account_info()`-style method chains and refs/derefs along the way).
fn resolve_syn_account_ref(expr: &syn::Expr, ctx_var: &str) -> Option<String> {
    match expr {
        syn::Expr::Path(p) => p.path.get_ident().map(|i| i.to_string()),
        syn::Expr::Field(f) => {
            if let syn::Expr::Field(inner) = &*f.base {
                if let syn::Member::Named(inner_field) = &inner.member {
                    if inner_field == "accounts" {
                        if let syn::Expr::Path(p) = &*inner.base {
                            if p.path.is_ident(ctx_var) {
                                if let syn::Member::Named(field) = &f.member {
                                    return Some(field.to_string());
                                }
                            }
                        }
                    }
                }
            }
            None
        }
        syn::Expr::MethodCall(mc) => resolve_syn_account_ref(&mc.receiver, ctx_var),
        syn::Expr::Reference(r) => resolve_syn_account_ref(&r.expr, ctx_var),
        syn::Expr::Paren(p) => resolve_syn_account_ref(&p.expr, ctx_var),
        syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => {
            resolve_syn_account_ref(&u.expr, ctx_var)
        }
        _ => None,
    }
}

fn resolve_syn_key_account(expr: &syn::Expr, ctx_var: &str) -> Option<String> {
    match expr {
        syn::Expr::MethodCall(mc) if mc.method == "key" => resolve_syn_account_ref(&mc.receiver, ctx_var),
        syn::Expr::Reference(r) => resolve_syn_key_account(&r.expr, ctx_var),
        syn::Expr::Paren(p) => resolve_syn_key_account(&p.expr, ctx_var),
        _ => None,
    }
}

fn is_derivation_var(expr: &syn::Expr, vars: &HashSet<String>) -> bool {
    matches!(expr, syn::Expr::Path(p) if p.path.get_ident().is_some_and(|i| vars.contains(&i.to_string())))
}

/// Extracts every `<ident>.key()` receiver name from a space-stripped token
/// string — used to read the macro form of the comparison idiom (e.g.
/// `check_eq!(expected, ctx.accounts.bank.key(), ..)`), since macro bodies
/// are only available as raw text, not a parsed expression tree.
fn extract_key_call_idents(raw_stripped: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let pattern = ".key()";
    let mut search_from = 0;
    while let Some(pos) = raw_stripped[search_from..].find(pattern) {
        let abs_pos = search_from + pos;
        let mut start = abs_pos;
        let bytes = raw_stripped.as_bytes();
        while start > 0 {
            let c = bytes[start - 1] as char;
            if c.is_alphanumeric() || c == '_' {
                start -= 1;
            } else {
                break;
            }
        }
        if start < abs_pos {
            out.insert(raw_stripped[start..abs_pos].to_string());
        }
        search_from = abs_pos + pattern.len();
    }
    out
}

struct ComparisonCollector<'a> {
    derivation_vars: &'a HashSet<String>,
    ctx_var: &'a str,
    found: &'a mut HashSet<String>,
}

impl<'a> ComparisonCollector<'a> {
    fn check_pair(&mut self, a: &syn::Expr, b: &syn::Expr) {
        if is_derivation_var(a, self.derivation_vars) {
            if let Some(acct) = resolve_syn_key_account(b, self.ctx_var) {
                self.found.insert(acct);
            }
        }
        if is_derivation_var(b, self.derivation_vars) {
            if let Some(acct) = resolve_syn_key_account(a, self.ctx_var) {
                self.found.insert(acct);
            }
        }
    }
}

impl<'a, 'ast> Visit<'ast> for ComparisonCollector<'a> {
    fn visit_expr_binary(&mut self, expr: &'ast syn::ExprBinary) {
        if matches!(expr.op, syn::BinOp::Eq(_) | syn::BinOp::Ne(_)) {
            self.check_pair(&expr.left, &expr.right);
        }
        syn::visit::visit_expr_binary(self, expr);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let tokens = &mac.tokens;
        let raw = quote::quote!(#tokens).to_string().replace(' ', "");
        let mentions_derivation_var = self.derivation_vars.iter().any(|v| raw.contains(v.as_str()));
        if mentions_derivation_var {
            for candidate in extract_key_call_idents(&raw) {
                self.found.insert(candidate);
            }
        }
        syn::visit::visit_macro(self, mac);
    }
}

/// Best-effort scan of the instruction's own source for accounts that are
/// specifically *verified* against a manually derived PDA — i.e. the account
/// whose `.key()` is compared against the `find_program_address`/
/// `create_program_address` result, not merely a seed ingredient. Returns an
/// empty set if the file can't be read, can't be parsed, or the function
/// can't be located; this signal only ever adds detections.
fn find_program_address_verified_accounts(
    file_path: &str,
    function_name: &str,
    ctx_var: &str,
) -> HashSet<String> {
    let mut result = HashSet::new();

    let content = match std::fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(_) => return result,
    };
    let file = match syn::parse_file(&content) {
        Ok(f) => f,
        Err(_) => return result,
    };

    let mut finder = FunctionFinder {
        name: function_name.to_string(),
        found: None,
    };
    finder.visit_file(&file);
    let Some(stmts) = finder.found else {
        return result;
    };

    let mut derivation_vars = HashSet::new();
    {
        let mut collector = DerivationVarCollector {
            vars: &mut derivation_vars,
        };
        for stmt in &stmts {
            collector.visit_stmt(stmt);
        }
    }
    if derivation_vars.is_empty() {
        return result;
    }

    let mut comparer = ComparisonCollector {
        derivation_vars: &derivation_vars,
        ctx_var,
        found: &mut result,
    };
    for stmt in &stmts {
        comparer.visit_stmt(stmt);
    }

    result
}

/// Computes the set of account field names that the instruction body
/// actually derives or signs for as a PDA, regardless of what the field
/// happens to be named — see the module-level notes above for why this is
/// two separate signals rather than one blanket scan.
///
/// The CFG walk iterates node ids in sorted order (rather than relying on
/// `HashMap` iteration order) so that signal is reproducible across runs,
/// per the determinism fix in commit bbd9438; the source re-parse is a pure
/// function of file content, so it is deterministic by construction.
fn collect_pda_usage_accounts(instruction_context: &InstructionAnalysisContext) -> HashSet<String> {
    let cfg = &instruction_context.cfg;
    let ctx_var = instruction_context.context_var_name.as_str();

    let mut node_ids: Vec<usize> = cfg.nodes.keys().copied().collect();
    node_ids.sort_unstable();

    let mut let_bindings = HashMap::new();
    for &node_id in &node_ids {
        if let Some(node) = cfg.nodes.get(&node_id) {
            collect_let_bindings_from_stmts(&node.statements, &mut let_bindings);
        }
    }

    let mut used = HashSet::new();
    for &node_id in &node_ids {
        if let Some(node) = cfg.nodes.get(&node_id) {
            collect_signer_seeds_usage_from_stmts(&node.statements, ctx_var, &let_bindings, &mut used);
        }
    }

    used.extend(find_program_address_verified_accounts(
        &instruction_context.file_path,
        &instruction_context.name,
        ctx_var,
    ));

    used
}

// ─────────────────────────────────────────────────────────────────────────────
// Rule implementation
// ─────────────────────────────────────────────────────────────────────────────

impl Rule for PdaDerivationRule {
    fn id(&self) -> &'static str {
        "EPIC-SEC-PDA"
    }

    fn name(&self) -> &'static str {
        "PDA Derivation and Bump Canonicality"
    }

    fn check(&self, context: &AnalysisContext) -> Vec<RuleDiagnostic> {
        let mut diagnostics = Vec::new();
        let instruction_context = &context.instruction_context;
        let struct_name = &instruction_context.context_struct_name;

        // Locate the context struct definition using the file-aware, deterministic helper.
        // This correctly handles same-named structs in different modules by preferring
        // the struct in the same file or directory as the instruction.
        let struct_match = crate::audit::find_struct_for_context(
            &context.ast_graph.registry,
            struct_name,
            &instruction_context.file_path,
        );

        // ─────────────────────────────────────────────────────────────────────
        // Sub-check 1: Missing PDA derivation gate
        // ─────────────────────────────────────────────────────────────────────
        if let Some((struct_path, struct_def)) = struct_match {
            let file_path = context
                .ast_graph
                .registry
                .file_paths
                .get(struct_path)
                .cloned()
                .unwrap_or_else(|| instruction_context.file_path.clone());

            let pda_usage_accounts = collect_pda_usage_accounts(instruction_context);

            for field in &struct_def.fields {
                // Gate: only real Anchor account fields.
                let field_sym = match instruction_context.symbol_table.get(&field.name) {
                    Some(&s) => s,
                    None => continue,
                };
                if !instruction_context.account_field_ids.contains(&field_sym) {
                    continue;
                }

                // Usage-based gate: is this account actually derived or
                // signed for as a PDA anywhere in the instruction body?
                if !pda_usage_accounts.contains(&field.name) {
                    continue;
                }

                // Is a PDA fact already present for this account?
                let has_pda_fact =
                    instruction_context.guard_facts.iter().any(|(fact, _)| {
                        matches!(fact, GuardFact::PDA { account, .. }
                            if account.symbol_id() == Some(field_sym))
                    });

                if !has_pda_fact {
                    diagnostics.push(RuleDiagnostic {
                        rule_id: self.id().to_string(),
                        severity: RuleSeverity::Critical,
                        message: format!(
                            "Account '{}' declared without PDA derivation constraint. \
                             Add `seeds = [...]` and `bump` to the `#[account(...)]` \
                             attribute to prevent account substitution attacks.",
                            field.name
                        ),
                        location: FindingLocation {
                            file: file_path.clone(),
                            line: field.line_number,
                            column: field.column_number,
                            node_id: 0,
                            statement_index: None,
                        },
                        confidence: FactConfidence::Asserted,
                        target_symbol: field_sym,
                    });
                }
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // Sub-check 2: Non-canonical (caller-supplied) bump detection
        // ─────────────────────────────────────────────────────────────────────
        for (fact, provenance) in &instruction_context.guard_facts {
            if let GuardFact::PDA {
                account,
                bump: Some(bump_expr),
                ..
            } = fact
            {
                if is_caller_supplied_bump(bump_expr, &instruction_context.symbol_table) {
                    let account_name = symbol_name(account, &instruction_context.symbol_table)
                        .unwrap_or_else(|| "<unknown>".to_string());

                    diagnostics.push(RuleDiagnostic {
                        rule_id: self.id().to_string(),
                        severity: RuleSeverity::Critical,
                        message: format!(
                            "PDA bump for '{}' is caller-supplied — use canonical bump \
                             derivation, not a caller-provided value. Replace `bump = {}` \
                             with bare `bump` (or store the canonical bump and load it from \
                             the account's own field).",
                            account_name,
                            fact_expr_to_string(bump_expr),
                        ),
                        location: FindingLocation {
                            file: provenance.source_file.clone(),
                            line: provenance.line_number,
                            column: provenance.column_number,
                            node_id: provenance.node_id.unwrap_or(0),
                            statement_index: provenance.statement_index,
                        },
                        confidence: FactConfidence::Asserted,
                        target_symbol: account.symbol_id().unwrap_or(SymbolId(0)),
                    });
                }
            }
        }

        diagnostics
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Display helpers
// ─────────────────────────────────────────────────────────────────────────────

fn fact_expr_to_string(expr: &FactExpression) -> String {
    match expr {
        FactExpression::Literal(s) => s.clone(),
        FactExpression::Target(t) => match t {
            GuardTarget::Literal(s) => s.clone(),
            GuardTarget::Variable(v) => format!("<var:{}>", v.symbol_id.0),
            GuardTarget::Account(s) => format!("<account:{}>", s.0),
        },
        FactExpression::PropertyOf { target, .. } => match target {
            GuardTarget::Literal(s) => format!("{}.property", s),
            GuardTarget::Variable(v) => format!("<var:{}>.property", v.symbol_id.0),
            GuardTarget::Account(s) => format!("<account:{}>.property", s.0),
        },
        FactExpression::BinaryOp { op, lhs, rhs } => format!(
            "{} {} {}",
            fact_expr_to_string(lhs),
            op,
            fact_expr_to_string(rhs)
        ),
        FactExpression::Unknown => "<unknown>".to_string(),
    }
}
