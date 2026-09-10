use crate::types::{StructDef, TypeRef};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use syn::parse::Parser;

/// A globally unique symbol identifier within an instruction handler context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SymbolId(pub usize);

/// Identifies a specific version of a symbol in the SSA-lite tracking system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SSAVersionId {
    pub symbol_id: SymbolId,
    pub version: usize,
}

/// A canonical target of a guard constraint.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GuardTarget {
    Variable(SSAVersionId),
    Account(SymbolId),
    Literal(String),
}

impl GuardTarget {
    pub fn symbol_id(&self) -> Option<SymbolId> {
        match self {
            GuardTarget::Variable(v) => Some(v.symbol_id),
            GuardTarget::Account(s) => Some(*s),
            GuardTarget::Literal(_) => None,
        }
    }
}

/// A framework-neutral semantic expression layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactExpression {
    Target(GuardTarget),
    Literal(String),
    PropertyOf {
        target: GuardTarget,
        property: SolanaProperty,
    },
    BinaryOp {
        op: String,
        lhs: Box<FactExpression>,
        rhs: Box<FactExpression>,
    },
    Unknown,
}

/// Standard Solana Virtual Machine account properties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SolanaProperty {
    Address,
    Owner,
    Lamports,
    DataLength,
    IsSigner,
    IsWritable,
    Executable,
    Bump,
}

/// Structured security metadata derived from declarations or explicit checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardFact {
    Signer(GuardTarget),
    Owner {
        account: GuardTarget,
        expected_owner: FactExpression,
    },
    KeyRelation {
        account: GuardTarget,
        field: SolanaProperty,
        target: GuardTarget,
    },
    PDA {
        account: GuardTarget,
        seeds: Vec<FactExpression>,
        bump: Option<FactExpression>,
    },
    Initialized {
        account: GuardTarget,
        payer: GuardTarget,
        space: Option<FactExpression>,
    },
    Resized {
        account: GuardTarget,
        new_size: FactExpression,
        payer: GuardTarget,
    },
    Deallocated {
        account: GuardTarget,
        destination: GuardTarget,
    },
    Custom {
        namespace: String,
        kind: String,
        payload: Vec<FactExpression>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DominanceInterval {
    pub dfs_entry: usize,
    pub dfs_exit: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardFactLocation {
    pub node_id: usize,
    pub statement_index: Option<usize>,
    pub dominance_interval: DominanceInterval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactConfidence {
    Declared,
    Asserted,
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactProvenance {
    pub source_file: String,
    pub line_number: usize,
    pub column_number: usize,
    pub framework: String,
    pub confidence_level: FactConfidence,
    #[serde(default)]
    pub node_id: Option<usize>,
    #[serde(default)]
    pub statement_index: Option<usize>,
}

impl FactProvenance {
    pub fn default_declared() -> Self {
        Self {
            source_file: "lib.rs".to_string(),
            line_number: 0,
            column_number: 0,
            framework: "Anchor".to_string(),
            confidence_level: FactConfidence::Declared,
            node_id: None,
            statement_index: None,
        }
    }
}

/// The analysis context for a single instruction handler, combining GuardFacts with CFG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionAnalysisContext {
    pub name: String,
    pub guard_facts: Vec<(GuardFact, FactProvenance)>,
    pub cfg: crate::cfg::ControlFlowGraph,
    #[serde(default)]
    pub symbol_table: HashMap<String, SymbolId>,
    /// The subset of symbol_table IDs that originate from real Anchor #[derive(Accounts)]
    /// struct fields. Local let-bindings, parameters, and seed arrays are NOT included.
    #[serde(default)]
    pub account_field_ids: std::collections::HashSet<SymbolId>,
    #[serde(default)]
    pub file_path: String,
    #[serde(default = "default_context_var")]
    pub context_var_name: String,
    #[serde(default)]
    pub context_struct_name: String,
}

fn default_context_var() -> String {
    "ctx".to_string()
}

// === Parser & Translator Implementation ===

#[allow(dead_code)]
#[derive(Debug, Clone)]
enum ParsedAttributeMeta {
    Mut,
    Signer,
    Owner(syn::Expr),
    HasOne(syn::Expr),
    Constraint(syn::Expr),
    Close(syn::Expr),
    Seeds(syn::Expr),
    Bump(Option<syn::Expr>),
    Init,
    Realloc(syn::Expr),
    Space(syn::Expr),
    Payer(syn::Expr),
}

fn preprocess_anchor_attribute_string(body: &str) -> String {
    let mut result = String::new();
    let mut depth: usize = 0;
    let mut skipping = false;

    for c in body.chars() {
        match c {
            '(' | '[' | '{' => {
                depth += 1;
                if !skipping {
                    result.push(c);
                }
            }
            ')' | ']' | '}' => {
                depth = depth.saturating_sub(1);
                if !skipping {
                    result.push(c);
                }
            }
            '@' if depth == 0 => {
                skipping = true;
            }
            ',' if depth == 0 => {
                skipping = false;
                result.push(c);
            }
            _ => {
                if !skipping {
                    result.push(c);
                }
            }
        }
    }
    result
}

fn parse_anchor_attribute_string(attr_str: &str) -> Vec<ParsedAttributeMeta> {
    let mut results = Vec::new();

    // Normalize string: Remove starting #[account( and ending )
    let body = if attr_str.starts_with("#[account(") && attr_str.ends_with(")]") {
        &attr_str["#[account(".len()..attr_str.len() - ")]".len()]
    } else if attr_str.starts_with("account(") && attr_str.ends_with(")") {
        &attr_str["account(".len()..attr_str.len() - ")".len()]
    } else {
        attr_str
    };

    let body_preprocessed = preprocess_anchor_attribute_string(body);

    // Preprocess: Replace standalone "mut" keyword with "writable" to avoid syn syntax error
    let parts: Vec<String> = body_preprocessed
        .split(',')
        .map(|s| {
            let trimmed = s.trim();
            if trimmed == "mut" {
                "writable".to_string()
            } else {
                s.to_string()
            }
        })
        .collect();
    let body_normalized = parts.join(",");

    // Use syn to parse the tokens inside the attribute parameters list
    let tokens: proc_macro2::TokenStream = match body_normalized.parse() {
        Ok(t) => t,
        Err(_) => return results,
    };

    let parser = syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated;
    let meta_list = match parser.parse2(tokens) {
        Ok(parsed) => parsed,
        Err(_) => {
            return results;
        }
    };

    for meta in meta_list {
        match meta {
            syn::Meta::Path(path) => {
                let ident = path.get_ident().map(|id| id.to_string());
                match ident.as_deref() {
                    Some("writable") => results.push(ParsedAttributeMeta::Mut),
                    Some("signer") => results.push(ParsedAttributeMeta::Signer),
                    Some("init") => results.push(ParsedAttributeMeta::Init),
                    Some("bump") => results.push(ParsedAttributeMeta::Bump(None)),
                    _ => {}
                }
            }
            syn::Meta::NameValue(nv) => {
                let ident = nv.path.get_ident().map(|id| id.to_string());
                match ident.as_deref() {
                    Some("owner") => results.push(ParsedAttributeMeta::Owner(nv.value)),
                    Some("has_one") => results.push(ParsedAttributeMeta::HasOne(nv.value)),
                    Some("constraint") => results.push(ParsedAttributeMeta::Constraint(nv.value)),
                    Some("close") => results.push(ParsedAttributeMeta::Close(nv.value)),
                    Some("seeds") => results.push(ParsedAttributeMeta::Seeds(nv.value)),
                    Some("bump") => results.push(ParsedAttributeMeta::Bump(Some(nv.value))),
                    Some("realloc") => results.push(ParsedAttributeMeta::Realloc(nv.value)),
                    Some("space") => results.push(ParsedAttributeMeta::Space(nv.value)),
                    Some("payer") => results.push(ParsedAttributeMeta::Payer(nv.value)),
                    _ => {}
                }
            }
            _ => {}
        }
    }

    results
}

/// Strips trivial accessor wrappers (`?`, parens, and method calls) off an
/// expression to find the underlying object identity — e.g. `bank.load()?`
/// strips down to `bank`. Used when resolving the base of a field access so
/// zero-copy `AccountLoader<'info, T>` patterns (`bank.load()?.some_bump`)
/// resolve to the same target as a direct field access would. This does not
/// attempt to interpret *what* the method call does, only to see through it
/// for identity purposes, so it is conservative by construction: it can only
/// ever change a base from "unresolved literal text" to "resolved account
/// symbol", never the reverse.
fn strip_accessor_wrappers(expr: &syn::Expr) -> &syn::Expr {
    match expr {
        syn::Expr::Try(inner) => strip_accessor_wrappers(&inner.expr),
        syn::Expr::Paren(inner) => strip_accessor_wrappers(&inner.expr),
        syn::Expr::MethodCall(inner) => strip_accessor_wrappers(&inner.receiver),
        _ => expr,
    }
}

pub fn convert_syn_expr(
    expr: &syn::Expr,
    symbol_table: &HashMap<String, SymbolId>,
) -> FactExpression {
    match expr {
        syn::Expr::Path(expr_path) => {
            let name = quote::quote!(#expr_path).to_string().replace(" ", "");
            if let Some(&symbol_id) = symbol_table.get(&name) {
                FactExpression::Target(GuardTarget::Variable(SSAVersionId {
                    symbol_id,
                    version: 1,
                }))
            } else {
                FactExpression::Literal(name)
            }
        }
        syn::Expr::Lit(expr_lit) => {
            let val = quote::quote!(#expr_lit).to_string().replace(" ", "");
            FactExpression::Literal(val)
        }
        syn::Expr::Field(expr_field) => {
            // Resolve the base through trivial wrapper calls (`?`, `.load()`,
            // `.load_mut()`, parens, etc.) so `bank.load()?.liquidity_vault_bump`
            // resolves to the same target as a plain `bank.bump` would — Anchor's
            // zero-copy `AccountLoader<'info, T>` accessor pattern is extremely
            // common and the underlying account identity is unaffected by it.
            let unwrapped_base = strip_accessor_wrappers(&expr_field.base);
            let base = convert_syn_expr(unwrapped_base, symbol_table);
            let field = match &expr_field.member {
                syn::Member::Named(ident) => ident.to_string(),
                syn::Member::Unnamed(idx) => idx.index.to_string(),
            };
            let target = match base {
                FactExpression::Target(t) => t,
                _ => {
                    let base_expr = &expr_field.base;
                    GuardTarget::Literal(quote::quote!(#base_expr).to_string().replace(" ", ""))
                }
            };
            let property = if field == "owner" {
                SolanaProperty::Owner
            } else if field == "lamports" {
                SolanaProperty::Lamports
            } else if field == "key" {
                SolanaProperty::Address
            } else if field.contains("bump") {
                // Anchor programs store canonical bumps under a wide variety
                // of names — a bare `bump`, a per-purpose suffix like
                // `liquidity_vault_authority_bump` (marginfi, mango-v4), or a
                // `_bump_seed` suffix (marinade's `sol_leg_bump_seed`). All of
                // these are equally "the stored bump", so a broad substring
                // match is used here rather than chasing each naming
                // convention individually as it's discovered.
                //
                // TODO(principled fix): this is still a name heuristic, not a
                // use-based one, and will both over- and under-match: a field
                // named e.g. `debump` would false-positive, and a
                // renamed/obfuscated bump field would false-negative. The
                // correct signal is how the value is *used* — does it flow
                // into a `seeds = [...]` array or a `with_signer`/
                // `invoke_signed` signer-seeds argument as the trailing bump
                // byte — the same use-based approach EPIC-SEC-PDA's sub-check
                // 1 (missing derivation) already takes for identifying PDA
                // accounts, rather than matching on field names at all.
                SolanaProperty::Bump
            } else {
                SolanaProperty::Address
            };
            FactExpression::PropertyOf { target, property }
        }
        syn::Expr::Binary(expr_binary) => {
            let op_token = &expr_binary.op;
            let op = match op_token {
                syn::BinOp::Eq(_) => "==".to_string(),
                syn::BinOp::Ne(_) => "!=".to_string(),
                syn::BinOp::Lt(_) => "<".to_string(),
                syn::BinOp::Gt(_) => ">".to_string(),
                _ => quote::quote!(#op_token).to_string().replace(" ", ""),
            };
            let lhs = convert_syn_expr(&expr_binary.left, symbol_table);
            let rhs = convert_syn_expr(&expr_binary.right, symbol_table);
            FactExpression::BinaryOp {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            }
        }
        _ => {
            let val = quote::quote!(#expr).to_string().replace(" ", "");
            FactExpression::Literal(val)
        }
    }
}

fn unwrap_account_type(type_ref: &TypeRef) -> Option<String> {
    match type_ref {
        TypeRef::Option(inner) => unwrap_account_type(inner),
        TypeRef::Custom(name) => Some(name.clone()),
        _ => None,
    }
}

/// Ingest and translate Anchor field declarations of an Accounts struct into canonical GuardFacts.
pub fn extract_guards_from_accounts_struct(
    struct_def: &StructDef,
    symbol_table: &mut HashMap<String, SymbolId>,
    next_symbol_id: &mut usize,
) -> Vec<(GuardFact, FactProvenance)> {
    let mut facts = Vec::new();

    // First, populate the symbol table for all account fields in this struct
    for field in &struct_def.fields {
        if !symbol_table.contains_key(&field.name) {
            symbol_table.insert(field.name.clone(), SymbolId(*next_symbol_id));
            *next_symbol_id += 1;
        }
    }

    for field in &struct_def.fields {
        let account_symbol = symbol_table.get(&field.name).cloned().unwrap();
        let target_acc = GuardTarget::Account(account_symbol);

        // Map implicit ownership validation checks based on TypeRef
        if let Some(custom_type) = unwrap_account_type(&field.type_ref) {
            if custom_type == "Account"
                || custom_type.starts_with("Account<")
                || custom_type == "AccountLoader"
                || custom_type.starts_with("AccountLoader<")
                || custom_type == "InterfaceAccount"
                || custom_type.starts_with("InterfaceAccount<")
            {
                // Implicit owner validation fact (Account<'info, T> owner is the current program ID)
                facts.push((
                    GuardFact::Owner {
                        account: target_acc.clone(),
                        expected_owner: FactExpression::Literal("program_id".to_string()),
                    },
                    FactProvenance::default_declared(),
                ));
            }
            if custom_type == "Signer" || custom_type.starts_with("Signer<") {
                facts.push((
                    GuardFact::Signer(target_acc.clone()),
                    FactProvenance::default_declared(),
                ));
            }
        }

        // Parse explicit constraints
        for attr_str in &field.attrs {
            let parsed_metas = parse_anchor_attribute_string(attr_str);

            let mut is_init = false;
            let mut payer_target = None;
            let mut space_expr = None;

            for meta in &parsed_metas {
                match meta {
                    ParsedAttributeMeta::Mut => {
                        // SVM-level is_writable constraint
                        facts.push((
                            GuardFact::KeyRelation {
                                account: target_acc.clone(),
                                field: SolanaProperty::IsWritable,
                                target: GuardTarget::Literal("true".to_string()),
                            },
                            FactProvenance::default_declared(),
                        ));
                    }
                    ParsedAttributeMeta::Signer => {
                        facts.push((
                            GuardFact::Signer(target_acc.clone()),
                            FactProvenance::default_declared(),
                        ));
                    }
                    ParsedAttributeMeta::HasOne(expr) => {
                        let target_expr = convert_syn_expr(expr, symbol_table);
                        let target_var = match target_expr {
                            FactExpression::Target(t) => t,
                            _ => GuardTarget::Literal(
                                quote::quote!(#expr).to_string().replace(" ", ""),
                            ),
                        };
                        facts.push((
                            GuardFact::KeyRelation {
                                account: target_acc.clone(),
                                field: SolanaProperty::Address,
                                target: target_var,
                            },
                            FactProvenance::default_declared(),
                        ));
                    }
                    ParsedAttributeMeta::Owner(expr) => {
                        let owner_expr = convert_syn_expr(expr, symbol_table);
                        facts.push((
                            GuardFact::Owner {
                                account: target_acc.clone(),
                                expected_owner: owner_expr,
                            },
                            FactProvenance::default_declared(),
                        ));
                    }
                    ParsedAttributeMeta::Close(expr) => {
                        let dest_expr = convert_syn_expr(expr, symbol_table);
                        let dest_target = match dest_expr {
                            FactExpression::Target(t) => t,
                            _ => GuardTarget::Literal(
                                quote::quote!(#expr).to_string().replace(" ", ""),
                            ),
                        };
                        facts.push((
                            GuardFact::Deallocated {
                                account: target_acc.clone(),
                                destination: dest_target,
                            },
                            FactProvenance::default_declared(),
                        ));
                    }
                    ParsedAttributeMeta::Seeds(expr) => {
                        let seed_expr = convert_syn_expr(expr, symbol_table);
                        facts.push((
                            GuardFact::PDA {
                                account: target_acc.clone(),
                                seeds: vec![seed_expr],
                                bump: None,
                            },
                            FactProvenance::default_declared(),
                        ));
                    }
                    ParsedAttributeMeta::Bump(opt_expr) => {
                        let bump_expr =
                            opt_expr.as_ref().map(|e| convert_syn_expr(e, symbol_table));
                        // Update existing PDA fact with bump if present
                        if let Some(pos) = facts
                            .iter()
                            .position(|f| matches!(f.0, GuardFact::PDA { .. }))
                        {
                            if let GuardFact::PDA { account, seeds, .. } = &facts[pos].0 {
                                facts[pos].0 = GuardFact::PDA {
                                    account: account.clone(),
                                    seeds: seeds.clone(),
                                    bump: bump_expr,
                                };
                            }
                        }
                    }
                    ParsedAttributeMeta::Init => {
                        is_init = true;
                    }
                    ParsedAttributeMeta::Payer(expr) => {
                        let payer_val = convert_syn_expr(expr, symbol_table);
                        payer_target = match payer_val {
                            FactExpression::Target(t) => Some(t),
                            _ => Some(GuardTarget::Literal(
                                quote::quote!(#expr).to_string().replace(" ", ""),
                            )),
                        };
                    }
                    ParsedAttributeMeta::Space(expr) => {
                        space_expr = Some(convert_syn_expr(expr, symbol_table));
                    }
                    ParsedAttributeMeta::Realloc(expr) => {
                        let size_expr = convert_syn_expr(expr, symbol_table);
                        facts.push((
                            GuardFact::Resized {
                                account: target_acc.clone(),
                                new_size: size_expr,
                                payer: GuardTarget::Literal("payer".to_string()),
                            },
                            FactProvenance::default_declared(),
                        ));
                    }
                    _ => {}
                }
            }

            if is_init {
                let payer = payer_target.unwrap_or(GuardTarget::Literal("payer".to_string()));
                facts.push((
                    GuardFact::Initialized {
                        account: target_acc.clone(),
                        payer,
                        space: space_expr,
                    },
                    FactProvenance::default_declared(),
                ));
            }
        }
    }

    facts
}

use std::collections::HashSet;

fn is_terminating_branch(
    cfg: &crate::cfg::ControlFlowGraph,
    start_node: usize,
    escape_node: usize,
) -> bool {
    let mut visited = HashSet::new();
    let mut queue = Vec::new();
    queue.push(start_node);
    visited.insert(start_node);

    while let Some(current) = queue.pop() {
        if current == escape_node {
            return false;
        }
        // Find all outgoing edges from current
        for edge in &cfg.edges {
            if edge.from == current && visited.insert(edge.to) {
                queue.push(edge.to);
            }
        }
    }
    true
}

pub fn extract_owner_check_from_ir_expr(
    expr: &epic_ir::IRExpression,
) -> Option<(String, String, String)> {
    if let epic_ir::IRExpression::BinaryOp { op, lhs, rhs } = expr {
        if op == "==" || op == "!=" {
            if let Some(acc) = get_account_from_owner_field_ir(lhs) {
                let expected = ir_expr_to_string(rhs);
                return Some((acc, expected, op.clone()));
            }
            if let Some(acc) = get_account_from_owner_field_ir(rhs) {
                let expected = ir_expr_to_string(lhs);
                return Some((acc, expected, op.clone()));
            }
        }
    }
    None
}

fn get_account_from_owner_field_ir(expr: &epic_ir::IRExpression) -> Option<String> {
    if let epic_ir::IRExpression::FieldAccess { object, field } = expr {
        if field == "owner" {
            let obj_str = ir_expr_to_string(object);
            if obj_str.starts_with("ctx.accounts.") {
                return Some(obj_str["ctx.accounts.".len()..].to_string());
            } else {
                return Some(obj_str);
            }
        }
    }
    None
}

fn ir_expr_to_string(expr: &epic_ir::IRExpression) -> String {
    match expr {
        epic_ir::IRExpression::Variable(name) => name.clone(),
        epic_ir::IRExpression::Literal(val) => val.clone(),
        epic_ir::IRExpression::FieldAccess { object, field } => {
            format!("{}.{}", ir_expr_to_string(object), field)
        }
        // `&spl_token::ID` / `*owner_ref` / `foo()?` — a reference, deref, or
        // try-unwrap around an owner-comparison value is transparent to its
        // identity for this purpose. Without unwrapping these, the extremely
        // common `account.owner != &SomeProgram::ID` idiom stringified to
        // "unknown" and could never match is_valid_expected_owner's
        // whitelist, regardless of what that whitelist accepts.
        epic_ir::IRExpression::Reference { expression, .. }
        | epic_ir::IRExpression::Dereference(expression)
        | epic_ir::IRExpression::Try(expression) => ir_expr_to_string(expression),
        _ => "unknown".to_string(),
    }
}

fn extract_signer_check_from_ir_expr(expr: &epic_ir::IRExpression) -> Option<(String, bool)> {
    match expr {
        epic_ir::IRExpression::FieldAccess { object, field } => {
            if field == "is_signer" {
                let obj_str = ir_expr_to_string(object);
                let acc = if obj_str.starts_with("ctx.accounts.") {
                    obj_str["ctx.accounts.".len()..].to_string()
                } else {
                    obj_str
                };
                return Some((acc, true));
            }
        }
        epic_ir::IRExpression::BinaryOp { op, lhs, rhs } => {
            if op == "!" {
                if let Some((acc, expected)) = extract_signer_check_from_ir_expr(lhs) {
                    return Some((acc, !expected));
                }
            } else if op == "==" || op == "!=" {
                if let Some((acc, base_expected)) = extract_signer_check_from_ir_expr(lhs) {
                    let val_str = ir_expr_to_string(rhs);
                    let val_bool = if val_str == "true" {
                        true
                    } else if val_str == "false" {
                        false
                    } else {
                        return None;
                    };
                    let final_expected = if op == "==" {
                        val_bool == base_expected
                    } else {
                        val_bool != base_expected
                    };
                    return Some((acc, final_expected));
                }
                if let Some((acc, base_expected)) = extract_signer_check_from_ir_expr(rhs) {
                    let val_str = ir_expr_to_string(lhs);
                    let val_bool = if val_str == "true" {
                        true
                    } else if val_str == "false" {
                        false
                    } else {
                        return None;
                    };
                    let final_expected = if op == "==" {
                        val_bool == base_expected
                    } else {
                        val_bool != base_expected
                    };
                    return Some((acc, final_expected));
                }
            }
        }
        _ => {}
    }
    None
}

pub fn extract_imperative_checks_ir(
    cfg: &crate::cfg::ControlFlowGraph,
    symbol_table: &HashMap<String, SymbolId>,
    file_path: &str,
) -> Vec<(GuardFact, FactProvenance)> {
    let mut facts = Vec::new();

    // 1. Process If Statement Conditions on CFG Edges
    for edge in &cfg.edges {
        if let Some(cond) = &edge.ir_condition {
            if let Some((acc_name, expected_owner_str, op)) = extract_owner_check_from_ir_expr(cond)
            {
                if let Some(&symbol_id) = symbol_table.get(&acc_name) {
                    let target_acc = GuardTarget::Account(symbol_id);

                    if op == "!=" {
                        let else_node_opt = cfg
                            .edges
                            .iter()
                            .find(|e| e.from == edge.from && e.to != edge.to)
                            .map(|e| e.to);
                        if let Some(else_node) = else_node_opt {
                            if is_terminating_branch(cfg, edge.to, else_node) {
                                facts.push((
                                    GuardFact::Owner {
                                        account: target_acc.clone(),
                                        expected_owner: FactExpression::Literal(expected_owner_str),
                                    },
                                    FactProvenance {
                                        source_file: file_path.to_string(),
                                        line_number: 0,
                                        column_number: 0,
                                        framework: "Anchor".to_string(),
                                        confidence_level: FactConfidence::Asserted,
                                        node_id: Some(else_node),
                                        statement_index: None,
                                    },
                                ));
                            }
                        }
                    } else if op == "==" {
                        let else_node_opt = cfg
                            .edges
                            .iter()
                            .find(|e| e.from == edge.from && e.to != edge.to)
                            .map(|e| e.to);
                        if let Some(else_node) = else_node_opt {
                            if is_terminating_branch(cfg, else_node, edge.to) {
                                facts.push((
                                    GuardFact::Owner {
                                        account: target_acc.clone(),
                                        expected_owner: FactExpression::Literal(expected_owner_str),
                                    },
                                    FactProvenance {
                                        source_file: file_path.to_string(),
                                        line_number: 0,
                                        column_number: 0,
                                        framework: "Anchor".to_string(),
                                        confidence_level: FactConfidence::Asserted,
                                        node_id: Some(edge.to),
                                        statement_index: None,
                                    },
                                ));
                            }
                        }
                    }
                }
            }

            if let Some((acc_name, is_signer)) = extract_signer_check_from_ir_expr(cond) {
                if let Some(&symbol_id) = symbol_table.get(&acc_name) {
                    let target_acc = GuardTarget::Account(symbol_id);
                    let else_node_opt = cfg
                        .edges
                        .iter()
                        .find(|e| e.from == edge.from && e.to != edge.to)
                        .map(|e| e.to);
                    if let Some(else_node) = else_node_opt {
                        if is_signer {
                            if is_terminating_branch(cfg, else_node, edge.to) {
                                facts.push((
                                    GuardFact::Signer(target_acc),
                                    FactProvenance {
                                        source_file: file_path.to_string(),
                                        line_number: 0,
                                        column_number: 0,
                                        framework: "Anchor".to_string(),
                                        confidence_level: FactConfidence::Asserted,
                                        node_id: Some(edge.to),
                                        statement_index: None,
                                    },
                                ));
                            }
                        } else if is_terminating_branch(cfg, edge.to, else_node) {
                            facts.push((
                                GuardFact::Signer(target_acc),
                                FactProvenance {
                                    source_file: file_path.to_string(),
                                    line_number: 0,
                                    column_number: 0,
                                    framework: "Anchor".to_string(),
                                    confidence_level: FactConfidence::Asserted,
                                    node_id: Some(else_node),
                                    statement_index: None,
                                },
                            ));
                        }
                    }
                }
            }
        }
    }

    facts
}
