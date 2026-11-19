//! Minimal Soroban frontend for EPIC (v0).
//!
//! Entirely separate from the Anchor pipeline (`audit.rs`, `CFGBuilder`,
//! `GuardFact` extraction, the rule engine) -- nothing here is called by,
//! or changes the behavior of, `run_audit`/`for_each_analysis_context`.
//! Reuses shared *data types* (`ControlFlowGraph`, `GuardTarget`,
//! `RuleDiagnostic`, `DominanceChecker`) and, where the shapes actually
//! line up, shared *converters* (`cfg::builder::{convert_stmt, convert_expr}`).
//! Every place those shapes didn't line up is in `docs/soroban-core-leaks.md`.
//!
//! Entrypoints: `pub fn`s inside a `#[contractimpl]` block. Guards:
//! `<addr>.require_auth()` / `.require_auth_for_args(..)`. Sinks:
//! `env.storage().{instance,persistent,temporary}().set/remove(..)` and
//! `.transfer(..)`. One-hop same-crate helper calls are followed; anything
//! deeper is INCONCLUSIVE, never a guess.

mod analysis;
mod cfg_builder;

use crate::rules::RuleDiagnostic;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use syn::visit::Visit;
use walkdir::WalkDir;

pub struct SorobanEntrypoint {
    pub name: String,
    pub file_path: String,
    pub stmts: Vec<syn::Stmt>,
    pub sig_params: Vec<String>,
}

/// Crate-wide index of free (non-`#[contractimpl]`) functions, for one-hop
/// helper resolution. A name seen on 2+ functions anywhere in the crate is
/// recorded as ambiguous (`None`) -- same ambiguity-refusal convention
/// `callgraph.rs`'s bare-name resolution already uses -- so a call to it is
/// always treated as unresolved (INCONCLUSIVE), never a guess at which one.
#[derive(Default)]
pub(crate) struct HelperIndex(HashMap<String, Option<Vec<syn::Stmt>>>);

impl HelperIndex {
    fn record(&mut self, name: String, stmts: Vec<syn::Stmt>) {
        match self.0.get(&name) {
            None => {
                self.0.insert(name, Some(stmts));
            }
            Some(_) => {
                self.0.insert(name, None);
            }
        }
    }

    pub(crate) fn resolve(&self, name: &str) -> Option<&Vec<syn::Stmt>> {
        self.0.get(name).and_then(|s| s.as_ref())
    }

    pub(crate) fn names(&self) -> HashSet<String> {
        self.0.keys().cloned().collect()
    }
}

struct EntrypointVisitor {
    file_path: String,
    in_contractimpl: bool,
    entrypoints: Vec<SorobanEntrypoint>,
}

impl<'ast> Visit<'ast> for EntrypointVisitor {
    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        let is_contractimpl = i.attrs.iter().any(|a| a.path().is_ident("contractimpl"));
        let outer = self.in_contractimpl;
        if is_contractimpl {
            self.in_contractimpl = true;
        }
        syn::visit::visit_item_impl(self, i);
        self.in_contractimpl = outer;
    }

    fn visit_impl_item_fn(&mut self, i: &'ast syn::ImplItemFn) {
        if self.in_contractimpl && matches!(i.vis, syn::Visibility::Public(_)) {
            let sig_params = i.sig.inputs.iter().filter_map(param_name).collect();
            self.entrypoints.push(SorobanEntrypoint {
                name: i.sig.ident.to_string(),
                file_path: self.file_path.clone(),
                stmts: i.block.stmts.clone(),
                sig_params,
            });
        }
        syn::visit::visit_impl_item_fn(self, i);
    }
}

struct FreeFnVisitor<'a> {
    index: &'a mut HelperIndex,
}

impl<'ast> Visit<'ast> for FreeFnVisitor<'_> {
    fn visit_item_fn(&mut self, i: &'ast syn::ItemFn) {
        if !is_cfg_test(&i.attrs) {
            self.index
                .record(i.sig.ident.to_string(), i.block.stmts.clone());
        }
        syn::visit::visit_item_fn(self, i);
    }

    fn visit_item_mod(&mut self, i: &'ast syn::ItemMod) {
        // Test code never runs in production and shouldn't collide with a
        // same-named production helper in the index -- confirmed against a
        // real scout-soroban fixture (`set-contract-storage-4`) where a
        // `#[cfg(test)] mod tests { fn increment() { .. } }` test function
        // happened to share a name with the real helper, making the real
        // one "ambiguous" and silently unresolvable.
        if is_cfg_test(&i.attrs) {
            return;
        }
        syn::visit::visit_item_mod(self, i);
    }
}

fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("cfg")
            && a.parse_args::<syn::Ident>()
                .is_ok_and(|ident| ident == "test")
    })
}

fn param_name(arg: &syn::FnArg) -> Option<String> {
    match arg {
        syn::FnArg::Typed(pt) => match &*pt.pat {
            syn::Pat::Ident(pi) => Some(pi.ident.to_string()),
            _ => None,
        },
        _ => None,
    }
}

/// Walks every `.rs` file under `root_path`, discovering entrypoints and
/// building the same-crate helper index -- shared by `run_soroban_audit`
/// and `count_entrypoints` so the two can never see a different set of
/// entrypoints from each other. Also returns the path of every `.rs` file
/// that failed to parse, so a 0-entrypoint result can be told apart from a
/// parse failure that hid them.
fn discover(root_path: &str) -> (Vec<SorobanEntrypoint>, HelperIndex, Vec<String>) {
    let root = Path::new(root_path);
    let mut entrypoints = Vec::new();
    let mut helper_index = HelperIndex::default();
    let mut parse_failures = Vec::new();

    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if entry.path().extension().is_some_and(|e| e == "rs") {
            let Ok(content) = std::fs::read_to_string(entry.path()) else {
                continue;
            };
            let file_path = entry.path().to_string_lossy().into_owned();
            let Ok(file) = syn::parse_file(&content) else {
                parse_failures.push(file_path);
                continue;
            };

            let mut ev = EntrypointVisitor {
                file_path: file_path.clone(),
                in_contractimpl: false,
                entrypoints: Vec::new(),
            };
            ev.visit_file(&file);
            entrypoints.extend(ev.entrypoints);

            let mut fv = FreeFnVisitor {
                index: &mut helper_index,
            };
            fv.visit_file(&file);
        }
    }
    (entrypoints, helper_index, parse_failures)
}

/// Runs the Soroban v0 analysis over every `.rs` file found under
/// `root_path`. Returns findings in the same `RuleDiagnostic` shape the
/// Anchor rule engine uses, so output tooling (JSON/SARIF) doesn't need a
/// separate code path.
pub fn run_soroban_audit(root_path: &str) -> Vec<RuleDiagnostic> {
    let (entrypoints, helper_index, _parse_failures) = discover(root_path);
    let mut diagnostics = Vec::new();
    for ep in &entrypoints {
        diagnostics.extend(analysis::analyze_entrypoint(ep, &helper_index));
    }
    diagnostics
}

/// Reporting-only accessor added for the Round 2 held-out precision run:
/// how many entrypoints were found, and which files (if any) failed to
/// parse. Does not run or change any detection logic -- `run_soroban_audit`
/// is untouched behaviorally, just refactored to share `discover` with
/// this. A 0 here means a blind spot (nothing to analyze was even found),
/// not a verified-clean crate; `run_soroban_audit` returning 0 findings on
/// a crate with >0 entrypoints is the only legitimate "clean."
pub fn count_entrypoints(root_path: &str) -> (usize, Vec<String>) {
    let (entrypoints, _helper_index, parse_failures) = discover(root_path);
    (entrypoints.len(), parse_failures)
}
