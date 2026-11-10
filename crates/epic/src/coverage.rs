//! Coverage reporting: how much of a program's instruction surface EPIC's
//! rules actually got to see, independent of what they found.
//!
//! A 0-finding repo and a fully-analyzed-and-clean repo look identical in
//! `epic audit`'s output — but they mean completely different things. This
//! module answers "how many instruction handlers exist, how many resolved
//! to an `Accounts` struct, and how many were analyzed without hitting a
//! structural boundary (a loop, a `match`, recursion)" so the difference is
//! visible instead of silently collapsing to the same empty finding list.
//!
//! Deliberately lighter than `for_each_analysis_context`: no call graph, no
//! SSA, no guard-fact extraction — coverage only needs to know whether a
//! handler's `Accounts` struct resolved and whether its CFG hit a boundary,
//! not what any rule would conclude from it.

use crate::audit::{discover_raw_functions, find_struct_by_name};
use crate::cfg::{CFGBoundaryWarning, CFGBuilder};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status")]
pub enum CoverageStatus {
    /// Resolved to an `Accounts` struct, CFG built cleanly, no boundary
    /// warnings — every rule got a full, unobstructed view of this handler.
    FullyAnalyzed,
    /// Resolved and analyzed, but the CFG hit a structural boundary (a
    /// loop body, a `match` arm, or recursion) that it doesn't model —
    /// rules still ran, but on a CFG that doesn't cover 100% of the
    /// handler's real control flow.
    PartiallyAnalyzed {
        boundary_warnings: Vec<CFGBoundaryWarning>,
    },
    /// No `Accounts` struct could be resolved for this handler's
    /// `Context<T>` argument — no rule saw this handler at all.
    Unresolved { reason: String },
    /// The struct resolved, but building a CFG from the handler's body
    /// itself failed — no rule saw this handler at all.
    CfgBuildFailed,
}

#[derive(Debug, Clone, Serialize)]
pub struct HandlerCoverage {
    pub name: String,
    pub file: String,
    pub status: CoverageStatus,
}

#[derive(Debug, Clone, Serialize)]
pub struct CoverageReport {
    pub total_handlers: usize,
    pub resolved_to_struct: usize,
    pub fully_analyzed: usize,
    /// `.rs` files that failed to parse entirely — any handler inside one
    /// is absent from `handlers` below, not just unresolved, since it was
    /// never even discovered.
    pub files_failed_to_parse: Vec<String>,
    pub handlers: Vec<HandlerCoverage>,
}

pub fn collect_coverage(root_path: &str) -> CoverageReport {
    let (workspace, raw_functions, files_failed_to_parse) = discover_raw_functions(root_path);

    let mut handlers = Vec::with_capacity(raw_functions.len());
    let mut resolved_to_struct = 0;
    let mut fully_analyzed = 0;

    for raw_fn in &raw_functions {
        let status = match find_struct_by_name(
            &workspace.registry,
            &raw_fn.program_name,
            &raw_fn.module_path,
            &raw_fn.context_struct_name,
        ) {
            None => {
                let reason = if raw_fn.context_struct_name == "Self" {
                    "Context<Self> — no enclosing impl-type tracking to resolve it".to_string()
                } else {
                    format!(
                        "no Accounts struct named '{}' found",
                        raw_fn.context_struct_name
                    )
                };
                CoverageStatus::Unresolved { reason }
            }
            Some(_) => {
                resolved_to_struct += 1;
                let mut cfg_builder = CFGBuilder::new();
                match cfg_builder.compile_statements(&raw_fn.stmts, 0) {
                    Err(_) => CoverageStatus::CfgBuildFailed,
                    Ok(_) => {
                        let warnings = cfg_builder.graph.boundary_warnings.clone();
                        if warnings.is_empty() {
                            fully_analyzed += 1;
                            CoverageStatus::FullyAnalyzed
                        } else {
                            CoverageStatus::PartiallyAnalyzed {
                                boundary_warnings: warnings,
                            }
                        }
                    }
                }
            }
        };

        handlers.push(HandlerCoverage {
            name: raw_fn.name.clone(),
            file: raw_fn.file_path.clone(),
            status,
        });
    }

    CoverageReport {
        total_handlers: raw_functions.len(),
        resolved_to_struct,
        fully_analyzed,
        files_failed_to_parse,
        handlers,
    }
}
