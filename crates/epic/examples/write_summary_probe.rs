//! Stage 2 demo: run `write_summary::compute_write_summary` on exactly one
//! method, in isolation, no caller involved — the thing the plan asked to
//! see before any wiring happens.
//!
//! Run: cargo run --release --example write_summary_probe -- <repo> <ImplType> <method>

use epic::callgraph::build_call_graph;
use epic::write_summary::compute_write_summary;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [repo, impl_type, method] = &args[..] else {
        eprintln!("usage: write_summary_probe <repo> <ImplType> <method>");
        std::process::exit(2);
    };

    let call_graph = build_call_graph(repo);
    let Some(id) = call_graph.resolve_typed(impl_type, method) else {
        eprintln!(
            "{}::{} did not resolve in this repo's call graph",
            impl_type, method
        );
        std::process::exit(1);
    };
    let info = call_graph
        .get(id)
        .expect("resolved id must exist in functions map");

    println!(
        "{}::{}  ({}, {} params)",
        impl_type,
        method,
        info.file_path,
        info.params.len()
    );
    let summary = compute_write_summary(info, &call_graph);
    if summary.writes.is_empty() {
        println!("  0 writes found — either a pure orchestrator (delegates to further\n  method calls, out of scope for single-hop) or genuinely has none.");
        return;
    }
    for w in &summary.writes {
        println!(
            "  write: self.{}  (line {}, node {}) — dominating guards: {}",
            w.field_path,
            w.line,
            w.node_id,
            if w.dominating_guards.is_empty() {
                "none".to_string()
            } else {
                w.dominating_guards.join(", ")
            }
        );
    }
}
