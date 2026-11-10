//! Regression tests for run-to-run output determinism.
//!
//! `run_audit` must produce byte-identical diagnostics for byte-identical
//! source, every time — a static analyzer whose answer depends on process
//! RNG state isn't wrong on purpose, which is worse than being wrong on
//! purpose, because nothing points at it. Two confirmed instances (fixed
//! alongside this test, see `ControlFlowGraph::nodes_sorted` in
//! `cfg/nodes.rs`): EPIC-SEC-ARITH and EPIC-SEC-007 both walked
//! `cfg.nodes.values()` directly — `HashMap` iteration order, which is
//! randomized per process — while keeping only the first match found for a
//! given dedup key. Caught on the real 5-protocol sweep corpus
//! (mango-v4's finding count varied 54-56 across runs); reproduced here
//! with a minimal fixture so it doesn't need that corpus checked in.

fn fixture_path(name: &str) -> String {
    format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name)
}

/// Runs `run_audit` on the same fixture `n` times (fresh `HashMap`s each
/// time — the whole pipeline rebuilds its CFGs from scratch per call) and
/// asserts every run produces the exact same rule_id/file/line/column/
/// message sequence, in the exact same order.
fn assert_stable_output(fixture: &str, n: usize) {
    let path = fixture_path(fixture);
    let first = epic::run_audit(&path).expect("run_audit should succeed on a valid fixture");
    let first_keys: Vec<_> = first
        .iter()
        .map(|d| {
            (
                d.rule_id.clone(),
                d.location.file.clone(),
                d.location.line,
                d.location.column,
                d.message.clone(),
            )
        })
        .collect();

    for run in 1..n {
        let diagnostics =
            epic::run_audit(&path).expect("run_audit should succeed on a valid fixture");
        let keys: Vec<_> = diagnostics
            .iter()
            .map(|d| {
                (
                    d.rule_id.clone(),
                    d.location.file.clone(),
                    d.location.line,
                    d.location.column,
                    d.message.clone(),
                )
            })
            .collect();
        assert_eq!(
            keys, first_keys,
            "{}: run {} produced different diagnostics than run 0 — output is not deterministic",
            fixture, run
        );
    }
}

/// The exact bug: `amount` is subtracted in two sibling if/else branches
/// (same resolved path, two CFG nodes, two source lines). EPIC-SEC-ARITH
/// reports it exactly once — but which of the two lines it picks must be
/// the same every time, not a function of which process happened to run.
#[test]
fn test_arith_sibling_branches_stable_across_many_runs() {
    assert_stable_output("arith-sibling-branches", 20);
}

/// Same determinism property, broader fixture set, one sweep instead of
/// twenty: everything the existing fixture suite already exercises
/// (dominance, PDA, token, arith, close) must agree with itself across two
/// independent runs, not just the one fixture built to provoke the bug.
#[test]
fn test_existing_fixtures_stable_across_two_runs() {
    let fixtures = [
        "dominance-safe",
        "dominance-bypass",
        "arith-bound-dominates",
        "arith-bound-inside-if",
        "arith-no-bound",
        "arith-cross-field-no-bound",
        "arith-same-field-bound-dominates",
        "arith-loop-and-index-clean",
        "pda-bump-canonical",
        "pda-bump-caller-supplied",
        "callgraph-basic",
        "summary-deep-chain",
        "closing-accounts-safe",
        "duplicate-mutable-accounts-body-guard",
    ];
    for fixture in fixtures {
        assert_stable_output(fixture, 2);
    }
}
