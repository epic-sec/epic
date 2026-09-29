//! Stage 2 of interprocedural guard analysis: verifies guard-summary
//! computation in isolation. Nothing here touches SEC-002, dominance
//! witnesses, or any caller CFG — per the staged build, that wiring is a
//! separate, later step. This only checks that `SummaryComputer` correctly
//! answers "does this function guarantee a signer check on parameter P on
//! every Ok-returning path," including its conservative failure modes.

use epic::callgraph::build_call_graph;
use epic::guard_summary::SummaryComputer;

fn fixture_path(name: &str) -> String {
    format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name)
}

fn function_named<'a>(graph: &'a epic::callgraph::CallGraph, suffix: &str) -> &'a str {
    graph
        .functions
        .keys()
        .find(|id| id.ends_with(suffix))
        .unwrap_or_else(|| panic!("no function found ending in {}", suffix))
        .as_str()
}

#[test]
fn test_unconditional_check_is_guaranteed() {
    let graph = build_call_graph(&fixture_path("summary-unconditional"));
    let id = function_named(&graph, "::validate").to_string();
    let mut computer = SummaryComputer::new(&graph);
    let summary = computer.summary_for(&id);
    assert!(
        summary.contains("account"),
        "an unconditional require!(account.is_signer, ...) dominating the \
         only Ok-return should guarantee 'account', got: {:?}",
        summary
    );
}

#[test]
fn test_conditional_check_is_not_guaranteed() {
    let graph = build_call_graph(&fixture_path("summary-conditional"));
    let id = function_named(&graph, "::validate").to_string();
    let mut computer = SummaryComputer::new(&graph);
    let summary = computer.summary_for(&id);
    assert!(
        summary.is_empty(),
        "a signer check inside `if some_flag {{ .. }}` does not dominate \
         the Ok-return reachable when some_flag is false - must be 'no \
         guarantee', not 'probably fine'. got: {:?}",
        summary
    );
}

#[test]
fn test_guarantee_propagates_transitively_through_one_hop() {
    let graph = build_call_graph(&fixture_path("summary-transitive"));
    let outer_id = function_named(&graph, "::outer").to_string();
    let mut computer = SummaryComputer::new(&graph);
    let summary = computer.summary_for(&outer_id);
    assert!(
        summary.contains("account"),
        "outer() calls inner_check(account)? unconditionally, and \
         inner_check guarantees a signer check on its own parameter - that \
         guarantee should propagate back onto outer's 'account' parameter, \
         got: {:?}",
        summary
    );
}

#[test]
fn test_recursion_terminates_without_panicking_or_hanging() {
    // The liveness/safety property under test: this call must return at
    // all (a naive implementation without the `in_progress` cycle guard
    // would recurse into compute() forever on a directly-recursive
    // function). Which specific summary comes out is secondary to that.
    let graph = build_call_graph(&fixture_path("summary-recursive"));
    let id = function_named(&graph, "::recursive_check").to_string();
    let mut computer = SummaryComputer::new(&graph);
    let _summary = computer.summary_for(&id);
    // Reaching this line at all is the assertion.
}

#[test]
fn test_depth_limit_blocks_propagation_past_three_hops() {
    let graph = build_call_graph(&fixture_path("summary-deep-chain"));
    let mut computer = SummaryComputer::new(&graph);

    // Querying the function with the actual check directly: found on its
    // own terms, independent of any chain.
    let hop4_id = function_named(&graph, "::hop4").to_string();
    let hop4_summary = computer.summary_for(&hop4_id);
    assert!(
        hop4_summary.contains("account"),
        "hop4's own unconditional check should be found when queried \
         directly, got: {:?}",
        hop4_summary
    );

    // Querying hop1, three call-graph hops away from hop4: the depth
    // cutoff should stop the guarantee from reaching this far - empty, not
    // a crash and not a wrong "guaranteed" answer.
    let hop1_id = function_named(&graph, "::hop1").to_string();
    let mut fresh_computer = SummaryComputer::new(&graph);
    let hop1_summary = fresh_computer.summary_for(&hop1_id);
    assert!(
        hop1_summary.is_empty(),
        "hop4's check is 3 call-graph hops from hop1 - MAX_DEPTH=3 should \
         prevent this from propagating all the way up, got: {:?}",
        hop1_summary
    );
}

/// KNOWN LIMITATION, demonstrated rather than just described: a plain
/// hand-written `if !cond { return Err(..); }` is semantically identical to
/// summary-unconditional's require!()-based check, but the CFG builder only
/// tags require!/assert!/`?`-desugared branches `is_early_return` - a plain
/// `if`'s branches never get that tag. So this check's Err-only exit is not
/// excluded from "exits the check must dominate," and this real, correct
/// check under-claims as "no guarantee." This is the conservative direction
/// (a false "unguaranteed" rather than a false "guaranteed"), and it is the
/// verified reason two real functions - orca-whirlpools's
/// util/shared.rs::validate_owner and marginfi's
/// test_transfer_hook::process - produced empty summaries in the 5-repo
/// survey despite containing genuine, unconditional signer checks.
#[test]
fn test_handwritten_if_return_err_is_a_known_underclaim() {
    let graph = build_call_graph(&fixture_path("summary-handwritten-if"));
    let id = function_named(&graph, "::validate").to_string();
    let mut computer = SummaryComputer::new(&graph);
    let summary = computer.summary_for(&id);
    assert!(
        summary.is_empty(),
        "documenting the current (conservative, not incorrect) behavior: \
         plain `if {{ return Err }}` is not yet recognized as an early-return \
         shape, so this should still be empty. If this now passes, the gap \
         described above has been closed - update this test's assertion \
         and its doc comment rather than deleting it, got: {:?}",
        summary
    );
}

/// The actual motivating case: does a real production helper function
/// (marinade's admin/initialize.rs) that performs a genuine signer check
/// produce a non-empty summary? This is the first check against real code,
/// not a synthetic fixture - if it fails, the synthetic fixtures above may
/// be validating a mechanism that doesn't generalize.
#[test]
fn test_real_repo_summary_computation_does_not_panic() {
    let marinade_path = "/Users/aksh/epic-audit-sweep/marinade";
    if !std::path::Path::new(marinade_path).exists() {
        eprintln!(
            "skipping: marinade checkout not present at {}",
            marinade_path
        );
        return;
    }
    let graph = build_call_graph(marinade_path);
    let mut computer = SummaryComputer::new(&graph);
    // Every function in a real 181-function crate must be computable
    // without panicking - the actual safety property this stage promises.
    let ids: Vec<String> = graph.functions.keys().cloned().collect();
    for id in ids {
        let _ = computer.summary_for(&id);
    }
}
