//! Regression tests for `coverage::collect_coverage`.
//!
//! The whole point of coverage reporting is that a handler EPIC silently
//! skipped must show up as skipped, not disappear. These pin that down for
//! the two shapes already known to matter: a clean, fully-analyzed handler,
//! and the `Context<Self>` delegation idiom that resolves to nothing.

use epic::coverage::{collect_coverage, CoverageStatus};

fn fixture_path(name: &str) -> String {
    format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name)
}

#[test]
fn test_fully_analyzed_fixture_reports_full_coverage() {
    let report = collect_coverage(&fixture_path("dominance-safe"));
    assert_eq!(report.total_handlers, 1);
    assert_eq!(report.resolved_to_struct, 1);
    assert_eq!(report.fully_analyzed, 1);
    assert!(report.files_failed_to_parse.is_empty());
    assert!(matches!(
        report.handlers[0].status,
        CoverageStatus::FullyAnalyzed
    ));
}

#[test]
fn test_context_self_delegation_now_resolves_via_impl_type() {
    // Stage 2: RawFunctionVisitor now tracks the enclosing impl type, and
    // resolve_accounts_struct substitutes it for "Self" -- this used to be
    // the squads-v4 blind spot (34 handlers Unresolved); both functions
    // below now resolve to the same struct.
    let report = collect_coverage(&fixture_path("coverage-context-self"));
    assert_eq!(
        report.total_handlers, 2,
        "both the #[program] wrapper and the impl-block delegate are real functions"
    );
    assert_eq!(report.resolved_to_struct, 2);
    assert_eq!(report.fully_analyzed, 2);
    assert!(report
        .handlers
        .iter()
        .all(|h| matches!(h.status, CoverageStatus::FullyAnalyzed)));
}

#[test]
fn test_delegate_writes_counted_but_not_visible_to_rules() {
    // The marinade shape: `ctx.accounts.process(..)` delegating to a
    // `&mut self` method (no `Context<T>` param, so it's never its own
    // RawFunction — only `resolve_typed` + `write_summary.rs` see it).
    let report = collect_coverage(&fixture_path("coverage-mutation-visibility"));
    assert_eq!(
        report.total_handlers, 1,
        "process(&mut self, ..) has no Context<T> param, so it's not a separate handler"
    );
    assert_eq!(report.fully_analyzed, 1);

    let mutation = report.handlers[0]
        .mutation
        .as_ref()
        .expect("resolved handler");
    assert_eq!(
        mutation.visible_writes, 0,
        "change_authority's own body makes no direct write"
    );
    assert_eq!(
        mutation.reachable_via_resolved_delegate, 2,
        "both writes inside process() must be counted via write_summary.rs"
    );
    assert_eq!(mutation.unresolved_delegate_calls, 0);
    assert!(
        mutation.mostly_invisible(),
        "2 reachable-but-hidden writes vs. 0 visible ones must flag as mostly invisible"
    );
}
