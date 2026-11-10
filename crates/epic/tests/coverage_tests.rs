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
fn test_context_self_delegation_is_reported_unresolved_not_hidden() {
    let report = collect_coverage(&fixture_path("coverage-context-self"));
    assert_eq!(
        report.total_handlers, 2,
        "both the #[program] wrapper and the impl-block delegate are real functions"
    );
    // The wrapper (`Context<Withdraw>`) resolves; the delegate
    // (`Context<Self>`) does not.
    assert_eq!(report.resolved_to_struct, 1);
    assert_eq!(report.fully_analyzed, 1);

    let unresolved: Vec<_> = report
        .handlers
        .iter()
        .filter(|h| matches!(h.status, CoverageStatus::Unresolved { .. }))
        .collect();
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0].name, "withdraw");
    let CoverageStatus::Unresolved { reason } = &unresolved[0].status else {
        unreachable!()
    };
    assert!(
        reason.contains("Context<Self>"),
        "reason should name the actual gap, got: {reason}"
    );
}
