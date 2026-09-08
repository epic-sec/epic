//! Regression test for the dominance-bypass / dominance-safe fixture pair.
//!
//! These fixtures are EPIC's central demo of dominance-based analysis: an
//! account signer check written with `require!(...)` either does or does not
//! dominate a privileged write, depending only on whether it sits inside a
//! conditional. Until now this was only ever exercised by manually invoking
//! the CLI against the two fixtures — there was no automated check that
//! bypass actually fires and safe actually stays clean, so a regression in
//! either the CFG builder's `require!` desugaring or EPIC-SEC-002 itself
//! could silently break the project's central claim.

fn fixture_path(name: &str) -> String {
    format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name)
}

#[test]
fn test_dominance_bypass_fires_exactly_one_sec002_finding() {
    let diagnostics = epic::run_audit(&fixture_path("dominance-bypass"))
        .expect("run_audit should succeed on a syntactically valid fixture");

    let sec002_findings: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.rule_id == "EPIC-SEC-002")
        .collect();

    assert_eq!(
        sec002_findings.len(),
        1,
        "dominance-bypass's require! is inside an `if`, so the write is not \
         dominated by the signer check — expected exactly one EPIC-SEC-002 \
         finding, got: {:?}",
        sec002_findings
    );
}

#[test]
fn test_dominance_safe_produces_zero_findings() {
    let diagnostics = epic::run_audit(&fixture_path("dominance-safe"))
        .expect("run_audit should succeed on a syntactically valid fixture");

    assert!(
        diagnostics.is_empty(),
        "dominance-safe's require! is unconditional and dominates the write \
         on every path — expected zero findings, got: {:?}",
        diagnostics
    );
}
