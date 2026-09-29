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

    let witness = sec002_findings[0]
        .witness
        .as_ref()
        .expect("a check exists (the require!) so the finding must carry a witness");
    let check = witness
        .check
        .as_ref()
        .expect("the require! was found, so this is not a no-check-at-all case");
    assert_eq!(
        check.line, 20,
        "check should be located at the require! line"
    );
    assert!(
        check.text.contains("require") && check.text.contains("is_signer"),
        "check text should read back the require!(...is_signer...) call, got: {}",
        check.text
    );

    let path_text = witness
        .path
        .iter()
        .map(|s| s.label.as_str())
        .collect::<Vec<_>>()
        .join(" -> ");
    assert!(
        path_text.contains("false"),
        "bypassing path must go through the false branch of `some_condition`, got: {}",
        path_text
    );
    assert!(
        witness
            .path
            .last()
            .is_some_and(|s| s.label.contains("write")),
        "path must end at the write, got: {}",
        path_text
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
