//! Regression tests for EPIC-SEC-006 (duplicate mutable accounts) and
//! EPIC-SEC-007 (unsafe manual account close), run end-to-end against
//! fixtures adapted from the sealevel-attacks benchmark's
//! `6-duplicate-mutable-accounts` and `9-closing-accounts` classes.

fn fixture_path(name: &str) -> String {
    format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name)
}

#[test]
fn test_duplicate_mutable_accounts_bypass_fires() {
    let diagnostics = epic::run_audit(&fixture_path("duplicate-mutable-accounts-bypass"))
        .expect("run_audit should succeed on a syntactically valid fixture");

    let findings: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.rule_id == "EPIC-SEC-006")
        .collect();

    assert_eq!(
        findings.len(),
        1,
        "user_a/user_b share a type with no distinguishing constraint — expected exactly one EPIC-SEC-006 finding, got: {:?}",
        findings
    );
    assert!(
        findings[0].message.contains("user_a") && findings[0].message.contains("user_b"),
        "message should name both ambiguous fields, got: {}",
        findings[0].message
    );
}

#[test]
fn test_duplicate_mutable_accounts_safe_produces_no_sec006_finding() {
    let diagnostics = epic::run_audit(&fixture_path("duplicate-mutable-accounts-safe"))
        .expect("run_audit should succeed on a syntactically valid fixture");

    let findings: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.rule_id == "EPIC-SEC-006")
        .collect();

    assert!(
        findings.is_empty(),
        "constraint = user_a.key() != user_b.key() should fully clear this pair, got: {:?}",
        findings
    );
}

#[test]
fn test_duplicate_mutable_accounts_body_guard_produces_no_sec006_finding() {
    let diagnostics = epic::run_audit(&fixture_path("duplicate-mutable-accounts-body-guard"))
        .expect("run_audit should succeed on a syntactically valid fixture");

    let findings: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.rule_id == "EPIC-SEC-006")
        .collect();

    assert!(
        findings.is_empty(),
        "an early-return `if a.key() == b.key()` guard in the handler body should clear this pair \
         (regression test for the real false positive this rule produced on orca-whirlpools' \
         two_hop_swap.rs), got: {:?}",
        findings
    );
}

#[test]
fn test_closing_accounts_bypass_fires() {
    let diagnostics = epic::run_audit(&fixture_path("closing-accounts-bypass"))
        .expect("run_audit should succeed on a syntactically valid fixture");

    let findings: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.rule_id == "EPIC-SEC-007")
        .collect();

    assert_eq!(
        findings.len(),
        1,
        "manual lamport-drain with no close= and no discriminator write — expected exactly one EPIC-SEC-007 finding, got: {:?}",
        findings
    );
    assert!(
        findings[0].message.contains("account"),
        "message should name the drained account, got: {}",
        findings[0].message
    );
}

#[test]
fn test_closing_accounts_safe_produces_no_sec007_finding() {
    let diagnostics = epic::run_audit(&fixture_path("closing-accounts-safe"))
        .expect("run_audit should succeed on a syntactically valid fixture");

    let findings: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.rule_id == "EPIC-SEC-007")
        .collect();

    assert!(
        findings.is_empty(),
        "close = destination should fully clear this account, got: {:?}",
        findings
    );
}

#[test]
fn test_closing_accounts_manual_safe_produces_no_sec007_finding() {
    let diagnostics = epic::run_audit(&fixture_path("closing-accounts-manual-safe"))
        .expect("run_audit should succeed on a syntactically valid fixture");

    let findings: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.rule_id == "EPIC-SEC-007")
        .collect();

    assert!(
        findings.is_empty(),
        "manual drain + CLOSED_ACCOUNT_DISCRIMINATOR write correctly re-implements the safe close idiom, got: {:?}",
        findings
    );
}
