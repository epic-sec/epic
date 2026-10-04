//! Regression tests for EPIC-SEC-ARITH, run end-to-end against fixtures
//! exercising the two things that sink a naive "flag every +/-/*" rule:
//! (1) dominance — the same bound protects the arithmetic unconditionally
//! in one fixture and only conditionally in another; (2) noise — loop
//! counters, index math, and `.len()` must never become candidates.

fn fixture_path(name: &str) -> String {
    format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name)
}

#[test]
fn test_bound_dominates_produces_no_finding() {
    let diagnostics = epic::run_audit(&fixture_path("arith-bound-dominates"))
        .expect("run_audit should succeed on a syntactically valid fixture");

    let findings: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.rule_id == "EPIC-SEC-ARITH")
        .collect();

    assert!(
        findings.is_empty(),
        "an unconditional require!(amount <= MAX_AMOUNT) should fully dominate the addition, got: {:?}",
        findings
    );
}

#[test]
fn test_bound_inside_if_fires_with_bypassed_witness() {
    let diagnostics = epic::run_audit(&fixture_path("arith-bound-inside-if"))
        .expect("run_audit should succeed on a syntactically valid fixture");

    let findings: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.rule_id == "EPIC-SEC-ARITH")
        .collect();

    assert_eq!(
        findings.len(),
        1,
        "the same require! nested in `if strict` doesn't dominate the addition on the false path — expected exactly one finding, got: {:?}",
        findings
    );
    assert!(
        findings[0].message.contains("amount"),
        "message should name the unbounded operand, got: {}",
        findings[0].message
    );
    let witness = findings[0]
        .witness
        .as_ref()
        .expect("a bound exists (inside the if), so this must be the Bypassed case with a witness");
    let check = witness
        .check
        .as_ref()
        .expect("the require! was found, so this is not a no-check-at-all case");
    assert!(
        check.text.contains("amount") && check.text.contains("MAX_AMOUNT"),
        "witness check text should read back the require! condition, got: {}",
        check.text
    );
    assert!(
        !witness.path.is_empty(),
        "a Bypassed finding must carry a concrete bypassing path"
    );
}

#[test]
fn test_no_bound_anywhere_fires_with_notfound_witness() {
    let diagnostics = epic::run_audit(&fixture_path("arith-no-bound"))
        .expect("run_audit should succeed on a syntactically valid fixture");

    let findings: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.rule_id == "EPIC-SEC-ARITH")
        .collect();

    assert_eq!(
        findings.len(),
        1,
        "amount has no bound anywhere — expected exactly one finding, got: {:?}",
        findings
    );
    let witness = findings[0]
        .witness
        .as_ref()
        .expect("even the no-bound case carries a witness, distinguishing it from Dominates");
    assert!(
        witness.check.is_none(),
        "no check exists anywhere, so witness.check must be None (the NotFound case, distinct from Bypassed)"
    );
    assert!(
        witness.path.is_empty(),
        "there's nothing to show a bypassing path around when no check exists at all"
    );
}

#[test]
fn test_cross_field_comparison_does_not_count_as_a_bound() {
    let diagnostics = epic::run_audit(&fixture_path("arith-cross-field-no-bound"))
        .expect("run_audit should succeed on a syntactically valid fixture");

    let findings: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.rule_id == "EPIC-SEC-ARITH")
        .collect();

    assert_eq!(
        findings.len(),
        2,
        "a comparison on vault.owner must not suppress findings on the unrelated vault.balance/vault.fee operands — expected exactly two findings, got: {:?}",
        findings
    );
    assert!(
        findings
            .iter()
            .all(|f| f.witness.as_ref().is_some_and(|w| w.check.is_none())),
        "neither operand has a real bound anywhere — both must be NotFound (witness.check: None), got: {:?}",
        findings
    );
}

#[test]
fn test_same_field_comparison_still_dominates() {
    let diagnostics = epic::run_audit(&fixture_path("arith-same-field-bound-dominates"))
        .expect("run_audit should succeed on a syntactically valid fixture");

    let findings: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.rule_id == "EPIC-SEC-ARITH")
        .collect();

    assert!(
        findings.is_empty(),
        "require!(vault.balance >= MIN_BALANCE) bounds the exact same field the subtraction operates on — exact-path matching must not lose this, got: {:?}",
        findings
    );
}

#[test]
fn test_loop_counter_and_index_and_len_produce_no_findings() {
    let diagnostics = epic::run_audit(&fixture_path("arith-loop-and-index-clean"))
        .expect("run_audit should succeed on a syntactically valid fixture");

    let findings: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.rule_id == "EPIC-SEC-ARITH")
        .collect();

    assert!(
        findings.is_empty(),
        "a loop counter increment, an index computation, and a .len() result are not account/param provenance — none should ever be a candidate, got: {:?}",
        findings
    );
}
