//! Regression test for stage 3 of interprocedural guard analysis: a
//! `require!`-backed signer check that lives inside a helper function,
//! called from the instruction handler, must still dominate (or fail to
//! dominate) a privileged write exactly as an inline check would.

fn fixture_path(name: &str) -> String {
    format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name)
}

#[test]
fn test_interprocedural_clean_produces_zero_findings() {
    let diagnostics = epic::run_audit(&fixture_path("interprocedural-clean"))
        .expect("run_audit should succeed on a syntactically valid fixture");

    assert!(
        diagnostics.is_empty(),
        "validate()'s signer check is called unconditionally before the \
         write, so its interprocedural guarantee should dominate — expected \
         zero findings, got: {:?}",
        diagnostics
    );
}

#[test]
fn test_interprocedural_bypass_fires_exactly_one_sec002_finding() {
    let diagnostics = epic::run_audit(&fixture_path("interprocedural-bypass"))
        .expect("run_audit should succeed on a syntactically valid fixture");

    let sec002_findings: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.rule_id == "EPIC-SEC-002")
        .collect();

    assert_eq!(
        sec002_findings.len(),
        1,
        "validate() is only called inside an `if`, so its interprocedural \
         guarantee does not dominate the write on the false path — expected \
         exactly one EPIC-SEC-002 finding, got: {:?}",
        sec002_findings
    );

    let witness = sec002_findings[0]
        .witness
        .as_ref()
        .expect("validate()'s check exists, so the finding must carry a witness");
    let check = witness
        .check
        .as_ref()
        .expect("the interprocedural check was found, so this is not a no-check-at-all case");
    assert_eq!(
        check.line, 20,
        "check should be located at the validate() call line"
    );
    assert!(
        check.text.contains("validate") && check.text.contains("authority"),
        "check text should read back the validate(ctx.accounts.authority) call, got: {}",
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
