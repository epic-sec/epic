fn fixture_path(name: &str) -> String {
    format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name)
}

#[test]
fn test_program_typed_account_not_flagged_for_post_cpi_staleness() {
    // A Program<'info, T> account's own data is the program's executable
    // bytecode, never user state a CPI could mutate -- referencing it
    // across two CPI-shaped calls in the same handler must never be
    // flagged, regardless of what other guard facts (address =, etc.) it
    // happens to carry.
    let diagnostics = epic::run_audit(&fixture_path("sec003-program-account-not-flagged"))
        .expect("run_audit should succeed on a syntactically valid fixture");

    let sec003_findings: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.rule_id == "EPIC-SEC-003")
        .collect();

    assert!(
        sec003_findings.is_empty(),
        "token_program is a Program<'info, Token> account and must never be flagged for post-CPI staleness, got: {:?}",
        sec003_findings
    );
}
