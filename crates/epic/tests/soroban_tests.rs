use epic::cfg::FactConfidence;
use epic::soroban::run_soroban_audit;

fn fixture_path(name: &str) -> String {
    format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name)
}

fn findings(name: &str) -> Vec<epic::rules::RuleDiagnostic> {
    run_soroban_audit(&fixture_path(name))
}

#[test]
fn test_a_set_admin_no_auth_flags() {
    let f = findings("soroban-set-admin-vulnerable");
    assert_eq!(f.len(), 1, "{f:#?}");
    assert_eq!(f[0].confidence, FactConfidence::Asserted);
}

#[test]
fn test_a_set_admin_fixed_is_clean() {
    assert!(findings("soroban-set-admin-fixed").is_empty());
}

#[test]
fn test_b_withdraw_one_branch_flags() {
    let f = findings("soroban-withdraw-one-branch-vulnerable");
    assert_eq!(f.len(), 1, "{f:#?}");
    assert_eq!(f[0].confidence, FactConfidence::Asserted);
}

#[test]
fn test_b_withdraw_fixed_is_clean() {
    assert!(findings("soroban-withdraw-one-branch-fixed").is_empty());
}

#[test]
fn test_c_escrow_helper_missing_call_flags() {
    let f = findings("soroban-escrow-helper-vulnerable");
    assert_eq!(f.len(), 1, "{f:#?}");
    assert_eq!(f[0].confidence, FactConfidence::Asserted);
}

#[test]
fn test_c_escrow_helper_called_is_clean() {
    assert!(findings("soroban-escrow-helper-fixed").is_empty());
}

#[test]
fn test_d_write_then_auth_is_clean() {
    assert!(findings("soroban-write-then-auth").is_empty());
}

#[test]
fn test_e_auth_both_branches_is_clean() {
    assert!(findings("soroban-auth-both-branches").is_empty());
}

#[test]
fn test_f_match_panic_arm_is_clean() {
    assert!(findings("soroban-match-panic-arm").is_empty());
}

#[test]
fn test_h_err_before_auth_is_clean() {
    // Round 2 task 3: verified empirically that returning Err rolls back
    // earlier storage writes in the same invocation -- `return Err(..)`
    // and a tail `Err(..)` are abort exits, not normal completions.
    assert!(findings("soroban-err-before-auth").is_empty());
}

#[test]
fn test_i_second_hop_auth_is_inconclusive() {
    // Round 2 task 4: the only require_auth is two hops deep
    // (check -> check_inner); v0 follows one hop, so this must land as
    // INCONCLUSIVE, not a guess either way.
    let f = findings("soroban-second-hop-inconclusive");
    assert_eq!(f.len(), 1, "{f:#?}");
    assert_eq!(f[0].confidence, FactConfidence::Inconclusive);
}

#[test]
fn test_helper_delegates_entire_sink_flags() {
    // Found running against real CoinFabrik scout-soroban fixtures: a sink
    // delegated into a one-hop helper reached via a module-qualified path
    // must still be found, and a same-named #[cfg(test)] function must not
    // make the helper's name ambiguous.
    let f = findings("soroban-helper-delegates-sink");
    assert_eq!(f.len(), 1, "{f:#?}");
    assert_eq!(f[0].confidence, FactConfidence::Asserted);
}

#[test]
fn test_g_helper_conditional_auth_flags_or_inconclusive() {
    let f = findings("soroban-helper-conditional-auth");
    assert_eq!(f.len(), 1, "{f:#?}");
    assert!(matches!(
        f[0].confidence,
        FactConfidence::Asserted | FactConfidence::Inconclusive
    ));
}
