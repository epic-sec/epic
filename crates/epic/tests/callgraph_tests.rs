//! Stage 1 of interprocedural guard analysis: verifies the crate-wide call
//! graph actually resolves the three direct-call shapes in scope
//! (`foo(x)`, `self.method(x)`, `receiver.method(x)`), and — the whole
//! motivation for this feature — that it sees real helper-function calls in
//! production code that EPIC's per-instruction pipeline has never analyzed
//! before.

use epic::callgraph::build_call_graph;

fn fixture_path(name: &str) -> String {
    format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name)
}

#[test]
fn test_resolves_free_function_call() {
    let graph = build_call_graph(&fixture_path("callgraph-basic"));

    let withdraw_id = graph
        .functions
        .keys()
        .find(|id| id.ends_with("::withdraw"))
        .expect("withdraw should be a discovered function")
        .clone();

    let callees: Vec<_> = graph
        .calls_from(&withdraw_id)
        .map(|c| c.callee.as_str())
        .collect();

    assert!(
        callees.iter().any(|c| c.ends_with("::check_owner")),
        "withdraw() should resolve its call to the free function check_owner(), got: {:?}",
        callees
    );
}

#[test]
fn test_resolves_method_call_on_self() {
    let graph = build_call_graph(&fixture_path("callgraph-basic"));

    let run_id = graph
        .functions
        .keys()
        .find(|id| id.ends_with("::run"))
        .expect("run should be a discovered function")
        .clone();

    let call = graph
        .calls_from(&run_id)
        .find(|c| c.callee.ends_with("::validate"))
        .expect("run() should resolve its self.validate(...) call");

    // args[0] is the receiver (`self`), args[1] is the explicit `account` arg.
    assert_eq!(call.args.len(), 2, "receiver + one explicit argument");
}

#[test]
fn test_resolves_method_call_on_receiver_expression() {
    let graph = build_call_graph(&fixture_path("callgraph-basic"));

    let withdraw_id = graph
        .functions
        .keys()
        .find(|id| id.ends_with("::withdraw"))
        .expect("withdraw should be a discovered function")
        .clone();

    let callees: Vec<_> = graph
        .calls_from(&withdraw_id)
        .map(|c| c.callee.as_str())
        .collect();

    assert!(
        callees.iter().any(|c| c.ends_with("::run")),
        "withdraw() should resolve its checker.run(...) call, got: {:?}",
        callees
    );
}

#[test]
fn test_discovers_helper_functions_invisible_to_the_instruction_pipeline() {
    // check_owner and validate/run take no Context<T> parameter, so
    // audit::RawFunctionVisitor would never have kept them. The whole point
    // of the call graph is that it does.
    let graph = build_call_graph(&fixture_path("callgraph-basic"));

    for name in ["check_owner", "validate", "run"] {
        assert!(
            graph
                .functions
                .keys()
                .any(|id| id.ends_with(&format!("::{}", name))),
            "helper function '{}' should be in the call graph despite having no Context<T> param",
            name
        );
    }
}

/// The actual motivating case from the require_keys_eq! measurement: marinade's
/// `check_sol_leg` and `check_stake_amount_and_validator` are called from
/// instruction-handler code but live in separate helper functions/files.
/// This is the concrete proof the call graph closes that gap on real code,
/// not just the synthetic fixture above.
#[test]
fn test_finds_real_marinade_helper_calls() {
    let marinade_path = "/Users/aksh/epic-audit-sweep/marinade";
    if !std::path::Path::new(marinade_path).exists() {
        eprintln!(
            "skipping: marinade checkout not present at {}",
            marinade_path
        );
        return;
    }

    let graph = build_call_graph(marinade_path);

    let check_sol_leg = graph
        .functions
        .keys()
        .find(|id| id.ends_with("::check_sol_leg"))
        .expect("check_sol_leg should be discovered as a function in its own right");

    let callers: Vec<_> = graph
        .calls_to(check_sol_leg)
        .map(|c| c.caller.as_str())
        .collect();
    assert!(
        !callers.is_empty(),
        "check_sol_leg should have at least one caller in the call graph"
    );

    let check_stake = graph
        .functions
        .keys()
        .find(|id| id.ends_with("::check_stake_amount_and_validator"));
    assert!(
        check_stake.is_some(),
        "check_stake_amount_and_validator (in checks.rs) should be discovered"
    );
}
