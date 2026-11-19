use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

/// Fixture (c) fixed: release() calls a one-hop helper that unconditionally
/// calls require_auth on every one of its own normal-return paths.
/// Expected: no finding.
fn check_release(env: &Env, beneficiary: &Address) {
    beneficiary.require_auth();
}

#[contract]
pub struct Escrow;

#[contractimpl]
impl Escrow {
    pub fn release(env: Env, beneficiary: Address) {
        check_release(&env, &beneficiary);
        env.storage()
            .instance()
            .remove(&Symbol::new(&env, "locked"));
    }
}
