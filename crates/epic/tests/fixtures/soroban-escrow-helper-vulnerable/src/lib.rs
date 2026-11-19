use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

/// Fixture (c) vulnerable: release() never calls the auth-checking helper
/// at all -- the developer forgot the call, a realistic near-miss of the
/// fixed version below.
/// Expected: EPIC-SOROBAN-001 fires (confirmed).
fn check_release(env: &Env, beneficiary: &Address) {
    beneficiary.require_auth();
}

#[contract]
pub struct Escrow;

#[contractimpl]
impl Escrow {
    pub fn release(env: Env, beneficiary: Address) {
        let _ = &beneficiary;
        env.storage()
            .instance()
            .remove(&Symbol::new(&env, "locked"));
    }
}
