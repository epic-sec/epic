use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

/// Round 2 task 4, fixture (i): the entrypoint calls a one-hop helper
/// (`check`) that itself has no require_auth of its own -- the *only*
/// require_auth lives in `check_inner`, a second hop `check` calls but v0
/// doesn't follow. `check`'s own auth coverage is incomplete (zero direct
/// auth calls) and it makes a further same-crate call this build won't
/// resolve -- genuinely unknown, not a guess either way.
/// Expected: EPIC-SOROBAN-001 fires with FactConfidence::Inconclusive.
fn check_inner(admin: &Address) {
    admin.require_auth();
}

fn check(admin: &Address) {
    check_inner(admin);
}

#[contract]
pub struct SecondHop;

#[contractimpl]
impl SecondHop {
    pub fn risky(env: Env, admin: Address, value: u32) {
        check(&admin);
        env.storage()
            .instance()
            .set(&Symbol::new(&env, "value"), &value);
    }
}
