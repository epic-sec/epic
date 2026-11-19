use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

/// Fixture (g): the one-hop helper only calls require_auth inside an `if`
/// -- not on every one of its own normal-return paths -- so it's confirmed
/// not a guaranteed guard.
/// Expected: EPIC-SOROBAN-001 fires, or INCONCLUSIVE (either is accepted
/// per review round 1, point 4). This implementation resolves it as a
/// confirmed finding: the helper has no further unresolved calls of its
/// own, so its conditional coverage is confidently "not a guard," not
/// merely unknown.
fn check_admin(env: &Env, admin: &Address, strict: bool) {
    if strict {
        admin.require_auth();
    }
    let _ = env;
}

#[contract]
pub struct Risky;

#[contractimpl]
impl Risky {
    pub fn risky(env: Env, admin: Address, strict: bool) {
        check_admin(&env, &admin, strict);
        env.storage()
            .instance()
            .set(&Symbol::new(&env, "config"), &1i128);
    }
}
