use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

/// Fixture (a) vulnerable: set_admin with no auth at all.
/// Expected: EPIC-SOROBAN-001 fires (confirmed).
#[contract]
pub struct AdminContract;

#[contractimpl]
impl AdminContract {
    pub fn set_admin(env: Env, new_admin: Address) {
        env.storage()
            .instance()
            .set(&Symbol::new(&env, "admin"), &new_admin);
    }
}
