use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

/// Fixture (a) fixed: admin.require_auth() unconditionally before the write.
/// Expected: no finding.
#[contract]
pub struct AdminContract;

#[contractimpl]
impl AdminContract {
    pub fn set_admin(env: Env, admin: Address, new_admin: Address) {
        admin.require_auth();
        env.storage()
            .instance()
            .set(&Symbol::new(&env, "admin"), &new_admin);
    }
}
