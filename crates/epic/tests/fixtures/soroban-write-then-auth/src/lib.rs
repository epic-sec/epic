use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

/// Fixture (d): storage.set() happens, THEN admin.require_auth() -- Soroban
/// reverts the whole invocation on auth failure, so the earlier write is
/// retroactively safe once the function returns normally.
/// Expected: no finding.
#[contract]
pub struct Config;

#[contractimpl]
impl Config {
    pub fn set_then_auth(env: Env, admin: Address, value: i128) {
        env.storage()
            .instance()
            .set(&Symbol::new(&env, "value"), &value);
        admin.require_auth();
    }
}
