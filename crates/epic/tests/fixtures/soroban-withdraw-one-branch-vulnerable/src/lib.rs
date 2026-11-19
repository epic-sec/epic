use soroban_sdk::{contract, contractimpl, Address, Env};

/// Fixture (b) vulnerable: require_auth only runs when `is_admin` is true;
/// the withdraw write happens on every path, including the one that
/// skips auth entirely.
/// Expected: EPIC-SOROBAN-001 fires (confirmed).
#[contract]
pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn withdraw(env: Env, user: Address, amount: i128, is_admin: bool) {
        if is_admin {
            user.require_auth();
        }
        let balance: i128 = env.storage().persistent().get(&user).unwrap_or(0);
        env.storage().persistent().set(&user, &(balance - amount));
    }
}
