use soroban_sdk::{contract, contractimpl, Address, Env};

/// Fixture (b) fixed: require_auth runs unconditionally before the write.
/// Expected: no finding.
#[contract]
pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn withdraw(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let balance: i128 = env.storage().persistent().get(&user).unwrap_or(0);
        env.storage().persistent().set(&user, &(balance - amount));
    }
}
