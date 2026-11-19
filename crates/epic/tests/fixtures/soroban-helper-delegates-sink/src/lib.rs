use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

/// Regression fixture for a gap found running against real CoinFabrik
/// scout-soroban fixtures (set-contract-storage-4,
/// unprotected-mapping-operation-2): the entrypoint delegates its *entire*
/// body -- including the actual storage write, not just the auth check --
/// to a one-hop helper reached through a module-qualified path
/// (`utils::increment(..)`, not a bare name). The helper itself has no
/// auth anywhere. Also exercises the `#[cfg(test)] mod tests { .. }`
/// exclusion: a same-named test function must not make `increment`
/// ambiguous.
/// Expected: EPIC-SOROBAN-001 fires (confirmed).
#[contract]
pub struct Counter;

#[contractimpl]
impl Counter {
    pub fn unsafe_increment(env: Env, user: Address) -> u32 {
        utils::increment(env, user)
    }
}

mod utils {
    use soroban_sdk::{Address, Env, Symbol};

    pub fn increment(env: Env, user: Address) -> u32 {
        let storage = env.storage().persistent();
        let mut count: u32 = storage.get(&Symbol::new(&env, "count")).unwrap_or_default();
        count += 1;
        storage.set(&Symbol::new(&env, "count"), &count);
        let _ = user;
        count
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn increment() {
        assert_eq!(1 + 1, 2);
    }
}
