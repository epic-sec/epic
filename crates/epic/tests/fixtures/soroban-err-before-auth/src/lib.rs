use soroban_sdk::{contract, contracterror, contractimpl, Address, Env, Symbol};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    Failed = 1,
}

/// Round 2 task 3, fixture (h): storage.set() happens unconditionally,
/// then one branch returns `Err(..)` *before* require_auth, the other
/// branch calls require_auth and returns Ok. Verified empirically
/// (docs/soroban-core-leaks.md #14) that a contract fn returning Err rolls
/// back any storage writes made earlier in the same invocation -- so the
/// `should_fail` branch's write is moot (never actually persists), and the
/// only path that completes normally passes through require_auth.
/// Expected: no finding.
#[contract]
pub struct ErrBeforeAuth;

#[contractimpl]
impl ErrBeforeAuth {
    pub fn risky(env: Env, admin: Address, value: u32, should_fail: bool) -> Result<u32, Error> {
        env.storage().instance().set(&Symbol::new(&env, "value"), &value);
        if should_fail {
            return Err(Error::Failed);
        }
        admin.require_auth();
        Ok(value)
    }
}
