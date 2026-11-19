use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

pub enum Action {
    Safe,
    Unsafe,
}

#[derive(Clone)]
pub enum Error {
    NotAllowed,
}

/// Fixture (f): the only arm that reaches the write also calls
/// require_auth; the other arm aborts via panic_with_error! before
/// anything else runs. `CFGBuilder` (the shared Anchor builder) treats
/// `match` as an opaque boundary and wouldn't see any of this at all --
/// this is exactly what the Soroban-only CFG builder's match-arm descent
/// is for.
/// Expected: no finding.
#[contract]
pub struct Dispatcher;

#[contractimpl]
impl Dispatcher {
    pub fn dispatch(env: Env, admin: Address, action: Action) {
        match action {
            Action::Safe => {
                admin.require_auth();
                env.storage()
                    .instance()
                    .set(&Symbol::new(&env, "state"), &1i128);
            }
            Action::Unsafe => {
                panic_with_error!(&env, Error::NotAllowed);
            }
        }
    }
}
