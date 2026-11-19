use soroban_sdk::{contract, contractimpl, Address, Env};

/// Fixture (e): auth happens in both the `if` and the `else` -- no single
/// node dominates the write, but every completing path passes through at
/// least one of the two auth calls, so the set-avoiding bypass check (which
/// avoids the whole set of auth nodes, not just one) must not fire.
/// Expected: no finding.
#[contract]
pub struct Ops;

#[contractimpl]
impl Ops {
    pub fn conditional_auth(
        env: Env,
        admin: Address,
        user: Address,
        is_admin_op: bool,
        amount: i128,
    ) {
        if is_admin_op {
            admin.require_auth();
        } else {
            user.require_auth();
        }
        env.storage().persistent().set(&user, &amount);
    }
}
