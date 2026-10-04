use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

/// EPIC-SEC-006 no-finding fixture — identical to the bypass fixture
/// except for sealevel-attacks' own `recommended` fix: a `constraint`
/// proving `user_a` and `user_b` can never be the same pubkey.
///
/// Expected: no findings.
#[program]
pub mod duplicate_mutable_accounts_safe {
    use super::*;

    pub fn update(ctx: Context<Update>, a: u64, b: u64) -> Result<()> {
        ctx.accounts.user_a.data = a;
        ctx.accounts.user_b.data = b;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Update<'info> {
    #[account(mut, constraint = user_a.key() != user_b.key())]
    pub user_a: Account<'info, User>,
    #[account(mut)]
    pub user_b: Account<'info, User>,
}

#[account]
pub struct User {
    pub data: u64,
}
