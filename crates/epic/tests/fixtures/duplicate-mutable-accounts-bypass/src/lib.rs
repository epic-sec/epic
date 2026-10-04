use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

/// EPIC-SEC-006 finding fixture — adapted from sealevel-attacks'
/// `6-duplicate-mutable-accounts/insecure`. `user_a` and `user_b` are both
/// `Account<'info, User>` with no constraint proving they're different
/// pubkeys, so a caller can pass the same account for both and have
/// `user_b.data = b` silently overwrite what `user_a.data = a` just wrote.
///
/// Expected: exactly one EPIC-SEC-006 finding.
#[program]
pub mod duplicate_mutable_accounts_bypass {
    use super::*;

    pub fn update(ctx: Context<Update>, a: u64, b: u64) -> Result<()> {
        ctx.accounts.user_a.data = a;
        ctx.accounts.user_b.data = b;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Update<'info> {
    #[account(mut)]
    pub user_a: Account<'info, User>,
    #[account(mut)]
    pub user_b: Account<'info, User>,
}

#[account]
pub struct User {
    pub data: u64,
}
