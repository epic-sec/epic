use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

/// EPIC-SEC-ARITH finding fixture — regression test for the real false
/// "Bypassed" this rule produced on mango-v4's `token_withdraw.rs` before
/// bound-matching required an exact field path: a comparison on `.owner`
/// must never be credited as a bound on `.balance`/`.fee`, even though
/// both are reached through the same `vault` account.
///
/// Expected: exactly two EPIC-SEC-ARITH findings (`vault.balance` and
/// `vault.fee`, from the two operands of the subtraction), both
/// `NotFound` — the owner check doesn't protect either.
#[program]
pub mod arith_cross_field_no_bound {
    use super::*;

    pub fn charge(ctx: Context<Charge>) -> Result<()> {
        require!(
            ctx.accounts.vault.owner == ctx.accounts.authority.key(),
            ErrorCode::WrongOwner
        );
        ctx.accounts.vault.balance = ctx.accounts.vault.balance - ctx.accounts.vault.fee;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Charge<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[account]
pub struct Vault {
    pub owner: Pubkey,
    pub balance: u64,
    pub fee: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Wrong owner")]
    WrongOwner,
}
