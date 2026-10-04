use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

const FLAT_FEE: u64 = 10;
const MAX_AMOUNT: u64 = 1_000_000;

/// EPIC-SEC-ARITH no-finding fixture — `amount`'s bound
/// (`require!(amount <= MAX_AMOUNT)`) is unconditional and precedes the
/// addition on every execution path, so it fully dominates. `FLAT_FEE` is a
/// plain constant, never a candidate.
///
/// Expected: no findings.
#[program]
pub mod arith_bound_dominates {
    use super::*;

    pub fn charge(ctx: Context<Charge>, amount: u64) -> Result<()> {
        require!(amount <= MAX_AMOUNT, ErrorCode::TooLarge);
        let new_total = amount + FLAT_FEE;
        ctx.accounts.vault.balance = new_total;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Charge<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
}

#[account]
pub struct Vault {
    pub balance: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Amount too large")]
    TooLarge,
}
