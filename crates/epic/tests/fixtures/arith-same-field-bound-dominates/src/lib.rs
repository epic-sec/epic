use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

const FLAT_FEE: u64 = 10;
const MIN_BALANCE: u64 = 100;

/// EPIC-SEC-ARITH no-finding fixture — the positive control for exact
/// field-path matching: the comparison and the arithmetic operand are the
/// *same* field (`vault.balance`), not merely the same account, so this
/// must still dominate. Confirms the fix narrows matching without losing
/// the ability to match at all.
///
/// Expected: no findings.
#[program]
pub mod arith_same_field_bound_dominates {
    use super::*;

    pub fn charge(ctx: Context<Charge>) -> Result<()> {
        require!(
            ctx.accounts.vault.balance >= MIN_BALANCE,
            ErrorCode::TooLow
        );
        ctx.accounts.vault.balance = ctx.accounts.vault.balance - FLAT_FEE;
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
    #[msg("Balance too low")]
    TooLow,
}
