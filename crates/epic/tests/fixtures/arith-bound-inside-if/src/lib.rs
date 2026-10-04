use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

const FLAT_FEE: u64 = 10;
const MAX_AMOUNT: u64 = 1_000_000;

/// EPIC-SEC-ARITH finding fixture — identical to arith-bound-dominates
/// except the same `require!` is nested inside an unrelated `if`, so on
/// the `strict == false` path the addition runs with no bound having
/// dominated it. The bound exists in the function but doesn't dominate the
/// arithmetic — the EPIC-SEC-002-style "Bypassed" case, expected to carry
/// a witness.
///
/// Expected: exactly one EPIC-SEC-ARITH finding, with a witness.
#[program]
pub mod arith_bound_inside_if {
    use super::*;

    pub fn charge(ctx: Context<Charge>, amount: u64, strict: bool) -> Result<()> {
        if strict {
            require!(amount <= MAX_AMOUNT, ErrorCode::TooLarge);
        }
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
