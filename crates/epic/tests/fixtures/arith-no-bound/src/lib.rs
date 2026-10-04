use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

/// EPIC-SEC-ARITH finding fixture — `amount` has no bound anywhere in the
/// function at all (no `require!`/`assert!`/checked_* call mentions it).
/// The EPIC-SEC-002-style "NotFound" case: a finding, but with
/// `witness.check: None` rather than a bypassing path, since there's no
/// check to show a path around.
///
/// Expected: exactly one EPIC-SEC-ARITH finding, witness present with
/// `check: None`.
#[program]
pub mod arith_no_bound {
    use super::*;

    pub fn charge(ctx: Context<Charge>, amount: u64) -> Result<()> {
        let new_total = amount + 10;
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
