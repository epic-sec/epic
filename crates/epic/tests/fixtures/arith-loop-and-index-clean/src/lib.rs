use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

/// EPIC-SEC-ARITH no-finding fixture — a loop counter increment
/// (`i = i + 1`), an index computation (`let idx = i + 1`), and a `.len()`
/// result used in a comparison. None of `i`, `idx`, `total`, or `len` trace
/// back to an account field or instruction parameter — they're all plain
/// locals seeded from a literal or from `.len()` — so none should ever
/// become a candidate in the first place. These are exactly the false
/// positives a naive "flag every +/-/*" rule would produce.
///
/// Expected: no findings.
#[program]
pub mod arith_loop_and_index_clean {
    use super::*;

    pub fn sum_items(ctx: Context<SumItems>) -> Result<()> {
        let len = ctx.accounts.vault.items.len() as u64;
        let mut total: u64 = 0;
        let mut i: u64 = 0;
        while i < len {
            let idx = i + 1;
            total = total + idx;
            i = i + 1;
        }
        ctx.accounts.vault.count = total;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SumItems<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
}

#[account]
pub struct Vault {
    pub items: Vec<u64>,
    pub count: u64,
}
