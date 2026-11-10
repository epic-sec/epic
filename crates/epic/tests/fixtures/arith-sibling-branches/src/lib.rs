use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

/// Determinism regression fixture (not a rule-behavior fixture).
///
/// `amount` is used in an unguarded subtraction in TWO sibling branches of
/// the same if/else — same resolved path ("amount"), two different CFG
/// nodes, two different source lines. EPIC-SEC-ARITH's "only report once
/// per resolved path" dedup (`epic_sec_arith.rs::check_bound`) means
/// exactly one of these two lines gets reported, never both — but *which*
/// line was, before the determinism fix, a function of `HashMap` iteration
/// order over `cfg.nodes`, which varies per process run. See
/// `determinism_tests.rs`.
#[program]
pub mod arith_sibling_branches {
    use super::*;

    pub fn adjust(ctx: Context<Adjust>, amount: u64, threshold: u64) -> Result<()> {
        if threshold < 10 {
            ctx.accounts.state.value = amount - threshold;
        } else if threshold > 10 {
            ctx.accounts.state.value = amount - threshold;
        }
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Adjust<'info> {
    #[account(mut)]
    pub state: Account<'info, StateAccount>,
}

#[account]
pub struct StateAccount {
    pub value: u64,
}
