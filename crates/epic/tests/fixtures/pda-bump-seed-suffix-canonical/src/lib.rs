use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

/// EPIC-SEC-PDA no-finding fixture — canonical bump stored under a
/// `_bump_seed` suffix rather than a bare `bump` field. This is marinade's
/// naming convention (`state.reserve_bump_seed`), distinct from the
/// `_bump`-suffix convention seen in marginfi/mango-v4 (`liquidity_vault_bump`)
/// covered by the pda-bump-canonical fixture. Must NOT be flagged as
/// caller-supplied.
///
/// Deliberately a single-level field access (`state.reserve_bump_seed`, where
/// `state` is a plain Accounts-struct field) — this isolates the field-name
/// widening fix from a separate, still-open limitation where the bump's base
/// object is itself a nested field access (e.g.
/// `state.stake_system.stake_deposit_bump_seed`), which this fixture does not
/// cover.
///
/// Expected: no findings.
#[program]
pub mod pda_bump_seed_suffix_canonical {
    use super::*;

    pub fn do_thing(_ctx: Context<DoThing>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct DoThing<'info> {
    #[account(
        seeds = [b"reserve"],
        bump = state.reserve_bump_seed,
    )]
    pub reserve: SystemAccount<'info>,
    pub state: Account<'info, StateAccount>,
}

#[account]
pub struct StateAccount {
    pub reserve_bump_seed: u8,
}
