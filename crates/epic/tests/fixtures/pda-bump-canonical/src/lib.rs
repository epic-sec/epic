use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

/// EPIC-SEC-PDA no-finding fixture — canonical stored bump.
///
/// `bump = multisig.bump` loads the canonical bump from the account's own
/// stored field. This is the standard, Anchor-recommended safe pattern and
/// must NOT be flagged as caller-supplied.
///
/// Expected: no findings.
#[program]
pub mod pda_bump_canonical {
    use super::*;

    pub fn do_thing(_ctx: Context<DoThing>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct DoThing<'info> {
    #[account(
        seeds = [b"multisig", multisig.create_key.as_ref()],
        bump = multisig.bump,
    )]
    pub multisig: Account<'info, Multisig>,
}

#[account]
pub struct Multisig {
    pub create_key: Pubkey,
    pub bump: u8,
}
