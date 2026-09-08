use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

/// EPIC-SEC-PDA finding fixture — caller-supplied bump.
///
/// `bump = user_supplied_arg` takes the bump directly from an instruction
/// argument instead of loading (or deriving) the canonical value. A caller
/// can supply an arbitrary bump, potentially landing off-curve or on a
/// different valid PDA than the one intended.
///
/// Expected: EPIC-SEC-PDA fires for `multisig`.
#[program]
pub mod pda_bump_caller_supplied {
    use super::*;

    pub fn do_thing(_ctx: Context<DoThing>, user_supplied_arg: u8) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(user_supplied_arg: u8)]
pub struct DoThing<'info> {
    #[account(
        seeds = [b"multisig", multisig.create_key.as_ref()],
        bump = user_supplied_arg,
    )]
    pub multisig: Account<'info, Multisig>,
}

#[account]
pub struct Multisig {
    pub create_key: Pubkey,
}
