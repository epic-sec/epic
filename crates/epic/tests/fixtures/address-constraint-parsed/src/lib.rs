use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

/// End-to-end smoke test for `address = <expr>` parsing (previously
/// dropped entirely -- no GuardFact at all, KNOWN_LIMITATIONS.md's
/// documented gap). `initializer` is pinned to a hardcoded constant via
/// `address = INITIALIZER @ ...` -- the real squads-v4 shape -- and is
/// also independently a `Signer<'info>`, so no rule should flag it either
/// way; this just confirms the parser handles the full statement (including
/// the `@ CustomError` suffix) without crashing or misclassifying anything.
///
/// Expected: no findings.
#[program]
pub mod address_constraint_parsed {
    use super::*;

    pub fn init(ctx: Context<Init>) -> Result<()> {
        ctx.accounts.config.authority = ctx.accounts.initializer.key();
        Ok(())
    }
}

const INITIALIZER: Pubkey = anchor_lang::solana_program::pubkey!(
    "HM5y4mz3Bt9JY9mr1hkyhnvqxSH4H2u2451j7Hc2dtvK"
);

#[derive(Accounts)]
pub struct Init<'info> {
    #[account(init, payer = initializer, space = 8 + 32)]
    pub config: Account<'info, Config>,

    #[account(mut, address = INITIALIZER @ ErrorCode::Unauthorized)]
    pub initializer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[account]
pub struct Config {
    pub authority: Pubkey,
}

#[error_code]
pub enum ErrorCode {
    Unauthorized,
}
