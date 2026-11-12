use anchor_lang::prelude::*;
use anchor_lang::solana_program;
use anchor_spl::token::{self, Token};

declare_id!("11111111111111111111111111111111");

/// EPIC-SEC-003 regression fixture: `token_program` is referenced across
/// two CPI-shaped calls in the same handler, the real orca-whirlpools
/// shape (collect_fees.rs et al.) that surfaced a false positive once
/// `address = token::ID` started producing a GuardFact for the first time.
/// `token_program`'s own account data is the SPL Token program's
/// executable bytecode -- never mutated by either CPI -- so this must
/// never be flagged for post-CPI staleness regardless of what other
/// guard facts it happens to have.
///
/// Expected: no EPIC-SEC-003 findings.
#[program]
pub mod sec003_program_account {
    use super::*;

    pub fn collect(ctx: Context<Collect>, amount_a: u64, amount_b: u64) -> Result<()> {
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.vault_a.to_account_info(),
                    to: ctx.accounts.owner_a.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                },
            ),
            amount_a,
        )?;

        solana_program::program::invoke(
            &spl_token::instruction::transfer(
                ctx.accounts.token_program.key,
                ctx.accounts.vault_b.key,
                ctx.accounts.owner_b.key,
                ctx.accounts.authority.key,
                &[],
                amount_b,
            )?,
            &[ctx.accounts.vault_b.to_account_info()],
        )
    }
}

#[derive(Accounts)]
pub struct Collect<'info> {
    #[account(mut)]
    pub vault_a: Account<'info, TokenAccount>,
    #[account(mut)]
    pub owner_a: Account<'info, TokenAccount>,
    #[account(mut)]
    pub vault_b: AccountInfo<'info>,
    #[account(mut)]
    pub owner_b: AccountInfo<'info>,
    pub authority: Signer<'info>,

    #[account(address = token::ID)]
    pub token_program: Program<'info, Token>,
}

#[account]
pub struct TokenAccount {
    pub amount: u64,
}
