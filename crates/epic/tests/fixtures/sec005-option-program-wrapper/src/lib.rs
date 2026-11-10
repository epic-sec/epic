use anchor_lang::prelude::*;
use anchor_lang::solana_program;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

/// EPIC-SEC-005 regression fixture: `token_program` is statically typed
/// `Option<Program<'info, Token>>` (the real squads-v4 `SpendingLimitUse`
/// shape — a program account that's only required for some code paths).
/// `is_program_symbol`/`is_struct_field_validated` matched `TypeRef::Custom`/
/// `Resolved` directly, which an `Option<T>`-wrapped field never is
/// (`TypeRef::Option(..)`) -- so a wrapped, statically-typed `Program<T>`
/// field used to be invisible to the type check and this fired as a false
/// positive. Expected: EPIC-SEC-005 does NOT fire.
#[program]
pub mod sec005_option_wrapper {
    use super::*;

    pub fn spending_limit_use(ctx: Context<SpendingLimitUse>, amount: u64) -> ProgramResult {
        if let Some(token_program) = &ctx.accounts.token_program {
            solana_program::program::invoke(
                &spl_token::instruction::transfer(
                    token_program.key,
                    ctx.accounts.source.key,
                    ctx.accounts.destination.key,
                    ctx.accounts.authority.key,
                    &[],
                    amount,
                )?,
                &[
                    ctx.accounts.source.clone(),
                    ctx.accounts.destination.clone(),
                    ctx.accounts.authority.clone(),
                ],
            )
        } else {
            Ok(())
        }
    }
}

#[derive(Accounts)]
pub struct SpendingLimitUse<'info> {
    source: AccountInfo<'info>,
    destination: AccountInfo<'info>,
    authority: AccountInfo<'info>,
    token_program: Option<Program<'info, Token>>,
}
