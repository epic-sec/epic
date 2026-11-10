use anchor_lang::prelude::*;
use anchor_lang::solana_program;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

/// EPIC-SEC-004/005 regression fixture: the instruction function's own name
/// ("multisig_create") does not match its Accounts struct's name
/// ("MultisigCreateV2") -- the real squads-v4 shape. `Context<MultisigCreateV2>`
/// already names the struct explicitly; nothing here needs Context<Self> at
/// all to reproduce the bug both rules used to have (title-casing the
/// *function* name -- "multisig_create" -> "MultisigCreate" -- to guess the
/// struct, instead of reading the type annotation that was right there).
///
/// `token_program` is statically typed `Program<'info, Token>` -- a real
/// rule, given the right struct_def, must recognize this as validated.
/// With the old title-casing bug, the wrong (or no) struct_def was found,
/// so the field's real type was invisible and this fired as a false
/// positive. Expected: EPIC-SEC-005 does NOT fire.
#[program]
pub mod sec005_name_mismatch {
    use super::*;

    pub fn multisig_create(ctx: Context<MultisigCreateV2>, amount: u64) -> ProgramResult {
        solana_program::program::invoke(
            &spl_token::instruction::transfer(
                ctx.accounts.token_program.key,
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
    }
}

#[derive(Accounts)]
pub struct MultisigCreateV2<'info> {
    source: AccountInfo<'info>,
    destination: AccountInfo<'info>,
    authority: AccountInfo<'info>,
    token_program: Program<'info, Token>,
}
