use anchor_lang::prelude::*;

/// The check lives in a helper function, not inline in the instruction
/// handler — the whole point of stages 1-3.
fn validate(account: &AccountInfo) -> Result<()> {
    require!(account.is_signer, ErrorCode::Unauthorized);
    Ok(())
}

/// Calls validate() unconditionally before the privileged write.
/// Expected: CLEAN — the call's guarantee should dominate the write.
#[program]
pub mod interprocedural_clean {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        validate(&ctx.accounts.authority)?;
        ctx.accounts.vault.balance -= amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    /// CHECK: checked manually via validate()
    #[account(mut)]
    pub authority: AccountInfo<'info>,
    #[account(mut)]
    pub vault: Account<'info, VaultAccount>,
}

#[account]
pub struct VaultAccount {
    pub balance: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized")]
    Unauthorized,
}
