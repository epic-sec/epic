use anchor_lang::prelude::*;

/// Same helper as interprocedural-clean — the check itself is genuinely
/// unconditional inside validate().
fn validate(account: &AccountInfo) -> Result<()> {
    require!(account.is_signer, ErrorCode::Unauthorized);
    Ok(())
}

/// Calls validate() only inside an `if`, so the call site does not
/// dominate the write on the `some_condition == false` path.
/// Expected: FLAGS EPIC-SEC-002 with a witness path through the false
/// branch of `some_condition`.
#[program]
pub mod interprocedural_bypass {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64, some_condition: bool) -> Result<()> {
        if some_condition {
            validate(&ctx.accounts.authority)?;
        }
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
