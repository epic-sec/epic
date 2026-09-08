use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

/// EPIC-SEC-002 no-finding fixture — unconditional signer check dominates the write.
///
/// Identical to dominance-bypass except for one thing: the `require!` here is
/// unconditional and precedes the write on every execution path, so the
/// write is fully dominated.
///
/// Expected: no findings.
#[program]
pub mod dominance_safe {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64, some_condition: bool) -> Result<()> {
        require!(ctx.accounts.authority.is_signer, ErrorCode::Unauthorized);
        ctx.accounts.vault.balance -= amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    /// CHECK: checked manually in the handler
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
