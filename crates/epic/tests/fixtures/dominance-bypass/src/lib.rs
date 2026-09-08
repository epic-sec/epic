use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

/// EPIC-SEC-002 demo fixture — dominance bypass via conditional signer check.
///
/// Identical to dominance-safe except for one thing: the `require!` here
/// lives inside `if some_condition { ... }`, so the privileged write
/// `ctx.accounts.vault.balance -= amount` is NOT dominated by the signer
/// check. An attacker can call with `some_condition = false` and bypass the
/// check entirely.
///
/// Expected: EPIC-SEC-002 fires for `authority`.
#[program]
pub mod dominance_bypass {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64, some_condition: bool) -> Result<()> {
        if some_condition {
            require!(ctx.accounts.authority.is_signer, ErrorCode::Unauthorized);
        }
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
