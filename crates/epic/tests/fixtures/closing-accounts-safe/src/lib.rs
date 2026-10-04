use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

/// EPIC-SEC-007 no-finding fixture — sealevel-attacks'
/// `9-closing-accounts/recommended`: Anchor's own `close = destination`
/// constraint does the lamport transfer, discriminator zeroing, and
/// re-init guard for you. No manual drain in the handler body at all.
///
/// Expected: no findings.
#[program]
pub mod closing_accounts_safe {
    use super::*;

    pub fn close(_ctx: Context<Close>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Close<'info> {
    #[account(mut, close = destination)]
    pub account: Account<'info, Data>,
    /// CHECK: receives the closed account's lamports
    #[account(mut)]
    pub destination: AccountInfo<'info>,
}

#[account]
pub struct Data {
    pub data: u64,
}
