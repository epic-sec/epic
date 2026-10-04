use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

/// EPIC-SEC-007 finding fixture — adapted from sealevel-attacks'
/// `9-closing-accounts/insecure`. `account`'s lamports are manually
/// zeroed out with no `close = ` constraint and no discriminator write,
/// so the account can be revived later in the same transaction by
/// refunding its rent before the runtime purges it.
///
/// Expected: exactly one EPIC-SEC-007 finding, on `account`.
#[program]
pub mod closing_accounts_bypass {
    use super::*;

    pub fn close(ctx: Context<Close>) -> Result<()> {
        let dest_starting_lamports = ctx.accounts.destination.lamports();

        **ctx.accounts.destination.lamports.borrow_mut() = dest_starting_lamports
            .checked_add(ctx.accounts.account.to_account_info().lamports())
            .unwrap();
        **ctx.accounts.account.to_account_info().lamports.borrow_mut() = 0;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Close<'info> {
    #[account(mut)]
    pub account: Account<'info, Data>,
    /// CHECK: receives the closed account's lamports
    #[account(mut)]
    pub destination: AccountInfo<'info>,
}

#[account]
pub struct Data {
    pub data: u64,
}
