use anchor_lang::__private::CLOSED_ACCOUNT_DISCRIMINATOR;
use anchor_lang::prelude::*;
use std::io::{Cursor, Write};
use std::ops::DerefMut;

declare_id!("11111111111111111111111111111111");

/// EPIC-SEC-007 no-finding fixture — sealevel-attacks'
/// `9-closing-accounts/secure`: no `close = ` constraint, but the handler
/// manually re-implements Anchor's close idiom correctly, including the
/// `CLOSED_ACCOUNT_DISCRIMINATOR` write that actually prevents revival
/// (zeroing lamports and data alone, as in the `insecure-still-still`
/// variant, is not sufficient — only this specific sentinel discriminator
/// marks the account as closed in a way nothing else can be confused with).
/// Exercises both the local-alias resolution (`account` bound via
/// `.to_account_info()`) and the discriminator-write detection.
///
/// Expected: no findings.
#[program]
pub mod closing_accounts_manual_safe {
    use super::*;

    pub fn close(ctx: Context<Close>) -> Result<()> {
        let account = ctx.accounts.account.to_account_info();
        let dest_starting_lamports = ctx.accounts.destination.lamports();

        **ctx.accounts.destination.lamports.borrow_mut() = dest_starting_lamports
            .checked_add(account.lamports())
            .unwrap();
        **account.lamports.borrow_mut() = 0;

        let mut data = account.try_borrow_mut_data()?;
        for byte in data.deref_mut().iter_mut() {
            *byte = 0;
        }

        let dst: &mut [u8] = &mut data;
        let mut cursor = Cursor::new(dst);
        cursor.write_all(&CLOSED_ACCOUNT_DISCRIMINATOR).unwrap();

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
