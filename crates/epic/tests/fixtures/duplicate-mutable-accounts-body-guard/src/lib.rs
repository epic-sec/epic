use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

/// EPIC-SEC-006 no-finding fixture — the sealevel-attacks `secure` fix,
/// adapted from the real false positive this rule produced on
/// orca-whirlpools' `two_hop_swap.rs` during the 5-protocol sweep: an
/// early-return guard in the handler body (`if a.key() == b.key() {
/// return Err(..) }`) instead of a struct-level `constraint`.
///
/// Expected: no findings.
#[program]
pub mod duplicate_mutable_accounts_body_guard {
    use super::*;

    pub fn update(ctx: Context<Update>, a: u64, b: u64) -> Result<()> {
        if ctx.accounts.user_a.key() == ctx.accounts.user_b.key() {
            return Err(ErrorCode::DuplicateAccount.into());
        }
        ctx.accounts.user_a.data = a;
        ctx.accounts.user_b.data = b;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Update<'info> {
    #[account(mut)]
    pub user_a: Account<'info, User>,
    #[account(mut)]
    pub user_b: Account<'info, User>,
}

#[account]
pub struct User {
    pub data: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Duplicate account")]
    DuplicateAccount,
}
