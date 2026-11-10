use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

/// Coverage fixture: the `#[program]` handler is a one-line delegate to a
/// method defined inside `impl Withdraw { .. }`, using `Context<Self>` —
/// the real Squads V4 idiom that `get_context_generic_type` can't resolve
/// (it reads `Context<Self>` literally, looks for a struct named `Self`,
/// finds none). Expected: `collect_coverage` reports this handler as
/// `Unresolved`, not `FullyAnalyzed` — it must never silently vanish.
#[program]
pub mod coverage_context_self {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        Withdraw::withdraw(ctx, amount)
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, VaultAccount>,
    pub authority: Signer<'info>,
}

impl<'info> Withdraw<'info> {
    pub fn withdraw(ctx: Context<Self>, amount: u64) -> Result<()> {
        ctx.accounts.vault.balance -= amount;
        Ok(())
    }
}

#[account]
pub struct VaultAccount {
    pub balance: u64,
}
