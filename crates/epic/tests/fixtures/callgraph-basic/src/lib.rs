use anchor_lang::prelude::*;

/// Free-function call: `foo(x)`.
fn check_owner(account: &AccountInfo) -> Result<()> {
    Ok(())
}

pub struct Checker;

impl Checker {
    /// Method call on a receiver: `checker.validate(x)`.
    fn validate(&self, account: &AccountInfo) -> Result<()> {
        Ok(())
    }

    /// Method call on `self`: `self.method(x)`.
    fn run(&self, account: &AccountInfo) -> Result<()> {
        self.validate(account)
    }
}

pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
    check_owner(&ctx.accounts.authority)?;

    let checker = Checker;
    checker.run(&ctx.accounts.authority)?;

    ctx.accounts.vault.balance -= 1;
    Ok(())
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub authority: AccountInfo<'info>,
    pub vault: Account<'info, VaultAccount>,
}

#[account]
pub struct VaultAccount {
    pub balance: u64,
}
