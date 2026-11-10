use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

/// Coverage fixture: the marinade `ctx.accounts.process(..)` shape — a
/// handler whose own body makes zero direct writes, delegating entirely to
/// a `&mut self` method that resolves cleanly via `CallGraph::resolve_typed`.
/// Expected: `visible_writes == 0` (nothing in the handler's own body),
/// `reachable_via_resolved_delegate == 2` (both writes inside `process`),
/// `unresolved_delegate_calls == 0`.
#[program]
pub mod coverage_mutation_visibility {
    use super::*;

    pub fn change_authority(ctx: Context<ChangeAuthority>, new_authority: Pubkey) -> Result<()> {
        ctx.accounts.process(new_authority)
    }
}

#[derive(Accounts)]
pub struct ChangeAuthority<'info> {
    #[account(mut)]
    pub state: Account<'info, StateAccount>,
    pub authority: Signer<'info>,
}

impl<'info> ChangeAuthority<'info> {
    pub fn process(&mut self, new_authority: Pubkey) -> Result<()> {
        self.state.authority = new_authority;
        self.state.last_updated = 0;
        Ok(())
    }
}

#[account]
pub struct StateAccount {
    pub authority: Pubkey,
    pub last_updated: u64,
}
