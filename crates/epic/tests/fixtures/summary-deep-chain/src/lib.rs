use anchor_lang::prelude::*;

/// hop1 -> hop2 -> hop3 -> hop4(has the actual check). Three call-graph
/// hops separate hop1 from the function that actually checks the account.
/// With MAX_DEPTH = 3, querying hop4 directly finds its own unconditional
/// check; querying hop1 should NOT see that guarantee propagate all the
/// way up — the depth cutoff should produce "no guarantee" for hop1, not a
/// crash, a hang, or (worse) a wrong "guaranteed" answer.
pub fn hop4(account: &AccountInfo) -> Result<()> {
    require!(account.is_signer, ErrorCode::Unauthorized);
    Ok(())
}

pub fn hop3(account: &AccountInfo) -> Result<()> {
    hop4(account)?;
    Ok(())
}

pub fn hop2(account: &AccountInfo) -> Result<()> {
    hop3(account)?;
    Ok(())
}

pub fn hop1(account: &AccountInfo) -> Result<()> {
    hop2(account)?;
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized")]
    Unauthorized,
}
