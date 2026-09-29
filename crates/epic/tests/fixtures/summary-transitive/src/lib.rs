use anchor_lang::prelude::*;

/// The actual check, one hop down.
fn inner_check(account: &AccountInfo) -> Result<()> {
    require!(account.is_signer, ErrorCode::Unauthorized);
    Ok(())
}

/// Calls inner_check unconditionally (dominates its own only Ok-return) and
/// propagates the argument straight through by bare identifier.
/// Expected summary for `outer`: {"account"} — proves transitive
/// propagation through one call-graph hop.
pub fn outer(account: &AccountInfo) -> Result<()> {
    inner_check(account)?;
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized")]
    Unauthorized,
}
