use anchor_lang::prelude::*;

/// Directly recursive. Has an unconditional signer check before the
/// recursive call, so a naive (non-cycle-safe) analysis might try to prove
/// the guarantee by chasing the recursive call forever. Expected: the
/// analysis terminates and produces *some* summary without hanging or
/// panicking (recursion is detected and bailed on, per spec) — this
/// fixture is a liveness/safety check, not a check on which specific
/// summary comes out.
pub fn recursive_check(account: &AccountInfo, depth: u8) -> Result<()> {
    require!(account.is_signer, ErrorCode::Unauthorized);
    if depth > 0 {
        recursive_check(account, depth - 1)?;
    }
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized")]
    Unauthorized,
}
