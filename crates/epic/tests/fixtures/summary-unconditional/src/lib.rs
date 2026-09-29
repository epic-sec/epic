use anchor_lang::prelude::*;

/// Unconditional signer check: dominates the function's only Ok-return.
/// Expected summary: {"account"}.
pub fn validate(account: &AccountInfo) -> Result<()> {
    require!(account.is_signer, ErrorCode::Unauthorized);
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized")]
    Unauthorized,
}
