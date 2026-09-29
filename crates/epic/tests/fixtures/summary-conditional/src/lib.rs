use anchor_lang::prelude::*;

/// Conditional signer check: does NOT dominate every Ok-return (the
/// `some_flag == false` path returns Ok without ever checking).
/// Expected summary: {} (empty — no guarantee).
pub fn validate(account: &AccountInfo, some_flag: bool) -> Result<()> {
    if some_flag {
        require!(account.is_signer, ErrorCode::Unauthorized);
    }
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized")]
    Unauthorized,
}
