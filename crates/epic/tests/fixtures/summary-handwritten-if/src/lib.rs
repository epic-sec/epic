use anchor_lang::prelude::*;

/// A genuinely unconditional signer check, written as a plain hand-rolled
/// `if !cond { return Err(..); }` rather than `require!`/`assert!`. This is
/// semantically identical to summary-unconditional's fixture — the account
/// IS checked on every path that reaches `Ok(())` — and the CFG builder now
/// recognizes this shape structurally (`block_always_returns_err`) and tags
/// it `is_early_return`, the same as a require!/assert!-desugared branch.
///
/// This mirrors a real, verified example: orca-whirlpools's
/// util/shared.rs::validate_owner and marginfi's
/// test_transfer_hook::process (both hand-written `if { return Err }`
/// signer checks). Expected summary: {"account"}.
pub fn validate(account: &AccountInfo) -> Result<()> {
    if !account.is_signer {
        return Err(ErrorCode::Unauthorized.into());
    }
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized")]
    Unauthorized,
}
