use anchor_lang::prelude::*;

/// A genuinely unconditional signer check, written as a plain hand-rolled
/// `if !cond { return Err(..); }` rather than `require!`/`assert!`. This is
/// semantically identical to summary-unconditional's fixture — the account
/// IS checked on every path that reaches `Ok(())` — but the CFG builder
/// only tags require!/assert!/`?`-desugared branches `is_early_return`,
/// never plain if-statements. So the `return Err(..)` exit here is NOT
/// excluded from "exits the check must dominate," and the check (which
/// only dominates the *other* branch) looks like it doesn't cover every
/// Ok-path.
///
/// This mirrors a real, verified example: orca-whirlpools's
/// util/shared.rs::validate_owner and marginfi's
/// test_transfer_hook::process (both hand-written `if { return Err }`
/// signer checks). Expected summary for THIS version: {} (empty) — a
/// known, conservative under-claim for a first version, not a bug in the
/// dominance logic itself.
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
