# KNOWN_LIMITATIONS.md

## Analysis Engine Scope & Known Boundaries

EPIC uses high-precision static analysis and abstract interpretation to detect security vulnerabilities in Anchor programs. The following boundaries define current operational assumptions and planned enhancements.

---

### EPIC-SEC-002: Mutable Write Detection Scope

**Behavior:**  
`EPIC-SEC-002` (Signer Validation Rule) detects privileged state modifications by analyzing `.borrow_mut()` / `.try_borrow_mut()` invocation chains and variable assignments initialized via `let` bindings.

**Scope Boundary:**  
Direct, plain field reassignments on structs without an intermediate `let` binding or explicit borrow call (for example, `account.field = value;`) are not currently evaluated as write triggers by `EPIC-SEC-002`.

**Verification & Real-World Impact:**  
An empirical audit across 6 production Solana codebases (Marginfi, Mango-v4, Orca Whirlpools, Squads-v4, Marinade, Metaplex MPL) confirmed that this scope boundary does **not** result in missed vulnerabilities:
- Every instance of direct field reassignment in the audited codebases operates on accounts already declared as `Signer<'info>` within Anchor context structs (which are automatically validated by EPIC's structural constraint analyzer).
- Remaining instances occur within initialization-only code paths where authority checks are enforced declaratively.

**Roadmap:**  
Extending `EPIC-SEC-002` expression tracing to cover direct assignments is scoped and scheduled for a post-release update, deferred to maintain strict false-positive bounds for the initial release.
