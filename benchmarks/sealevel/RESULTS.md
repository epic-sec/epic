# Sealevel Attacks — Classified Results

Measured against EPIC commit `59a6950272e07c2ba2efb48e7084b0e364f4f138`,
sealevel-attacks pinned at `24555d044802db4022112a94d6d70e74291a4b6d`.
Regenerate the raw per-variant output with `./run.sh`; this file is the
classified, narrated read of that output — verdicts below were re-checked
by hand against the actual source of every flagged/unflagged variant, not
inferred from pass/fail alone.

Legend:
- **TRUE POSITIVE** — insecure variant flagged, by a rule that targets this
  vulnerability class.
- **FALSE NEGATIVE** — insecure variant *not* flagged, even though a rule
  targeting this class exists.
- **NOT COVERED** — insecure variant not flagged because no rule in EPIC
  targets this vulnerability class at all (not a bug in an existing rule;
  there's nothing to fire).
- **FALSE POSITIVE** — secure or recommended variant flagged at full
  (CRITICAL/HIGH) severity for something that isn't actually a
  vulnerability.
- **NOT FLAGGED** — the variant produced zero findings from any rule.
- **FLAGGED — WARNING** — the variant produced a finding, but at a
  downgraded, non-blocking severity rather than zero findings. This is
  *not* the same as NOT FLAGGED and is not scored as a clean pass: a
  reader of EPIC's output still sees an item to review. It is also not
  scored as a FALSE POSITIVE, since the downgrade is intentional and the
  underlying manual check genuinely closes the vulnerability — but it
  means discrimination on that class is partial, not complete.

| # | Class | Rule(s) that apply | insecure | secure flag status | recommended flag status |
|---|-------|---------------------|----------|--------|-------------|
| 0 | signer-authorization | EPIC-SEC-002 | FALSE NEGATIVE | NOT FLAGGED (correct) | NOT FLAGGED (correct) |
| 1 | account-data-matching | *(none)* | NOT COVERED | NOT FLAGGED | NOT FLAGGED |
| 2 | owner-checks | EPIC-SEC-001 | FALSE NEGATIVE | NOT FLAGGED (correct)† | NOT FLAGGED (correct) |
| 3 | type-cosplay | *(none)* | NOT COVERED | NOT FLAGGED | NOT FLAGGED |
| 4 | initialization | *(none)* | NOT COVERED | NOT FLAGGED | NOT FLAGGED |
| 5 | arbitrary-cpi | EPIC-SEC-005 | **TRUE POSITIVE** (CRITICAL) | NOT FLAGGED (correct) | NOT FLAGGED for SEC-005; SEC-TOKEN fires ×2, see note‡ |
| 6 | duplicate-mutable-accounts | *(none)* | NOT COVERED | NOT FLAGGED | NOT FLAGGED |
| 7 | bump-seed-canonicalization | EPIC-SEC-PDA | **TRUE POSITIVE** (CRITICAL) | **FLAGGED — WARNING** (not clean — see note§) | NOT FLAGGED |
| 8 | pda-sharing | *(none)* | NOT COVERED | NOT FLAGGED | NOT FLAGGED |
| 9 | closing-accounts | *(none)* | NOT COVERED (all 5 variants: insecure, insecure-still, insecure-still-still, secure, recommended — all NOT FLAGGED) | — | — |
| 10 | sysvar-address-checking | *(none)* | NOT COVERED | NOT FLAGGED | NOT FLAGGED |

**Score: 2 TRUE POSITIVE / 2 FALSE NEGATIVE / 7 NOT COVERED / 0 FALSE POSITIVE
/ 1 FLAGGED — WARNING (class 7's secure variant).**
Zero full-severity false positives is expected, not impressive — most
classes have no rule to false-positive with in the first place. The
FLAGGED — WARNING case is counted on its own line deliberately: it is
**not** folded into either "0 FALSE POSITIVE" or a clean pass. Full
discrimination on class 7 is not yet achieved — EPIC correctly tells
CRITICAL and WARNING apart by which derivation call backs the manual
check, but the secure variant still produces a finding at all, so a
reader auditing its output is not shown a fully clean bill of health for
that fixture.

## Notes

**† Class 2, `secure` variant is a real edge case worth understanding, not
a clean pass in the trivial sense.** Its `secure` example deserializes the
token account's data (`SplTokenAccount::unpack(&ctx.accounts.token.data.borrow())?`)
*before* checking `ctx.accounts.token.owner != &spl_token::ID`. EPIC's
dominance analysis is technically correct that the read precedes the check
in program order — it stays clean only because EPIC's write-only mutation
gate never triggers here at all (nothing is *written*), not because it
reasoned about the ordering and let it pass. If SEC-001 is ever widened to
data reads again, this fixture needs to be re-examined, since the
benchmark's own "secure" ordering is arguably not best-practice.

**‡ Class 5, `recommended` fires EPIC-SEC-TOKEN twice** (`source` and
`destination` missing mint/authority constraints) — a genuine, unrelated
finding from a different rule, not a false positive of SEC-005 and not
counted against the arbitrary-CPI classification above. SEC-005 correctly
stays silent on this variant (it uses a typed `Program<'info, Token>` and
`CpiContext::new`, which is exactly the fix). Whether the SEC-TOKEN finding
is itself fair is a separate question this benchmark wasn't testing.

**§ Class 7, `secure` variant is FLAGGED — WARNING, not a clean pass, and
that gap is not yet closed.** `find_program_address` always returns the
canonical bump, so a manual `.key()` comparison against its result already
rules out account substitution regardless of what the caller passes in —
there is no vulnerability here to flag CRITICAL. That severity downgrade
is intentional and correct. What is *not* yet achieved is full
discrimination: EPIC still emits a WARNING-level hardening note on this
fixture ("declare this with `seeds = [...], bump]` for easier auditing")
rather than recognizing the check as fully sufficient and staying silent.
The rule correctly tells CRITICAL and WARNING apart by which derivation
call backs the manual check (see the SEC-PDA sub-check 1 fix — it also
keeps `create_program_address` at CRITICAL, since that call blindly trusts
whatever bump it's given), but it does not yet go the further step of
suppressing the WARNING entirely for a canonically-verified account. Until
that's done, `secure` on this class will keep showing up as "1 finding" in
EPIC's own output, not zero.

## The SEC-001 / SEC-002 mutation-gate decision (classes 0 and 2)

Both false negatives above share the same root cause: SEC-001 and SEC-002
only trigger on a **privileged write** to the account in question. Classes
0 and 2's `insecure` fixtures never write anything — they read an
unchecked signer's/owner's data and only `msg!()` it. A write-only gate
structurally cannot see this.

This was not an oversight. Widening the gate from "write" to "any
privileged use" (reads, call-argument passes, logged references) was
implemented and measured against all 6 real protocols in this project's
audit sweep. It fixed both benchmark classes, but at an unacceptable cost:
100+ new findings on real protocol code, the overwhelming majority on
program IDs, PDAs, and accounts explicitly annotated
`/// CHECK: safe, arbitrary` by their own authors (e.g. Orca's
`new_fee_authority` — a pubkey being stored as a *future* authority, which
has no reason to be checked at the point it's merely read). Sampling
confirmed this was noise, not signal, so the widening was reverted in
full — commit `10e3f4c` in this repo's history.

**This is a deliberate precision tradeoff, not an oversight**: a rule that
misses a read-only variant of signer/owner misuse is a known, bounded gap.
A rule that triples false positives on real, audited protocols destroys
the tool's credibility on every finding it produces, including the correct
ones. Given a choice between the two failure modes, EPIC chose the
narrower, honest one. If this gap needs closing in the future, it needs a
narrower anchor than "any use" — e.g. specifically data-content access
(deserialization, field reads) as opposed to identity-only or
pass-through use — not a full revert of this decision.

## Classes with no covering rule (1, 3, 4, 6, 8, 9, 10)

These seven classes are not bugs in an existing rule — there is currently
no rule in EPIC that targets account-data-matching, type-cosplay,
(re)initialization guards, duplicate mutable accounts, PDA-sharing, account
closing, or sysvar address checking. None of `EPIC-SEC-001/002/003/004/005`,
`EPIC-SEC-PDA`, `EPIC-SEC-009/010`, or `EPIC-SEC-TOKEN` claim to cover any
of them. This benchmark run is the honest record of that: 7 of 11 classes
are simply out of scope for the current rule set, not silently missed by
one that claims to handle them.
