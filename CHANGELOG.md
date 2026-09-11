# Changelog

All notable changes to the EPIC project will be documented in this file. This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.0] - 2026-09-11

This release changes finding output. If you have anything depending on exact
finding counts or severities (CI gates, dashboards, snapshot tests), expect
your numbers to move on upgrade — read "Changed" below before upgrading in
an automated pipeline.

The previously published version (0.2.0) predates `EPIC-SEC-PDA` entirely —
that rule did not exist yet. Everything below that touches `EPIC-SEC-PDA` is
new to anyone upgrading from 0.2.0, not just a fix to prior behavior.

### Added
*   **`EPIC-SEC-PDA`** (PDA Derivation and Bump Canonicality): new since 0.2.0. Detects accounts used as a PDA (via `find_program_address`/`create_program_address`, or in a signer-seeds array for `invoke_signed`/`CpiContext::new_with_signer`) that lack a `seeds = [...], bump` derivation constraint, and separately flags caller-supplied (non-canonical) bump values.
*   CFG desugaring for `require!`/`require_eq!`/`require_neq!`/`require_keys_eq!`/`require_keys_neq!`/`require_gt!`/`require_gte!`/`assert!`/`assert_eq!`/`assert_ne!`: these now produce real conditional branches in the control-flow graph, the same shape a hand-written `if !cond { return Err(..) }` would. Previously only a literal `if` was visible to dominance analysis; a `require!`-guarded check was invisible to `EPIC-SEC-002`'s dominance query regardless of where it appeared relative to the write it was meant to guard.
*   `benchmarks/sealevel/`: a vendored, re-runnable benchmark harness against `coral-xyz/sealevel-attacks` (pinned commit `24555d044802db4022112a94d6d70e74291a4b6d`), with a checked-in, classified results table for all 11 vulnerability classes (`benchmarks/sealevel/RESULTS.md`) — including every known false negative and not-covered class.

### Fixed
*   **`EPIC-SEC-PDA` false positive on canonical stored bumps**: `bump = <account>.bump` and marinade's `_bump_seed` naming convention no longer flag as caller-supplied. Also fixed a location-attribution bug (findings previously reported at `lib.rs:0:0` for macro-declared facts now report the real field span) and a message leak (`<var:1>.property` internal debug tokens no longer appear in finding text).
*   **`EPIC-SEC-PDA` sub-check 1 firing identically on secure and insecure code**: it previously flagged CRITICAL on any account used as a PDA without a macro-level `seeds/bump` declaration, with no awareness of manual validation in the function body. It's now aware of *which* derivation call backs a manual check: `find_program_address` is unconditionally canonical, so a `.key()` comparison against its result is downgraded to a WARNING-level hardening note instead of CRITICAL; `create_program_address` blindly trusts its bump argument and stays CRITICAL, since a comparison against its result provides no real protection.
*   **`EPIC-SEC-005` (Arbitrary CPI Target) fired on almost nothing**, including its own namesake benchmark class. Root-caused to three compounding gaps: (1) dataflow into a raw `invoke(instruction, accounts)` call only ever inspected the accounts-slice argument, never the instruction-building argument where the target program id actually lives (e.g. `spl_token::instruction::transfer(token_program, ...)`); (2) the resolver couldn't match a raw `AccountInfo` field access (`token_program.key`, not `.key()`) back to its account symbol; (3) a local `expr_to_string` helper silently dropped call arguments, hiding validation performed via a helper function call rather than an inline comparison. All three fixed; verified against `sealevel-attacks/5-arbitrary-cpi`.
*   **`ir_expr_to_string` (guards.rs)** did not unwrap `Reference`/`Dereference`/`Try`, so an owner comparison written as `account.owner != &spl_token::ID` (a `Reference` around the RHS) stringified to `"unknown"` and could never match `is_valid_expected_owner`'s whitelist regardless of its contents — a real false positive on the (very common) `&Program::ID` owner-check idiom, independent of any other change in this release.
*   `is_valid_expected_owner`'s whitelist now accepts `::ID`/`::id`-suffixed qualified paths (e.g. `spl_token::ID`), not just the bare literals it previously matched.
*   Dead npm-based CI (`test.yml` ran `npm ci && npm run build && npm test` against a `package.json` whose `packages/*` workspaces didn't exist) replaced with real `cargo build`/`test`/`clippy --all-targets`/`fmt --check` steps. `--all-targets` was added to the clippy step specifically so test-file clippy errors (previously invisible to CI) are caught going forward.

### Changed
*   **Sweep corpus dropped from 6 to 5 real-world protocols.** `metaplex-foundation/mpl-token-metadata` was removed: it's a Shank-based native Solana program, not Anchor (zero `anchor-lang`, zero `#[program]`, zero `#[derive(Accounts)]`), and its results were dominated by a naming collision (see Known Issues) rather than representative signal about EPIC's accuracy on Anchor code. Current corpus: mango-v4, marginfi, marinade, orca-whirlpools, squads-v4.
*   Real-world finding counts will be lower for two independent reasons on top of the corpus change: (a) the SEC-PDA severity discrimination above moves some prior CRITICALs to WARNING rather than removing them outright — check severity distributions, not just totals, before assuming a clean diff; (b) the SEC-005 fix removed two false-CRITICAL findings on metaplex-mpl (now dropped from the corpus anyway) while adding a net +1 elsewhere.

### Investigated and Reverted (documented, not shipped)
*   **SEC-001/SEC-002 "mutation gate" widening.** Both rules only trigger on a privileged *write*; widening the anchor to any privileged *use* (reads, call-argument passes, logged references) was implemented and measured against all 6 protocols in the corpus at the time. It fixed two real false-negative classes (an unchecked signer/owner whose only use is `msg!()`), but produced 100+ new findings dominated by program IDs, PDAs, and accounts explicitly annotated `/// CHECK: safe, arbitrary` by their own authors. Reverted in full — see `benchmarks/sealevel/RESULTS.md` for the measured detail. Two independent bug fixes discovered during that investigation (the `ir_expr_to_string` and `is_valid_expected_owner` fixes above) were kept.
*   **`EPIC-SEC-TOKEN` `has_authority` keyword-list fix.** The rule's authority-constraint check scans for the substrings `"authority"`/`"key"`/`"vault"` in a `constraint = ...` attribute but not `"owner"`, missing a genuine constraint on mango-v4 (`token_force_withdraw.rs:51`). Adding `"owner"` was implemented and measured, then reverted: the check is a bare substring match over the whole attribute text, and Anchor constraints reference their own field by name — orca-whirlpools names several fields `token_owner_account_a`, `reward_owner_account`, etc., so `"owner"` matched the field's own name inside an unrelated mint-only constraint, silently suppressing 18 legitimate findings (5-repo sweep total 224 → 206, entirely from this one repo). Not fixed; a correct fix requires parsing the constraint expression rather than substring matching.

### Known Issues (newly documented this release, see `KNOWN_LIMITATIONS.md`)
*   **`EPIC-SEC-001`/`EPIC-SEC-002` authority-like-symbol scan can match a struct-literal field label instead of the account it's populated from** — e.g. `SomeStruct { authority: ctx.accounts.authority_info.key, .. }` is misread as a reference to a nonexistent account named `authority`, rather than the real, checked account `authority_info`. General to any Anchor program with this shape, not specific to non-Anchor code. Documented with a concrete example; not fixed.
*   **`EPIC-SEC-TOKEN` never analyzes the instruction handler body** — it reads only the `#[account(...)]` attribute text, `has_one` in the same struct, and existing PDA facts, unlike `EPIC-SEC-001`/`EPIC-SEC-002` which at least attempt CFG dominance over a manual check. It also does not distinguish a token account's role: a credit-only account (a deposit source, a mint destination) needs no authority constraint, but the rule demands both uniformly. Sampled 10 findings across 4 protocols: 0 true positives, 6 backed by a real but imperative check, 4 requiring no constraint at all. Its message overstates what it detects — read it as "does not use Anchor's declarative constraint idiom," not "is exploitable."

---

## [0.1.0-beta.2] - 2026-06-25

This release transforms the EPIC CLI from a static analyzer into a premium, interactive, and educational security workflow.

### Added
*   **Intelligent CLI Workflow**: `epic audit` now groups findings intelligently, displays occurrence metrics, and dynamically generates actionable Next Steps based on audit priority.
*   **Rule Knowledge Engine**: Embeds rich historical context, actionable fixes, and conceptual explanations into findings directly inside the terminal.
*   **Diagnostics Mode**: Added `epic doctor` to automatically verify system environment dependencies (Rust, Cargo, Node.js, Configuration, Workspace structure).
*   **Explanation Mode**: Added `epic explain <rule_id>` for on-demand deep-dive rule education containing severity mapping, threat models, safe/unsafe examples, and historical vulnerabilities.
*   **Smart Security Score**: The audit summary now calculates a dynamic `Security Score` spanning confidence bands (`Production Ready`, `Minor Issues`, `Needs Review`, `High Risk`, `Unsafe For Deployment`).

### Changed
*   **Terminal Aesthetics**: Replaced the large ASCII banner with a highly polished typography-driven header. Extensively utilized `bold`, `dim`, `cyan`, and precise alignments for a Cargo/Rust analyzer-like premium feel.
*   **Repository Filtering**: Improved parsing logic to automatically ignore test suites, `.git`, `node_modules`, `vendor`, and `fixtures` by default to ensure only production logic affects security scores. Added overrides (`--include-tests`, `--all`).
*   **Publish Pipeline**: Overhauled `scripts/publish.sh` to enforce real `npm publish`, integrate interactive 2FA prompt support, verify real-time registry deployments, and implement a `--from` resume flag.

### Developer Experience
*   **Execution Metrics**: Added detailed elapsed timing visualizations dividing processing across AST Build, Call Graph extraction, Rule Execution, and Rendering.
*   **Repository Overview**: Generates a fast breakdown of parsed code blocks (Rust Files, Instructions, Accounts, CPIs, PDAs, Programs) prior to rule execution.
*   **Contextual Hints**: Introduced dynamically rolling tips at the end of execution to improve command discovery (e.g., using `--markdown`).
*   **Output Modes**: Expanded `--format` support providing clean JSON output for programmatic ingestion and Markdown rendering for PR comments.

### Fixed
*   **Release Pipeline Simulator Flaw**: Replaced the mock npm publisher (`mock-npm.sh`) with strict production npm registry calls.
*   **Finding Noise**: Resolved issues where dummy test cases would artificially deflate the overall security score of the project.

---

## [0.1.0-beta.1] - 2026-06-18

This is the initial public beta release of the Engineering Platform for Intelligent Contracts (EPIC), providing deterministic state layout verification and ABI compatibility audits for Solana program upgrades.

### Added
*   **Rust AST Parsing Engine (`parser-v2`)**: Compiles and parses Anchor/Rust program structures, state accounts, enums, and type aliases without compile-time cargo steps.
*   **Workspace Packages**:
    *   `@epic/cli`: Command-line executable (`epic`) featuring a multi-layered native binary loader.
    *   `@epic/parser`: Configuration parser for `epic.toml` integrating Zod-schema constraints, wildcard block lists, and security gates.
    *   `@epic/diff-engine`: Comparison engine matching account layouts, analyzing offset drift, type width reductions, and realloc constraints.
    *   `@epic/github-action`: CI pull-request reporter displaying status banners, summary findings tables, and active configuration overrides.
*   **Native Binary Loader**: Automatically detects target platforms and architectures (`darwin-arm64`, `darwin-x64`, `linux-x64`, `win32-x64`) and resolves the host wrapper.
*   **Configuration Mutes (`epic.toml`)**: Custom mutes and override rules to silence specific layout drift warnings, gated by strict security validation rules (blocking wildcard overrides, note lengths, and critical layout overrides).
*   **Validation Suite**: 42 unit and integration tests executing configuration loads, layout drift compares, action HTML/markdown report formatting, and loader checks.
*   **Packaging and Install Runners**:
    *   `package-local.mjs` for workspace packing.
    *   `test-local-install.mjs` to verify isolated npm tarball installation.

### Fixed
*   **TS Tarball Packing**: Added explicit `"files": ["dist"]` filters to TypeScript packages to prevent compiled folders from being ignored by gitignore constraints during packaging.
*   **Inline TOML Parsing**: Resolved AST parsing bugs on inline configurations inside the parser.
