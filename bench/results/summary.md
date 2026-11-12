# Sweep summary

| Protocol | Findings |
|---|---|
| marginfi | 70 |
| mango-v4 | 57 |
| orca-whirlpools | 89 |
| squads-mpl | 14 |
| marinade | 18 |

**Total: 248**

## Per rule

| Rule | Count |
|---|---|
| EPIC-SEC-002 | 65 |
| EPIC-SEC-003 | 41 |
| EPIC-SEC-004 | 2 |
| EPIC-SEC-ARITH | 24 |
| EPIC-SEC-PDA | 16 |
| EPIC-SEC-TOKEN | 100 |

## Per severity

| Severity | Count |
|---|---|
| Critical | 139 |
| High | 56 |
| Medium | 46 |
| Warning | 7 |

## Supplementary (not in sweep total)

| Protocol | Findings |
|---|---|
| squads-v4 | 1 |

### squads-v4 — per rule

| Rule | Count |
|---|---|
| EPIC-SEC-005 | 1 |

## Coverage

A 0-finding protocol with low coverage is not the same as a
0-finding protocol with full coverage — this table is what tells
them apart.

| Protocol | Handlers | Resolved | Fully analyzed |
|---|---|---|---|
| marginfi | 213 | 213 | 206 |
| mango-v4 | 181 | 181 | 164 |
| orca-whirlpools | 129 | 129 | 129 |
| squads-mpl | 33 | 33 | 31 |
| marinade | 29 | 29 | 29 |
| squads-v4 | 71 | 71 | 67 |

### Unresolved / partially analyzed handlers, by protocol

**marginfi** (7 not fully analyzed):

- lending_pool_configure_bank_emode (/Users/aksh/Documents/Solana EPIC/bench/corpus/marginfi/programs/marginfi/src/instructions/marginfi_group/config_bank_emode.rs): PartiallyAnalyzed — ["LoopDetected"]
- place_order (/Users/aksh/Documents/Solana EPIC/bench/corpus/marginfi/programs/marginfi/src/instructions/marginfi_account/order.rs): PartiallyAnalyzed — ["MatchExpression"]
- set_keeper_close_flags (/Users/aksh/Documents/Solana EPIC/bench/corpus/marginfi/programs/marginfi/src/instructions/marginfi_account/order.rs): PartiallyAnalyzed — ["MatchExpression"]
- start_execute_order (/Users/aksh/Documents/Solana EPIC/bench/corpus/marginfi/programs/marginfi/src/instructions/marginfi_account/order.rs): PartiallyAnalyzed — ["MatchExpression"]
- end_execute_order (/Users/aksh/Documents/Solana EPIC/bench/corpus/marginfi/programs/marginfi/src/instructions/marginfi_account/order.rs): PartiallyAnalyzed — ["MatchExpression"]
- sync_indexer_flags (/Users/aksh/Documents/Solana EPIC/bench/corpus/marginfi/programs/marginfi/src/instructions/marginfi_account/sync_indexer_flags.rs): PartiallyAnalyzed — ["LoopDetected"]
- lending_account_pulse_health (/Users/aksh/Documents/Solana EPIC/bench/corpus/marginfi/programs/marginfi/src/instructions/marginfi_account/pulse_health.rs): PartiallyAnalyzed — ["MatchExpression"]

**mango-v4** (17 not fully analyzed):

- token_deregister (/Users/aksh/Documents/Solana EPIC/bench/corpus/mango-v4/programs/mango-v4/src/instructions/token_deregister.rs): PartiallyAnalyzed — ["LoopDetected"]
- flash_loan_end (/Users/aksh/Documents/Solana EPIC/bench/corpus/mango-v4/programs/mango-v4/src/instructions/flash_loan.rs): PartiallyAnalyzed — ["LoopDetected","MatchExpression"]
- serum3_place_order (/Users/aksh/Documents/Solana EPIC/bench/corpus/mango-v4/programs/mango-v4/src/instructions/serum3_place_order.rs): PartiallyAnalyzed — ["MatchExpression","LoopDetected"]
- health_region_begin (/Users/aksh/Documents/Solana EPIC/bench/corpus/mango-v4/programs/mango-v4/src/instructions/health_region.rs): PartiallyAnalyzed — ["LoopDetected","MatchExpression"]
- account_buyback_fees_with_mngo (/Users/aksh/Documents/Solana EPIC/bench/corpus/mango-v4/programs/mango-v4/src/instructions/account_buyback_fees_with_mngo.rs): PartiallyAnalyzed — ["LoopDetected"]
- ix_gate_set (/Users/aksh/Documents/Solana EPIC/bench/corpus/mango-v4/programs/mango-v4/src/instructions/ix_gate_set.rs): PartiallyAnalyzed — ["LoopDetected"]
- token_update_index_and_rate (/Users/aksh/Documents/Solana EPIC/bench/corpus/mango-v4/programs/mango-v4/src/instructions/token_update_index_and_rate.rs): PartiallyAnalyzed — ["LoopDetected","MatchExpression"]
- perp_consume_events (/Users/aksh/Documents/Solana EPIC/bench/corpus/mango-v4/programs/mango-v4/src/instructions/perp_consume_events.rs): PartiallyAnalyzed — ["LoopDetected","MatchExpression"]
- account_close (/Users/aksh/Documents/Solana EPIC/bench/corpus/mango-v4/programs/mango-v4/src/instructions/account_close.rs): PartiallyAnalyzed — ["LoopDetected"]
- token_liq_bankruptcy (/Users/aksh/Documents/Solana EPIC/bench/corpus/mango-v4/programs/mango-v4/src/instructions/token_liq_bankruptcy.rs): PartiallyAnalyzed — ["LoopDetected"]
- account_edit (/Users/aksh/Documents/Solana EPIC/bench/corpus/mango-v4/programs/mango-v4/src/instructions/account_edit.rs): PartiallyAnalyzed — ["MatchExpression"]
- health_check (/Users/aksh/Documents/Solana EPIC/bench/corpus/mango-v4/programs/mango-v4/src/instructions/health_check.rs): PartiallyAnalyzed — ["MatchExpression"]
- token_edit (/Users/aksh/Documents/Solana EPIC/bench/corpus/mango-v4/programs/mango-v4/src/instructions/token_edit.rs): PartiallyAnalyzed — ["LoopDetected"]
- perp_place_order (/Users/aksh/Documents/Solana EPIC/bench/corpus/mango-v4/programs/mango-v4/src/lib.rs): PartiallyAnalyzed — ["MatchExpression"]
- perp_place_order_v2 (/Users/aksh/Documents/Solana EPIC/bench/corpus/mango-v4/programs/mango-v4/src/lib.rs): PartiallyAnalyzed — ["MatchExpression"]
- perp_place_order_pegged (/Users/aksh/Documents/Solana EPIC/bench/corpus/mango-v4/programs/mango-v4/src/lib.rs): PartiallyAnalyzed — ["MatchExpression"]
- perp_place_order_pegged_v2 (/Users/aksh/Documents/Solana EPIC/bench/corpus/mango-v4/programs/mango-v4/src/lib.rs): PartiallyAnalyzed — ["MatchExpression"]

**squads-mpl** (2 not fully analyzed):

- create_transaction (/Users/aksh/Documents/Solana EPIC/bench/corpus/squads-mpl/programs/squads-mpl/src/lib.rs): PartiallyAnalyzed — ["MatchExpression"]
- execute_instruction (/Users/aksh/Documents/Solana EPIC/bench/corpus/squads-mpl/programs/squads-mpl/src/lib.rs): PartiallyAnalyzed — ["LoopDetected"]

**squads-v4** (4 not fully analyzed):

- config_transaction_execute (/Users/aksh/Documents/Solana EPIC/bench/corpus/squads-v4/programs/squads_multisig_program/src/instructions/config_transaction_execute.rs): PartiallyAnalyzed — ["LoopDetected","MatchExpression"]
- config_transaction_accounts_close (/Users/aksh/Documents/Solana EPIC/bench/corpus/squads-v4/programs/squads_multisig_program/src/instructions/transaction_accounts_close.rs): PartiallyAnalyzed — ["MatchExpression"]
- vault_transaction_accounts_close (/Users/aksh/Documents/Solana EPIC/bench/corpus/squads-v4/programs/squads_multisig_program/src/instructions/transaction_accounts_close.rs): PartiallyAnalyzed — ["MatchExpression"]
- batch_accounts_close (/Users/aksh/Documents/Solana EPIC/bench/corpus/squads-v4/programs/squads_multisig_program/src/instructions/transaction_accounts_close.rs): PartiallyAnalyzed — ["MatchExpression"]

## Timing / peak memory

| Protocol | Wall time | Peak RSS |
|---|---|---|
| marginfi | 1.25s | 107696KB |
| mango-v4 | 1.15s | 122128KB |
| orca-whirlpools | 0.83s | 126880KB |
| squads-mpl | 0.06s | 8816KB |
| marinade | 0.06s | 10720KB |
| squads-v4 | 0.10s | 15584KB |
