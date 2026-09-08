# EPIC Semantic Engine Benchmarks (v0.2.0)

The new EPIC Rust engine provides unparalleled scan times for large Solana workspaces. It parses the entire AST structure, constructs Control Flow Graphs (CFG), resolves Static Single Assignment (SSA) traces, and verifies complex lifecycle constraints across instruction bodies in milliseconds.

| Repository | Size Classification | Scan Time | Findings |
| --- | --- | --- | --- |
| **Squads-v4** | Medium | `0.07s` | 0 |
| **Solana Program Examples** | Large (Many small protocols) | `0.20s` | 16 |
| **Mango-v4** | Very Large | `0.78s` | 77 |
| **Marginfi** | Very Large | `0.84s` | 73 |

*Measurements taken on macOS Apple Silicon (M-series).*

These metrics demonstrate that EPIC is fast enough to run continuously on every keystroke in local IDE environments, completely blocking security regressions in real-time.
