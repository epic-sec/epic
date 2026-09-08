# Frequently Asked Questions (FAQ)

### What is EPIC?
EPIC is the deployment safety layer for Solana. It provides a purely Rust-based semantic static analysis engine to prevent state layout corruptions, backward incompatibility, and severe lifecycle exploits in Anchor programs.

### Does EPIC replace `cargo-clippy` or other linters?
No. `cargo-clippy` ensures your Rust code is idiomatic and syntactically sound. EPIC operates at a semantic level, building Control Flow Graphs (CFG) and Static Single Assignment (SSA) trees to trace runtime safety constraints across instruction bodies.

### How do I integrate EPIC into CI/CD?
We provide a standalone GitHub Composite Action. See the [Migration Guide](migration_guide.md) or root `README.md` for workflow configuration.

### Does EPIC support non-Anchor programs?
Currently, EPIC heavily leverages the Anchor framework's declarative macros to infer layout intent and context bounds. Native Solana program support is on the roadmap.

### Is EPIC completely free?
Yes! EPIC is an open-source tool built for the Solana ecosystem.
