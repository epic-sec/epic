# EPIC Installation Guide

The EPIC Semantic Engine is now a standalone Rust binary, providing massive performance improvements and stronger static analysis guarantees for Solana Anchor programs.

## Option 1: Install from crates.io (Recommended)
You can install EPIC directly using Cargo:
```bash
cargo install epic
```

## Option 2: Pre-compiled Binaries
You can download the pre-compiled binaries from the GitHub Releases page.
Supported platforms:
- macOS (Apple Silicon / ARM64)
- macOS (Intel / x64)
- Linux (x64)
- Windows (x64)

Extract the binary and place it in your `$PATH`.

## Option 3: Build from Source
```bash
git clone https://github.com/solana-epic/epic.git
cd epic
cargo install --path crates/epic
```

## Verifying Installation
Once installed, verify the installation by running:
```bash
epic doctor
```
If you see a healthy environment output, EPIC is successfully installed and ready to audit your workspaces!
