# Contributing to EPIC

Thank you for your interest in contributing to EPIC! We welcome contributions from Solana protocol engineers, developer experience enthusiasts, and Rust/TypeScript developer tooling enthusiasts.

This guide will walk you through setting up your local environment, building the codebase, and running tests.

---

## Code of Conduct

As a contributor, you agree to uphold our values of:
*   **Trust and Correctness**: EPIC is a security safety tool. Ensure that layout offset calculations and AST parsers are deterministic and correct.
*   **Developer Focus**: Keep tools fast, clean, and local-first. We do not integrate tracking, analytics, or third-party SaaS dependencies.

---

## Getting Started

### Prerequisites
Before you start, make sure you have installed:
*   **Node.js** (v20 or higher)
*   **npm** (v10 or higher)
*   **Rust and Cargo** (only if editing the native Rust parser engine `parser-v2`)

### 1. Repository Setup
Clone the repository and install all node dependencies. We use npm workspaces to manage monorepo packages:

```bash
git clone https://github.com/epic-sec/epic.git
cd epic

# Install monorepo dependencies and link local workspaces
npm install
```

### 2. Building the Project
We use [Turborepo](https://turbo.build/) to coordinate builds. Build all workspaces with:

```bash
npm run build
```

This compiles TypeScript source files in `packages/*/src/` to compiled files in `packages/*/dist/`.

---

## Monorepo Architecture

EPIC is structured as a monorepo under `packages/`:

*   [`packages/cli`](file:///Users/aksh/Documents/Solana%20EPIC/packages/cli): The command-line entrypoint (`epic` CLI). Contains the native binary loader.
*   [`packages/parser`](file:///Users/aksh/Documents/Solana%20EPIC/packages/parser): Handles configuration (`epic.toml`), schema validation using Zod, and Rust source/IDL loading.
*   [`packages/diff-engine`](file:///Users/aksh/Documents/Solana%20EPIC/packages/diff-engine): Performs ABI difference comparisons and maps differences to severities.
*   [`packages/github-action`](file:///Users/aksh/Documents/Solana%20EPIC/packages/github-action): The GitHub Action wrapper that displays warning banners and status tables.
*   [`packages/cli-*`](file:///Users/aksh/Documents/Solana%20EPIC/packages/): OS/CPU specific prebuilt packages containing pre-compiled `parser-v2` binaries (e.g. `@epic/cli-darwin-arm64`).
*   [`packages/parser-v2`](file:///Users/aksh/Documents/Solana%20EPIC/packages/parser-v2): The core Rust program analysis AST parser.

---

## Development Workflow

### Running Tests
Our test suite uses Node's native test runner (`node --test`). Run all tests in the workspace with:

```bash
npm test
```

### Modifying the Rust Engine
If you make changes to the Rust AST parsing logic inside `packages/parser-v2`:
1.  Run tests inside the Rust crate:
    ```bash
    cd packages/parser-v2
    cargo test
    ```
2.  Build the release binary:
    ```bash
    cargo build --release
    ```
3.  Run the local packaging test utility to confirm integration:
    ```bash
    cd ../../
    node scripts/package-local.mjs
    node scripts/test-local-install.mjs
    ```

### Documentation Policy
*   **Do not delete or modify docstrings/comments** unless you are directly correcting outdated behavior.
*   Write clean, self-documenting code.
*   Keep user guides and documentation updated inside `/docs`.

---

## Submitting Pull Requests

1.  Create a feature branch from `main` (e.g., `git checkout -b feature/my-feature`).
2.  Make your changes. Ensure you add unit tests if you are introducing new logic or resolving bugs.
3.  Run `npm run build` and `npm test` locally.
4.  Commit your changes following standard commit conventions.
5.  Open a Pull Request against the `main` branch. CI must pass cleanly before merge.
