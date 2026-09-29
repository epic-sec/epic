# EPIC

> **Upgrade Intelligence for Solana Programs.**  
> *Know what changes. Know what breaks. Ship with confidence.*

---

EPIC is the deployment safety layer for Solana. Positioned between git push and mainnet, EPIC evaluates account layout evolution, ABI compatibility, and security regressions before upgrades reach production.

## Why Upgrade Intelligence Matters

Your Solana upgrade compiled successfully. Tests pass. Audits pass. It is still about to corrupt every existing account. 

Every Solana program upgrade is a high-risk migration. A minor type shift, field reordering, or missing state reload can corrupt deserialization layouts, lock user funds, and introduce severe security regressions. Most protocol teams discover breaking layout changes after deployment. EPIC answers a simple question before you ever sign a transaction: *"Can I safely deploy this?"*

## Core Capabilities

*   **Upgrade Compatibility Checking**: Compare program versions to detect state layout drift, field reordering, type width changes, and Anchor discriminator shifts.
*   **Security Audit**: Verify safety constraints, signer checks, and post-CPI reload invariants introduced during upgrade changes.
*   **Workspace Analysis**: Analyze serialized account sizes, offset structures, and memory growth impact to manage state scaling.
*   **Deployment Readiness Pipeline**: Integrate upgrade validation into CI/CD workflows using the GitHub Action to prevent breaking layouts from reaching mainnet.

## Installation

Install the command-line interface:

```bash
npm install -g @solana-epic/cli
```

## Repositories

*   **[epic](https://github.com/epic-sec/epic)** — Core CLI, compiler-model layout diffing engine, and GitHub Action integration.
*   **[epic-web](https://github.com/epic-sec/epic-web)** — Dashboard interface for tracking upgrade history and deployment readiness metrics.

## Roadmap

*   [ ] IDL-based layout drift and state migration validation
*   [ ] Interactive CLI layout visualization and diffing tools
*   [ ] Local editor LSP diagnostics for real-time layout feedback
*   [ ] Automated state migration helper generation

## Contributing

Review the contribution guidelines in the core repository to get started.

---

*EPIC is open-source developer tooling licensed under the MIT License.*
