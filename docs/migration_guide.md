# Migration Guide: NPM to Rust CLI

The EPIC Semantic Engine has been rewritten from TypeScript to pure Rust to dramatically improve performance, security, and developer experience.

## Uninstalling the Legacy NPM Package
If you previously installed EPIC via npm, you must uninstall it to prevent conflicts:

```bash
npm uninstall -g @solana-epic/cli
```

## Installing the New Rust Binary
Install the new Rust version via Cargo:

```bash
cargo install epic
```
*(For pre-compiled binaries, check the GitHub Releases page).*

## Command Changes
The new CLI offers a streamlined, developer-first experience.

### Auditing
**Old (TypeScript):**
```bash
epic-cli analyze ./my-program
```

**New (Rust):**
```bash
epic audit ./my-program
```
*(You can also use `epic audit . --format sarif` for GitHub Code Scanning integration).*

### Diffing Workspaces
**Old (TypeScript):**
```bash
epic-cli diff ./v1 ./v2
```

**New (Rust):**
```bash
epic diff ./v1 ./v2
```

## GitHub Actions Migration
If you use the EPIC GitHub Action, update your workflow from using the Node-based version to the new composite action:

**`.github/workflows/epic.yml`**
```yaml
name: Security Audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run EPIC
        uses: epic-sec/epic/github-action@main
        with:
          path: '.'
          format: 'sarif'
```
