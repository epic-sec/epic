# False Positive Policy

At Solana EPIC, we prioritize **Zero False Positives**. 

Static analyzers are notoriously noisy. A security tool that developers ignore is a useless tool. EPIC's design philosophy mandates that if the engine emits a warning, it represents a genuine vulnerability, a high-risk code smell, or a direct violation of Anchor best practices.

## Handling False Positives
If you encounter a finding that you believe is a false positive:
1. **Verify Context**: Double check that there are no edge cases where the vulnerability might still be exploitable (e.g. cross-program invocations mutating state unexpectedly).
2. **Report Issue**: Open an issue on our GitHub repository with the code snippet that triggered the false positive.
3. **Internal Resolution**: We will prioritize addressing the false positive in the compiler's semantic tree mapping or control flow graph to ensure the engine correctly tracks the invariants.

*We explicitly forbid adding `.epicignore` or whitelist features to bypass findings. The engine must understand the safe code pattern natively.*
