use crate::rules::{RuleDiagnostic, RuleSeverity};
use serde_json::{json, Value};

pub fn generate_sarif(diagnostics: &[RuleDiagnostic]) -> String {
    let rules = vec![
        json!({
            "id": "EPIC-SEC-001",
            "name": "MissingOwnerCheck",
            "shortDescription": { "text": "Missing Program Owner Verification" },
            "fullDescription": { "text": "Mutable state or operations rely on account data without checking the owning program." },
            "defaultConfiguration": { "level": "error" }
        }),
        json!({
            "id": "EPIC-SEC-002",
            "name": "MissingSignerCheck",
            "shortDescription": { "text": "Missing Signer Verification" },
            "fullDescription": { "text": "Privileged instructions mutating state must ensure the authority-like account signed the transaction." },
            "defaultConfiguration": { "level": "error" }
        }),
        json!({
            "id": "EPIC-SEC-003",
            "name": "StaleStateAfterCPI",
            "shortDescription": { "text": "Stale State After CPI" },
            "fullDescription": { "text": "Accounts passed to a CPI might be mutated by the callee. Reading from them directly afterwards without reloading can lead to using stale data." },
            "defaultConfiguration": { "level": "error" }
        }),
        json!({
            "id": "EPIC-SEC-004",
            "name": "PdaSeedCollision",
            "shortDescription": { "text": "PDA Seed Collision" },
            "fullDescription": { "text": "PDA derivations with ambiguous or colliding seeds." },
            "defaultConfiguration": { "level": "error" }
        }),
        json!({
            "id": "EPIC-SEC-005",
            "name": "ArbitraryCpiTarget",
            "shortDescription": { "text": "Arbitrary CPI Target Program Validation" },
            "fullDescription": { "text": "CPI calls must validate the target program statically or imperatively." },
            "defaultConfiguration": { "level": "error" }
        }),
        json!({
            "id": "EPIC-SEC-009",
            "name": "MissingMintConstraint",
            "shortDescription": { "text": "Missing Mint Constraint" },
            "fullDescription": { "text": "Token accounts missing a declarative `mint` constraint could be injected with malicious tokens." },
            "defaultConfiguration": { "level": "error" }
        }),
        json!({
            "id": "EPIC-SEC-010",
            "name": "MissingAuthorityConstraint",
            "shortDescription": { "text": "Missing Authority Constraint" },
            "fullDescription": { "text": "Token accounts missing an `authority` constraint could be owned by an attacker." },
            "defaultConfiguration": { "level": "error" }
        }),
    ];

    let results: Vec<Value> = diagnostics
        .iter()
        .map(|d| {
            let level = match d.severity {
                RuleSeverity::Critical | RuleSeverity::High => "error",
                RuleSeverity::Medium | RuleSeverity::Warning => "warning",
            };

            // Calculate startLine ensuring it is >= 1 as required by SARIF
            let start_line = if d.location.line == 0 { 1 } else { d.location.line };

            let mut result = json!({
                "ruleId": d.rule_id,
                "level": level,
                "message": {
                    "text": d.message
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": d.location.file
                            },
                            "region": {
                                "startLine": start_line,
                                "startColumn": if d.location.column == 0 { 1 } else { d.location.column }
                            }
                        }
                    }
                ]
            });

            // Witness path -> a single-threadFlow codeFlow: the concrete
            // control-flow steps from entry to the flagged location that
            // bypass the (non-dominating or missing) check.
            if let Some(witness) = &d.witness {
                if !witness.path.is_empty() {
                    let flow_locations: Vec<Value> = witness
                        .path
                        .iter()
                        .map(|step| {
                            let line = if step.line == 0 { 1 } else { step.line };
                            json!({
                                "location": {
                                    "physicalLocation": {
                                        "artifactLocation": { "uri": d.location.file },
                                        "region": { "startLine": line }
                                    },
                                    "message": { "text": step.label }
                                }
                            })
                        })
                        .collect();
                    result["codeFlows"] = json!([
                        { "threadFlows": [ { "locations": flow_locations } ] }
                    ]);
                }
            }

            result
        })
        .collect();

    let sarif = json!({
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "EPIC Engine",
                        "informationUri": "https://github.com/epic-sec/epic",
                        "semanticVersion": env!("CARGO_PKG_VERSION"),
                        "rules": rules
                    }
                },
                "results": results
            }
        ]
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".to_string())
}
