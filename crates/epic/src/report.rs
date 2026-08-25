use crate::abi::AbiEngine;
use crate::layout::LayoutEngine;
use crate::types::{TypeDef, TypeRegistry};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountReport {
    pub account: String,
    pub namespace: String,
    pub size: usize,
    pub fingerprint: String,
    pub dynamic: bool,
    pub risk: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EpicReport {
    pub accounts: Vec<AccountReport>,
    pub structs_found: usize,
    pub enums_found: usize,
    pub aliases_found: usize,
}

pub fn generate_report(registry: &TypeRegistry) -> anyhow::Result<EpicReport> {
    let mut layout_engine = LayoutEngine::new(registry);
    let mut abi_engine = AbiEngine::new(registry);

    let mut reports = Vec::new();
    let mut structs_found = 0;
    let mut enums_found = 0;
    let mut aliases_found = 0;

    // Sort definitions by key for deterministic report ordering.
    let mut sorted_defs: Vec<(&String, &TypeDef)> = registry.definitions.iter().collect();
    sorted_defs.sort_by_key(|(k, _)| k.as_str());

    for (abs_path, def) in sorted_defs {
        match def {
            TypeDef::Struct(s) => {
                structs_found += 1;
                if s.is_account {
                    let layout = layout_engine.size_of_absolute_path(abs_path)?;
                    let fingerprint = abi_engine.hash_of_absolute_path(abs_path)?;

                    let namespace = if let Some(idx) = abs_path.rfind("::") {
                        abs_path[..idx].to_string()
                    } else {
                        "".to_string()
                    };

                    reports.push(AccountReport {
                        account: s.name.clone(),
                        namespace,
                        size: layout.size,
                        fingerprint,
                        dynamic: layout.dynamic,
                        risk: "None".to_string(), // Risk is properly assessed during diffing.
                    });
                }
            }
            TypeDef::Enum(_) => enums_found += 1,
            TypeDef::Alias(_) => aliases_found += 1,
            TypeDef::Instruction(_) => {} // Ignore for account report
        }
    }

    Ok(EpicReport {
        accounts: reports,
        structs_found,
        enums_found,
        aliases_found,
    })
}
