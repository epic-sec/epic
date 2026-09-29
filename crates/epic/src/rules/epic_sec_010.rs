use crate::cfg::guards::{FactConfidence, GuardFact};
use crate::rules::{AnalysisContext, FindingLocation, Rule, RuleDiagnostic, RuleSeverity};

pub struct VaultAuthorityRule;

impl Rule for VaultAuthorityRule {
    fn id(&self) -> &'static str {
        "EPIC-SEC-010"
    }

    fn name(&self) -> &'static str {
        "Missing Vault Authority Constraint"
    }

    fn check(&self, context: &AnalysisContext) -> Vec<RuleDiagnostic> {
        let mut diagnostics = Vec::new();
        let instruction_context = &context.instruction_context;
        let struct_name = &instruction_context.context_struct_name;

        let struct_match = crate::audit::find_struct_for_context(
            &context.ast_graph.registry,
            struct_name,
            &instruction_context.file_path,
        );
        let (struct_path, s_def) = match struct_match {
            Some(pair) => pair,
            None => return diagnostics,
        };

        let file_path = context
            .ast_graph
            .registry
            .file_paths
            .get(struct_path)
            .cloned()
            .unwrap_or_else(|| instruction_context.file_path.clone());
        {
            // Find all vault fields
            for field in &s_def.fields {
                let ty_str = format!("{:?}", field.type_ref);
                if (ty_str.contains("TokenAccount")
                    || ty_str.contains("Account<'info, TokenAccount>")
                    || ty_str.contains("Account<'info, token::TokenAccount>"))
                    && (field.name.contains("vault") || field.name.contains("pool"))
                {
                    let field_sym = instruction_context.symbol_table.get(&field.name);
                    if let Some(&field_sym) = field_sym {
                        let mut has_auth = false;

                        for attr in &field.attrs {
                            if attr.contains("authority =")
                                || attr.contains("token::authority")
                                || attr.contains("address")
                                || (attr.contains("constraint")
                                    && (attr.contains("authority")
                                        || attr.contains("key")
                                        || attr.contains("vault")))
                            {
                                has_auth = true;
                                break;
                            }
                        }

                        if !has_auth {
                            for other_field in &s_def.fields {
                                for attr in &other_field.attrs {
                                    if attr
                                        .replace(" ", "")
                                        .contains(&format!("has_one={}", field.name))
                                    {
                                        has_auth = true;
                                        break;
                                    }
                                }
                            }
                        }

                        if !has_auth {
                            for (fact, _) in &instruction_context.guard_facts {
                                if let GuardFact::PDA { account, .. } = fact {
                                    if account.symbol_id() == Some(field_sym) {
                                        has_auth = true;
                                    }
                                }
                            }
                        }

                        if !has_auth {
                            diagnostics.push(RuleDiagnostic {
                                rule_id: self.id().to_string(),
                                severity: RuleSeverity::High,
                                message: format!("Vault token account '{}' lacks authority validation constraint.", field.name),
                                location: FindingLocation {
                                    file: file_path.clone(),
                                    line: field.line_number,
                                    column: field.column_number,
                                    node_id: 0,
                                    statement_index: None,
                                },
                                confidence: FactConfidence::Asserted,
                                target_symbol: field_sym,
                                witness: None,
                            });
                        }
                    }
                }
            }
        }

        diagnostics
    }
}
