use crate::cfg::guards::{FactConfidence, GuardFact};
use crate::rules::{AnalysisContext, FindingLocation, Rule, RuleDiagnostic, RuleSeverity};

pub struct TokenAccountRule;

impl Rule for TokenAccountRule {
    fn id(&self) -> &'static str {
        "EPIC-SEC-TOKEN"
    }

    fn name(&self) -> &'static str {
        "Missing Token Account Constraints"
    }

    fn check(&self, context: &AnalysisContext) -> Vec<RuleDiagnostic> {
        let mut diagnostics = Vec::new();
        let instruction_context = &context.instruction_context;
        let struct_name = &instruction_context.context_struct_name;

        // Use find_struct_for_context for correct, deterministic disambiguation when
        // multiple structs share the same bare name across different modules.
        let struct_match = crate::audit::find_struct_for_context(
            &context.ast_graph.registry,
            struct_name,
            &instruction_context.file_path,
        );
        let (struct_path, struct_def) = match struct_match {
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

        // struct_def is already &StructDef from find_struct_for_context
        let s_def = struct_def;
        {
            for field in &s_def.fields {
                let ty_str = format!("{:?}", field.type_ref);

                if ty_str.contains("TokenAccount")
                    || ty_str.contains("Account<'info, TokenAccount>")
                    || ty_str.contains("Account<'info, token::TokenAccount>")
                {
                    let field_sym = instruction_context.symbol_table.get(&field.name);
                    if let Some(&field_sym) = field_sym {
                        let mut has_mint = false;
                        let mut has_authority = false;

                        for attr in &field.attrs {
                            if attr.contains("mint =")
                                || attr.contains("token::mint")
                                || (attr.contains("constraint") && attr.contains("mint"))
                                || attr.contains("address")
                                || (attr.contains("constraint") && attr.contains("key"))
                            {
                                has_mint = true;
                            }
                            
                            if attr.contains("authority =")
                                || attr.contains("token::authority")
                                || attr.contains("address")
                                || (attr.contains("constraint")
                                    && (attr.contains("authority")
                                        || attr.contains("key")
                                        || attr.contains("vault")))
                            {
                                has_authority = true;
                            }
                        }

                        // Check has_one relationships
                        for other_field in &s_def.fields {
                            for attr in &other_field.attrs {
                                if attr
                                    .replace(" ", "")
                                    .contains(&format!("has_one={}", field.name))
                                {
                                    has_mint = true;
                                    has_authority = true;
                                }
                            }
                        }

                        // Check guard facts for PDA
                        for (fact, _) in &instruction_context.guard_facts {
                            if let GuardFact::PDA { account, .. } = fact {
                                if account.symbol_id() == Some(field_sym) {
                                    has_mint = true;
                                    has_authority = true;
                                }
                            }
                        }

                        if !has_mint && !has_authority {
                            diagnostics.push(RuleDiagnostic {
                                rule_id: self.id().to_string(),
                                severity: RuleSeverity::High,
                                message: format!("Token account '{}' missing both mint and authority constraints", field.name),
                                location: FindingLocation {
                                    file: file_path.clone(),
                                    line: field.line_number,
                                    column: field.column_number,
                                    node_id: 0,
                                    statement_index: None,
                                },
                                confidence: FactConfidence::Asserted,
                                target_symbol: field_sym,
                            });
                        } else if !has_mint {
                            diagnostics.push(RuleDiagnostic {
                                rule_id: self.id().to_string(),
                                severity: RuleSeverity::High,
                                message: format!("Token account '{}' missing mint constraint", field.name),
                                location: FindingLocation {
                                    file: file_path.clone(),
                                    line: field.line_number,
                                    column: field.column_number,
                                    node_id: 0,
                                    statement_index: None,
                                },
                                confidence: FactConfidence::Asserted,
                                target_symbol: field_sym,
                            });
                        } else if !has_authority {
                            diagnostics.push(RuleDiagnostic {
                                rule_id: self.id().to_string(),
                                severity: RuleSeverity::Medium,
                                message: format!("Token account '{}' missing authority constraint", field.name),
                                location: FindingLocation {
                                    file: file_path.clone(),
                                    line: field.line_number,
                                    column: field.column_number,
                                    node_id: 0,
                                    statement_index: None,
                                },
                                confidence: FactConfidence::Asserted,
                                target_symbol: field_sym,
                            });
                        }
                    }
                }
            }
        }

        diagnostics
    }
}
