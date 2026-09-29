use crate::cfg::guards::{FactConfidence, GuardFact};
use crate::rules::{AnalysisContext, FindingLocation, Rule, RuleDiagnostic, RuleSeverity};

pub struct TokenMintRule;

impl Rule for TokenMintRule {
    fn id(&self) -> &'static str {
        "EPIC-SEC-009"
    }

    fn name(&self) -> &'static str {
        "Arbitrary Token Account (Missing Mint Constraint)"
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
            for field in &s_def.fields {
                let ty_str = format!("{:?}", field.type_ref);
                if ty_str.contains("TokenAccount")
                    || ty_str.contains("Account<'info, TokenAccount>")
                {
                    let field_sym = instruction_context.symbol_table.get(&field.name);
                    if let Some(&field_sym) = field_sym {
                        let mut has_mint = false;
                        for attr in &field.attrs {
                            if attr.contains("mint =")
                                || attr.contains("token::mint")
                                || (attr.contains("constraint") && attr.contains("mint"))
                                || attr.contains("address")
                                || (attr.contains("constraint") && attr.contains("key"))
                            {
                                has_mint = true;
                                break;
                            }
                        }

                        if !has_mint {
                            for other_field in &s_def.fields {
                                for attr in &other_field.attrs {
                                    if attr
                                        .replace(" ", "")
                                        .contains(&format!("has_one={}", field.name))
                                    {
                                        has_mint = true;
                                        break;
                                    }
                                }
                            }
                        }

                        if !has_mint {
                            for (fact, _) in &instruction_context.guard_facts {
                                if let GuardFact::PDA { account, .. } = fact {
                                    if account.symbol_id() == Some(field_sym) {
                                        has_mint = true;
                                    }
                                }
                            }
                        }

                        if !has_mint {
                            diagnostics.push(RuleDiagnostic {
                                rule_id: self.id().to_string(),
                                severity: RuleSeverity::High,
                                message: format!(
                                    "Token account '{}' lacks mint validation constraint.",
                                    field.name
                                ),
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
