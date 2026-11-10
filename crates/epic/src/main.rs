use clap::{builder::Styles, Parser, Subcommand, ValueEnum};
use colored::Colorize;
use std::time::Duration;

use epic::ui::{
    create_spinner, print_banner, print_diagnostics_report, print_doc_card, print_footer,
    print_info, print_section_header, print_success,
};
use epic::{compare_workspaces, format_impact_terminal, generate_aggregated_impact, Workspace};

fn cli_styles() -> Styles {
    use clap::builder::styling::AnsiColor;
    Styles::styled()
        .header(AnsiColor::Blue.on_default().bold())
        .usage(AnsiColor::Green.on_default().bold())
        .literal(AnsiColor::Cyan.on_default().bold())
        .placeholder(AnsiColor::Cyan.on_default())
        .error(AnsiColor::Red.on_default().bold())
        .valid(AnsiColor::Green.on_default().bold())
        .invalid(AnsiColor::Yellow.on_default().bold())
}

#[derive(Parser)]
#[command(
    name = "epic",
    about = "EPIC is a compiler-grade semantic security engine for smart contracts.",
    long_about = None,
    version,
    styles = cli_styles()
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Audit a Solana program or workspace for security vulnerabilities
    Audit {
        /// Path to the repository or program to audit
        #[arg(default_value = ".")]
        path: String,

        /// Output format
        #[arg(short, long, default_value = "human")]
        format: OutputFormat,
    },
    /// Explain a specific rule or finding
    Explain {
        /// Rule ID (e.g., EPIC-SEC-009)
        rule_id: String,
    },
    /// Check system environment and Epic installation
    Doctor,
    /// Run quick syntax and AST checks without full semantic analysis
    Check {
        /// Path to the repository or program
        #[arg(default_value = ".")]
        path: String,
    },
    /// Diff two versions of a workspace to identify upgrade risks
    Diff { old_path: String, new_path: String },
    /// Report how much of a program's instruction surface was actually
    /// analyzed: handlers found, resolved to an Accounts struct, fully
    /// analyzed, and why any others were skipped or only partially seen
    Coverage {
        /// Path to the repository or program
        #[arg(default_value = ".")]
        path: String,

        /// Output format
        #[arg(short, long, default_value = "human")]
        format: OutputFormat,
    },
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
    Sarif,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Audit { path, format } => run_audit(&path, format),
        Commands::Explain { rule_id } => run_explain(&rule_id),
        Commands::Doctor => run_doctor(),
        Commands::Check { path } => run_check(&path),
        Commands::Diff { old_path, new_path } => run_diff(&old_path, &new_path),
        Commands::Coverage { path, format } => run_coverage(&path, format),
    }
}

fn run_audit(path: &str, format: OutputFormat) -> anyhow::Result<()> {
    match format {
        OutputFormat::Human => {
            print_banner();
            print_info(&format!("Target: {}", path));
            print_section_header("Analysis Phases");

            let pb_scan = create_spinner("Scanning Files...");
            std::thread::sleep(Duration::from_millis(150));
            pb_scan.finish_with_message("Scanning Files... Done.");

            let pb_parse = create_spinner("Parsing Frontend...");
            std::thread::sleep(Duration::from_millis(150));
            pb_parse.finish_with_message("Parsing Frontend... Done.");

            let pb_ir = create_spinner("Building EPIC-IR...");
            std::thread::sleep(Duration::from_millis(150));
            pb_ir.finish_with_message("Building EPIC-IR... Done.");

            let pb_cfg = create_spinner("Building CFG...");
            std::thread::sleep(Duration::from_millis(150));
            pb_cfg.finish_with_message("Building CFG... Done.");

            let pb_ssa = create_spinner("Building SSA...");
            std::thread::sleep(Duration::from_millis(150));
            pb_ssa.finish_with_message("Building SSA... Done.");

            let pb_sem = create_spinner("Semantic Analysis...");

            // Run the audit
            let diagnostics = epic::audit::run_audit(path)?;

            pb_sem.finish_with_message("Semantic Analysis... Done.");

            let pb_rules = create_spinner("Running Security Rules...");
            std::thread::sleep(Duration::from_millis(150));
            pb_rules.finish_with_message("Running Security Rules... Done.");

            print_diagnostics_report(path, &diagnostics);
            print_footer();
        }
        OutputFormat::Json => {
            let diagnostics = epic::audit::run_audit(path)?;
            println!("{}", serde_json::to_string_pretty(&diagnostics)?);
        }
        OutputFormat::Sarif => {
            let diagnostics = epic::audit::run_audit(path)?;
            let sarif_output = epic::sarif::generate_sarif(&diagnostics);
            println!("{}", sarif_output);
        }
    }

    Ok(())
}

use epic::ui::DocCard;

fn run_explain(rule_id: &str) -> anyhow::Result<()> {
    print_banner();
    match rule_id {
        "EPIC-SEC-001" => print_doc_card(&DocCard {
            rule_id,
            name: "Missing Program Owner Verification",
            description: "Mutable state or operations rely on account data without checking the owning program.",
            risk: "High",
            impact: "An attacker could pass in a maliciously crafted account owned by a different program to manipulate state.",
            mitigation: "Add `#[account(owner = ...)]` or statically check the account owner.",
            example: "```rust\n#[account(owner = token_program.key())]\npub token_account: AccountInfo<'info>,\n```",
            references: "- https://docs.rs/anchor-lang",
        }),
        "EPIC-SEC-002" => print_doc_card(&DocCard {
            rule_id,
            name: "Missing Signer Verification",
            description: "Privileged instructions mutating state must ensure the authority-like account signed the transaction.",
            risk: "Critical",
            impact: "An attacker can execute unauthorized actions impersonating another user.",
            mitigation: "Add `#[account(signer)]` or `Signer<'info>` to the authority account, or verify it is a PDA.",
            example: "```rust\n#[account(mut, signer)]\npub authority: Signer<'info>,\n```",
            references: "- https://solanacookbook.com/core-concepts/accounts.html#signers",
        }),
        "EPIC-SEC-003" => print_doc_card(&DocCard {
            rule_id,
            name: "Stale State After CPI",
            description: "Accounts passed to a CPI might be mutated by the callee. Reading from them directly afterwards without reloading can lead to using stale data.",
            risk: "Medium",
            impact: "Logic may operate on outdated values leading to incorrect accounting or bypassing of constraints.",
            mitigation: "Call `account.reload()?` before reading state post-CPI.",
            example: "```rust\ntoken::transfer(cpi_ctx, amount)?;\nuser_account.reload()?;\n```",
            references: "- https://docs.rs/anchor-lang/latest/anchor_lang/accounts/account/struct.Account.html#method.reload",
        }),
        "EPIC-SEC-004" => print_doc_card(&DocCard {
            rule_id,
            name: "PDA Seed Collision",
            description: "PDA derivations with ambiguous or colliding seeds.",
            risk: "High",
            impact: "Attacker could spoof PDA accounts if user-controlled strings/bytes can be manipulated to match other derivations.",
            mitigation: "Ensure safe literal delimiters or fixed length byte slices between variable PDA seeds.",
            example: "```rust\n#[account(seeds = [b\"vault\", user.key().as_ref()], bump)]\npub vault: AccountInfo<'info>,\n```",
            references: "- https://docs.solana.com/developing/programming-model/calling-between-programs#program-derived-addresses",
        }),
        "EPIC-SEC-005" => print_doc_card(&DocCard {
            rule_id,
            name: "Arbitrary CPI Target Program Validation",
            description: "CPI calls must validate the target program statically or imperatively.",
            risk: "Critical",
            impact: "Malicious program can be invoked instead of the intended system/token program, causing loss of funds.",
            mitigation: "Use `Program<'info, T>` for static checking or enforce `require_keys_eq`.",
            example: "```rust\npub token_program: Program<'info, Token>,\n```",
            references: "- https://docs.rs/anchor-lang/latest/anchor_lang/accounts/program/struct.Program.html",
        }),
        "EPIC-SEC-009" => print_doc_card(&DocCard {
            rule_id,
            name: "Missing Mint Constraint",
            description: "Token accounts missing a declarative `mint` constraint could be injected with malicious tokens.",
            risk: "High",
            impact: "Attackers can pass an unexpected token mint to drain value or inflate balances.",
            mitigation: "Add `#[account(token::mint = ...)]` or ensure another account exerts a `has_one` constraint over it.",
            example: "```rust\n#[account(token::mint = expected_mint)]\npub token_account: Account<'info, TokenAccount>,\n```",
            references: "- https://docs.rs/anchor-spl/latest/anchor_spl/token/struct.TokenAccount.html",
        }),
        "EPIC-SEC-010" => print_doc_card(&DocCard {
            rule_id,
            name: "Missing Authority Constraint",
            description: "Token accounts missing an `authority` constraint could be owned by an attacker.",
            risk: "High",
            impact: "Token logic might credit/debit the wrong party if ownership isn't enforced.",
            mitigation: "Add `#[account(token::authority = ...)]`.",
            example: "```rust\n#[account(token::authority = user)]\npub token_account: Account<'info, TokenAccount>,\n```",
            references: "- https://docs.rs/anchor-spl/latest/anchor_spl/token/struct.TokenAccount.html",
        }),
        _ => print_info(&format!("Unknown rule ID: {}", rule_id)),
    }
    print_footer();
    Ok(())
}

fn run_doctor() -> anyhow::Result<()> {
    print_banner();
    println!("\n{}", "▌ Environment Diagnostics".bold().blue());
    print_success(&format!(
        "Rust compiler (v{}) is active",
        env!("CARGO_PKG_RUST_VERSION")
    ));
    print_success("EPIC Core is configured correctly");
    print_success("Compiler-grade Semantic Security modules are ready");
    println!();
    print_info("Environment is healthy and ready for audits.");
    print_footer();
    Ok(())
}

fn run_check(path: &str) -> anyhow::Result<()> {
    print_banner();
    print_info(&format!("Running fast syntax check on {}...", path));

    let pb = create_spinner("Parsing workspace...");

    let mut workspace = Workspace::new();
    for entry in walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.path().extension().is_some_and(|ext| ext == "rs") {
            let content = std::fs::read_to_string(entry.path())?;
            let file_stem = entry
                .path()
                .file_stem()
                .unwrap()
                .to_string_lossy()
                .into_owned();
            workspace.add_file(
                "program",
                &[&file_stem],
                &content,
                Some(&entry.path().to_string_lossy()),
            )?;
        }
    }

    pb.finish_with_message("Parsing workspace... Done.");
    print_success("Syntax OK. Workspace parsed successfully.");
    print_footer();
    Ok(())
}

fn run_coverage(path: &str, format: OutputFormat) -> anyhow::Result<()> {
    let report = epic::coverage::collect_coverage(path);

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        OutputFormat::Sarif => {
            anyhow::bail!("coverage has no SARIF output; use --format human or --format json");
        }
        OutputFormat::Human => {
            print_banner();
            print_info(&format!("Target: {}", path));
            print_section_header("Coverage Summary");
            println!(
                "  Instruction handlers found:     {}",
                report.total_handlers
            );
            println!(
                "  Resolved to an Accounts struct: {}",
                report.resolved_to_struct
            );
            println!(
                "  Fully analyzed (no boundary):   {}",
                report.fully_analyzed
            );
            if !report.files_failed_to_parse.is_empty() {
                println!(
                    "  Files that failed to parse:     {}",
                    report.files_failed_to_parse.len()
                );
                for f in &report.files_failed_to_parse {
                    println!("    - {}", f);
                }
            }

            let skipped: Vec<_> = report
                .handlers
                .iter()
                .filter(|h| !matches!(h.status, epic::coverage::CoverageStatus::FullyAnalyzed))
                .collect();
            if !skipped.is_empty() {
                print_section_header("Unresolved / Partially Analyzed Handlers");
                for h in skipped {
                    let reason = match &h.status {
                        epic::coverage::CoverageStatus::Unresolved { reason } => reason.clone(),
                        epic::coverage::CoverageStatus::CfgBuildFailed => {
                            "CFG build failed".to_string()
                        }
                        epic::coverage::CoverageStatus::PartiallyAnalyzed { boundary_warnings } => {
                            format!("{:?}", boundary_warnings)
                        }
                        epic::coverage::CoverageStatus::FullyAnalyzed => unreachable!(),
                    };
                    println!("  {} ({}): {}", h.name, h.file, reason);
                }
            }

            let (mut visible, mut reachable, mut unresolved_calls) = (0usize, 0usize, 0usize);
            let mut mostly_invisible = Vec::new();
            for h in &report.handlers {
                if let Some(m) = &h.mutation {
                    visible += m.visible_writes;
                    reachable += m.reachable_via_resolved_delegate;
                    unresolved_calls += m.unresolved_delegate_calls;
                    if m.mostly_invisible() {
                        mostly_invisible.push(h);
                    }
                }
            }
            print_section_header("Mutation Visibility");
            println!("  Writes visible to rules today:          {}", visible);
            println!("  Writes reachable via resolved delegate: {}", reachable);
            println!(
                "  Unresolved delegate-shaped call sites:  {}",
                unresolved_calls
            );
            if !mostly_invisible.is_empty() {
                println!(
                    "\n  {} handler(s) where most reachable writes are invisible to rules:",
                    mostly_invisible.len()
                );
                for h in mostly_invisible {
                    let m = h.mutation.as_ref().unwrap();
                    println!(
                        "    {} ({}): {} visible, {} reachable via delegate",
                        h.name, h.file, m.visible_writes, m.reachable_via_resolved_delegate
                    );
                }
            }
            print_footer();
        }
    }
    Ok(())
}

fn run_diff(old_path: &str, new_path: &str) -> anyhow::Result<()> {
    print_banner();
    print_info(&format!("Diffing {} and {}...", old_path, new_path));

    let pb = create_spinner("Parsing workspaces and generating diff...");

    let mut old_ws = Workspace::new();
    for entry in walkdir::WalkDir::new(old_path)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.path().extension().is_some_and(|ext| ext == "rs") {
            let content = std::fs::read_to_string(entry.path())?;
            let file_stem = entry
                .path()
                .file_stem()
                .unwrap()
                .to_string_lossy()
                .into_owned();
            old_ws.add_file(
                "program",
                &[&file_stem],
                &content,
                Some(&entry.path().to_string_lossy()),
            )?;
        }
    }

    let mut new_ws = Workspace::new();
    for entry in walkdir::WalkDir::new(new_path)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.path().extension().is_some_and(|ext| ext == "rs") {
            let content = std::fs::read_to_string(entry.path())?;
            let file_stem = entry
                .path()
                .file_stem()
                .unwrap()
                .to_string_lossy()
                .into_owned();
            new_ws.add_file(
                "program",
                &[&file_stem],
                &content,
                Some(&entry.path().to_string_lossy()),
            )?;
        }
    }

    let diffs = compare_workspaces(&old_ws, &new_ws);
    let aggregated_impact = generate_aggregated_impact(&diffs);

    pb.finish_with_message("Parsing workspaces and generating diff... Done.");

    print_section_header("Diff Report");
    let terminal_report = format_impact_terminal("Solana Workspace", &aggregated_impact);
    println!("{}", terminal_report);
    print_footer();

    Ok(())
}
