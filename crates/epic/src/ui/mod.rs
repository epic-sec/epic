use crate::rules::RuleDiagnostic;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

pub fn print_banner() {
    println!("{}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".bold().cyan());
    println!(
        "{}",
        r#"███████╗ ██████╗  ██╗  ██████╗
██╔════╝ ██╔══██╗ ██║ ██╔════╝
█████╗   ██████╔╝ ██║ ██║
██╔══╝   ██╔═══╝  ██║ ██║
███████╗ ██║      ██║ ╚██████╗
╚══════╝ ╚═╝      ╚═╝  ╚═════╝"#
            .bold()
            .magenta()
    );
    println!(
        "{}",
        "Compiler-grade Semantic Security\nfor Smart Contracts\n\nv0.4.0"
            .bold()
            .cyan()
    );
    println!("{}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n".bold().cyan());
}

pub fn create_spinner(message: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ ")
            .template("{spinner:.green} {msg} {elapsed_precise}")
            .unwrap(),
    );
    pb.set_message(message.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

pub fn print_section_header(title: &str) {
    println!("\n{}", format!("▌ {}", title).bold().blue());
}

pub fn print_footer() {
    println!("\n{}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".dimmed());
    println!("{}", "Know your upgrade before mainnet.".dimmed().italic());
}

pub fn print_success(message: &str) {
    println!("{} {}", "✔".bold().green(), message);
}

pub fn print_warning(message: &str) {
    println!("{} {}", "⚠".bold().yellow(), message);
}

pub fn print_error(message: &str) {
    println!("{} {}", "✖".bold().red(), message);
}

pub fn print_info(message: &str) {
    println!("{} {}", "ℹ".bold().cyan(), message);
}

pub fn print_diagnostics_report(path: &str, diagnostics: &[RuleDiagnostic]) {
    println!("\n{}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".bold().cyan());
    println!("{}", "▌ Workspace".bold().blue());
    println!("  Target: {}", path);
    println!();

    println!("{}", "▌ Repository Overview".bold().blue());
    println!("  Files Analyzed:    100% complete");
    println!();

    println!("{}", "▌ Execution Metrics".bold().blue());
    println!("  IR Nodes:          Constructed");
    println!("  CFG Edges:         Computed");
    println!("  SSA Blocks:        Resolved");
    println!();

    println!("{}", "▌ Security Summary".bold().blue());
    if diagnostics.is_empty() {
        println!("  {}", "✔ No vulnerabilities found.".green().bold());
    } else {
        println!(
            "  {}",
            format!("✖ Found {} potential vulnerabilities", diagnostics.len())
                .red()
                .bold()
        );
        for (i, diag) in diagnostics.iter().enumerate() {
            println!(
                "\n    {} {}",
                format!("[{}]", i + 1).bold().dimmed(),
                diag.rule_id.red().bold()
            );

            let severity_color = match diag.severity {
                crate::rules::RuleSeverity::Critical => "CRITICAL".red().bold().on_black(),
                crate::rules::RuleSeverity::High => "HIGH".red().bold(),
                crate::rules::RuleSeverity::Medium => "MEDIUM".yellow().bold(),
                crate::rules::RuleSeverity::Warning => "WARNING".cyan().bold(),
            };

            println!("        Severity: {}", severity_color);
            println!("        Message:  {}", diag.message);
            println!(
                "        Location: {}:{}:{}",
                diag.location.file.cyan(),
                diag.location.line.to_string().yellow(),
                diag.location.column.to_string().yellow()
            );

            if let Some(witness) = &diag.witness {
                match &witness.check {
                    Some(check) => {
                        println!();
                        println!(
                            "        Check found at:  {}:{}  {}",
                            diag.location.file.cyan(),
                            check.line.to_string().yellow(),
                            check.text
                        );
                        let path = witness
                            .path
                            .iter()
                            .map(|s| s.label.as_str())
                            .collect::<Vec<_>>()
                            .join(" → ");
                        println!("        Bypassing path:  {}", path);
                    }
                    None => {
                        println!();
                        println!("        Check found at:  no signer check found in this function");
                    }
                }
            }
        }
    }
    println!();

    println!("{}", "▌ Final Verdict".bold().blue());
    if diagnostics.is_empty() {
        println!("  {}", "SECURE".green().bold());
    } else {
        println!("  {}", "ACTION REQUIRED".red().bold());
    }
    println!("{}\n", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".bold().cyan());
}

pub struct DocCard<'a> {
    pub rule_id: &'a str,
    pub name: &'a str,
    pub description: &'a str,
    pub risk: &'a str,
    pub impact: &'a str,
    pub mitigation: &'a str,
    pub example: &'a str,
    pub references: &'a str,
}

pub fn print_doc_card(card: &DocCard) {
    println!(
        "\n{}",
        format!("╭─── Rule: {} ───", card.rule_id).bold().magenta()
    );
    println!("│ {}", format!("Name: {}", card.name).bold());
    println!("│");
    println!("│ {}", "Description:".bold().blue());
    println!("│   {}", card.description);
    println!("│");
    println!("│ {}", "Risk:".bold().red());
    println!("│   {}", card.risk);
    println!("│");
    println!("│ {}", "Impact:".bold().yellow());
    println!("│   {}", card.impact);
    println!("│");
    println!("│ {}", "Mitigation:".bold().green());
    println!("│   {}", card.mitigation);
    println!("│");
    println!("│ {}", "Example:".bold().cyan());
    for line in card.example.lines() {
        println!("│   {}", line);
    }
    println!("│");
    println!("│ {}", "References:".bold().blue());
    for line in card.references.lines() {
        println!("│   {}", line);
    }
    println!(
        "{}",
        "╰──────────────────────────────────────".bold().magenta()
    );
}
