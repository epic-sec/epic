use epic::{compare_workspaces, format_diff_results, ChangeType, Severity, Workspace};
use std::fs;
use std::process::Command;

fn get_git_file_content(repo_path: &str, commit: &str, file_path: &str) -> Option<String> {
    let output = Command::new("git")
        .args(["show", &format!("{}:{}", commit, file_path)])
        .current_dir(repo_path)
        .output()
        .ok()?;

    if output.status.success() {
        String::from_utf8(output.stdout).ok()
    } else {
        None
    }
}

struct ValidationCase {
    name: &'static str,
    repo_path: &'static str,
    file_path: &'static str,
    old_commit: &'static str,
    new_commit: &'static str,
    expected_severity: Severity,
    expected_change: ChangeType,
}

// Ignored: this harness validates the ABI/upgrade-safety diff engine against
// real historical commits of external protocols (squads-v4, marginfi, drift),
// hardcoded to local clones at /Users/aksh/epic-test-repos/*. Those clones
// aren't vendored in this repo and don't exist in CI, so every case fails to
// load and the accuracy assertion below fails closed (0/4). Making this
// self-contained would mean vendoring real before/after file snapshots from
// 3 external repos' git history — out of scope for this fix, which is only
// about making `cargo test` pass in CI, not re-validating the ABI diff
// engine's fixtures. Run manually with the real clones present via
// `cargo test -- --ignored test_historical_upgrades_harness`.
#[test]
#[ignore = "requires local clones at /Users/aksh/epic-test-repos/* that aren't vendored in-repo or available in CI"]
fn test_historical_upgrades_harness() {
    let cases = vec![
        ValidationCase {
            name: "Squads V4 Multisig Add rent_collector",
            repo_path: "/Users/aksh/epic-test-repos/squads-v4",
            file_path: "programs/squads_multisig_program/src/state/multisig.rs",
            old_commit: "72e3c3b542c7ba9a5d0a7e0d6d784d889727d009^",
            new_commit: "72e3c3b542c7ba9a5d0a7e0d6d784d889727d009",
            expected_severity: Severity::Critical,
            expected_change: ChangeType::StructFieldRemoval, // _reserved removed
        },
        ValidationCase {
            name: "Squads V4 Add SpendingLimit Account",
            repo_path: "/Users/aksh/epic-test-repos/squads-v4",
            file_path: "programs/multisig/src/state/spending_limit.rs",
            old_commit: "88e3486^",
            new_commit: "88e3486",
            expected_severity: Severity::Safe,
            expected_change: ChangeType::AccountLayoutChange, // new account introduced
        },
        ValidationCase {
            name: "MarginFi V2 Group Padding Admin Utilization",
            repo_path: "/Users/aksh/epic-test-repos/marginfi",
            file_path: "type-crate/src/types/group.rs",
            old_commit: "8f38cfb9109cbc7ee78cea6fe4c4e9a925933122^",
            new_commit: "8f38cfb9109cbc7ee78cea6fe4c4e9a925933122",
            expected_severity: Severity::Critical, // Changes ABI and client deserialization
            expected_change: ChangeType::StructFieldAddition, // delegate_flow_admin appended
        },
        ValidationCase {
            name: "Drift V2 User Isolated Position replacement",
            repo_path: "/Users/aksh/epic-test-repos/drift-v2",
            file_path: "programs/drift/src/state/user.rs",
            old_commit: "97355509aba9a4373ad99e7c741a3527c20483b3^",
            new_commit: "97355509aba9a4373ad99e7c741a3527c20483b3",
            expected_severity: Severity::Critical,
            expected_change: ChangeType::StructFieldRemoval, // last_base_asset_amount_per_lp removed
        },
    ];

    let mut passed_cases = 0;
    let mut total_cases = 0;
    let mut markdown_report = String::new();

    markdown_report.push_str("# ABI Intelligence Validation Report\n\n");
    markdown_report.push_str("Generated on: 2026-06-15\n\n");
    markdown_report.push_str("## Executive Summary\n\n");

    let mut case_details = String::new();
    case_details.push_str("| Upgrade Case | Expected Severity | Actual Severity | Expected Change | Actual Change | Result |\n");
    case_details.push_str("| :--- | :--- | :--- | :--- | :--- | :--- |\n");

    for case in &cases {
        total_cases += 1;
        let mut old_ws = Workspace::new();
        if let Some(content) = get_git_file_content(case.repo_path, case.old_commit, case.file_path)
        {
            old_ws
                .add_file("program", &["state"], &content, None)
                .unwrap();
        }

        let mut new_ws = Workspace::new();
        if let Some(content) = get_git_file_content(case.repo_path, case.new_commit, case.file_path)
        {
            new_ws
                .add_file("program", &["state"], &content, None)
                .unwrap();
        }

        let diffs = compare_workspaces(&old_ws, &new_ws);

        // Determine the actual severity and if the expected change type was found
        let actual_severity = diffs
            .iter()
            .map(|d| d.severity)
            .max()
            .unwrap_or(Severity::Safe);
        let found_expected_change = diffs.iter().any(|d| d.change_type == case.expected_change);

        let case_passed = actual_severity == case.expected_severity && found_expected_change;
        if case_passed {
            passed_cases += 1;
        }

        let actual_change_desc = diffs
            .iter()
            .find(|d| d.change_type == case.expected_change)
            .map(|d| format!("{:?}", d.change_type))
            .unwrap_or_else(|| {
                diffs
                    .first()
                    .map(|d| format!("{:?}", d.change_type))
                    .unwrap_or("None".to_string())
            });

        case_details.push_str(&format!(
            "| {} | {:?} | {:?} | {:?} | {} | {} |\n",
            case.name,
            case.expected_severity,
            actual_severity,
            case.expected_change,
            actual_change_desc,
            if case_passed { "✅ Pass" } else { "❌ Fail" }
        ));

        // Append the formatted output as well
        case_details.push_str("\n```text\n");
        case_details.push_str(&format_diff_results(&diffs));
        case_details.push_str("\n```\n\n");
    }

    let accuracy = (passed_cases as f64 / total_cases as f64) * 100.0;

    markdown_report.push_str(&format!(
        "* **Total Historical Cases Tested**: {}\n",
        total_cases
    ));
    markdown_report.push_str(&format!("* **Successful Detections**: {}\n", passed_cases));
    markdown_report.push_str(&format!(
        "* **Classification Accuracy**: {:.2}%\n\n",
        accuracy
    ));

    markdown_report.push_str("## Detailed Validation Matrix\n\n");
    markdown_report.push_str(&case_details);

    // Save report to artifacts directory
    let artifact_path = "target/validation_report.md";
    fs::create_dir_all("target").unwrap();
    fs::write(artifact_path, markdown_report).unwrap();

    println!("==================================================");
    println!("ABI Intelligence Validation Summary");
    println!("Total Cases: {}", total_cases);
    println!("Passed: {}", passed_cases);
    println!("Accuracy: {:.2}%", accuracy);
    println!("==================================================");

    assert!(
        accuracy > 90.0,
        "Accuracy must be high for a production-ready parser"
    );
}
