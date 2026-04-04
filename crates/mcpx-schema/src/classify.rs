/// Re-export diff types — classification is embedded in the diff engine.
/// This module provides policy-level interpretation of diffs.
pub use crate::diff::{DiffReport, Severity};

/// Summarize a diff report as a human-readable string.
pub fn summarize(report: &DiffReport) -> String {
    if report.diffs.is_empty() {
        return format!("[mcpx] [{}] no schema changes detected.", report.server_name);
    }

    let breaking = report.diffs.iter().filter(|d| d.severity == Severity::Breaking).count();
    let warnings = report.diffs.iter().filter(|d| d.severity == Severity::Warning).count();
    let safe = report.diffs.iter().filter(|d| d.severity == Severity::Safe).count();

    let mut lines = vec![
        "[mcpx] --------------------------------------------------".to_string(),
        format!("[mcpx] Schema drift detected for '{}'", report.server_name),
        format!(
            "[mcpx] Total: {} | Breaking: {} | Warning: {} | Safe: {}",
            report.diffs.len(),
            breaking,
            warnings,
            safe
        ),
        "[mcpx] Changes:".to_string(),
    ];

    for diff in &report.diffs {
        let sev = match diff.severity {
            Severity::Breaking => "BREAKING",
            Severity::Warning => "WARNING",
            Severity::Safe => "SAFE",
        };
        lines.push(format!(
            "[mcpx] - [{}] {}",
            sev,
            diff.explanation
        ));
    }
    lines.push("[mcpx] --------------------------------------------------".to_string());

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use crate::diff::{DiffKind, DiffReport, SchemaDiff, Severity};

    #[test]
    fn summarize_no_changes() {
        let report = DiffReport {
            server_name: "demo".into(),
            diffs: vec![],
            max_severity: Severity::Safe,
        };
        let out = super::summarize(&report);
        assert!(out.contains("no schema changes detected"));
    }

    #[test]
    fn summarize_counts_and_lines() {
        let report = DiffReport {
            server_name: "demo".into(),
            diffs: vec![
                SchemaDiff {
                    tool_name: "t1".into(),
                    field_path: "description".into(),
                    severity: Severity::Warning,
                    kind: DiffKind::DescriptionChanged,
                    old_value: Some("old".into()),
                    new_value: Some("new".into()),
                    explanation: "desc changed".into(),
                },
                SchemaDiff {
                    tool_name: "t1".into(),
                    field_path: "properties.q".into(),
                    severity: Severity::Breaking,
                    kind: DiffKind::ParameterRemoved { was_required: true },
                    old_value: Some("q".into()),
                    new_value: None,
                    explanation: "param removed".into(),
                },
            ],
            max_severity: Severity::Breaking,
        };

        let out = super::summarize(&report);
        assert!(out.contains("Total: 2 | Breaking: 1 | Warning: 1 | Safe: 0"));
        assert!(out.contains("[WARNING] desc changed"));
        assert!(out.contains("[BREAKING] param removed"));
    }
}
