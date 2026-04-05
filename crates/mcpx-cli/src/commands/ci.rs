use anyhow::{anyhow, bail, Context, Result};
use mcpx_core::mcp::{ToolDefinition, ToolsListResult};
use mcpx_core::snapshot::{ServerBaseline, ToolSnapshot};
use mcpx_poison::structural;
use mcpx_schema::{diff, shim};
use mcpx_store::Store;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum FindingSeverity {
    Warning,
    Breaking,
    Blocked,
}

impl FindingSeverity {
    fn rank(self) -> u8 {
        match self {
            FindingSeverity::Warning => 1,
            FindingSeverity::Breaking => 2,
            FindingSeverity::Blocked => 3,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct CiFinding {
    id: String,
    rule_id: String,
    severity: FindingSeverity,
    category: String,
    tool_name: String,
    field_path: String,
    message: String,
    details: Value,
    source_uri: Option<String>,
    source_line: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
enum OutputFormat {
    Json,
    Sarif,
    Both,
}

#[derive(Debug, Clone, Copy)]
enum FailOn {
    Warning,
    Breaking,
    Blocked,
}

impl FailOn {
    fn threshold(self) -> u8 {
        match self {
            FailOn::Warning => FindingSeverity::Warning.rank(),
            FailOn::Breaking => FindingSeverity::Breaking.rank(),
            FailOn::Blocked => FindingSeverity::Blocked.rank(),
        }
    }
}

fn parse_format(format: &str) -> Result<OutputFormat> {
    match format {
        "json" => Ok(OutputFormat::Json),
        "sarif" => Ok(OutputFormat::Sarif),
        "both" => Ok(OutputFormat::Both),
        other => bail!(
            "Invalid --format '{}'. Expected one of: json, sarif, both",
            other
        ),
    }
}

fn parse_fail_on(fail_on: &str) -> Result<FailOn> {
    match fail_on {
        "warning" => Ok(FailOn::Warning),
        "breaking" => Ok(FailOn::Breaking),
        "blocked" => Ok(FailOn::Blocked),
        other => bail!(
            "Invalid --fail-on '{}'. Expected one of: warning, breaking, blocked",
            other
        ),
    }
}

pub fn scan(
    baseline: &str,
    target: &str,
    format: &str,
    out: Option<PathBuf>,
    fail_on: &str,
    suppress: &[String],
    only_new_since: Option<PathBuf>,
) -> Result<()> {
    let format = parse_format(format)?;
    let fail_on = parse_fail_on(fail_on)?;

    let baseline_data = load_baseline(baseline)?;
    let target_tools = load_target_tools(target)?;
    let target_path = PathBuf::from(target);
    let findings = analyze(&baseline_data, &target_tools, Some(&target_path));
    let suppressed: HashSet<&str> = suppress.iter().map(String::as_str).collect();
    let findings: Vec<CiFinding> = findings
        .into_iter()
        .filter(|f| !suppressed.contains(f.rule_id.as_str()))
        .collect();
    let findings = if let Some(prev_path) = only_new_since {
        filter_only_new_findings(&findings, &prev_path)?
    } else {
        findings
    };
    let output_json = build_json_report(&baseline_data.server_name, &findings, fail_on);
    let output_sarif = build_sarif_report(&findings, Some(&target_path));

    write_outputs(format, out.as_deref(), &output_json, &output_sarif)?;

    let should_fail = findings
        .iter()
        .any(|f| f.severity.rank() >= fail_on.threshold());
    if should_fail {
        bail!("CI scan failed due to findings at/above fail threshold");
    }

    Ok(())
}

fn analyze(
    baseline: &ServerBaseline,
    target_tools: &[ToolDefinition],
    target_path: Option<&Path>,
) -> Vec<CiFinding> {
    let mut findings = Vec::new();
    let source_uri = target_path.map(|p| p.to_string_lossy().to_string());
    let source_line = Some(1_u64);

    let report = diff::diff_tools(&baseline.server_name, &baseline.tools, target_tools);
    for d in report.diffs {
        let severity = match d.severity {
            diff::Severity::Safe => continue,
            diff::Severity::Warning => FindingSeverity::Warning,
            diff::Severity::Breaking => FindingSeverity::Breaking,
        };
        findings.push(CiFinding {
            id: format!("{}:{}", d.tool_name, d.field_path),
            rule_id: "MCPX-BREAKING-SCHEMA".to_string(),
            severity,
            category: "schema_drift".to_string(),
            tool_name: d.tool_name,
            field_path: d.field_path,
            message: d.explanation,
            details: json!({
                "kind": d.kind,
                "old_value": d.old_value,
                "new_value": d.new_value,
            }),
            source_uri: source_uri.clone(),
            source_line,
        });
    }

    let baseline_by_tool: HashMap<&str, &ToolSnapshot> = baseline
        .tools
        .iter()
        .map(|t| (t.name.as_str(), t))
        .collect();

    for tool in target_tools {
        if let Some(b) = baseline_by_tool.get(tool.name.as_str()) {
            let old_desc = b.description.as_deref().unwrap_or("");
            let new_desc = tool.description.as_deref().unwrap_or("");
            if old_desc != new_desc {
                let p = structural::analyze(&tool.name, old_desc, new_desc, 0.85);
                if matches!(p.verdict, structural::Verdict::Blocked) {
                    findings.push(CiFinding {
                        id: format!("{}:description", tool.name),
                        rule_id: "MCPX-POISON-TOOL-DESC".to_string(),
                        severity: FindingSeverity::Blocked,
                        category: "poisoning".to_string(),
                        tool_name: tool.name.clone(),
                        field_path: "description".to_string(),
                        message: "tool description matched poisoning indicators".to_string(),
                        details: json!({
                            "injection_patterns": p.injection_patterns,
                            "hidden_chars": p.hidden_chars,
                            "structural_similarity": p.structural_similarity,
                            "semantic_similarity": p.semantic_similarity
                        }),
                        source_uri: source_uri.clone(),
                        source_line,
                    });
                } else if matches!(p.verdict, structural::Verdict::Suspicious) {
                    findings.push(CiFinding {
                        id: format!("{}:description:suspicious", tool.name),
                        rule_id: "MCPX-POISON-TOOL-DESC".to_string(),
                        severity: FindingSeverity::Warning,
                        category: "poisoning".to_string(),
                        tool_name: tool.name.clone(),
                        field_path: "description".to_string(),
                        message: "tool description drift is suspicious".to_string(),
                        details: json!({
                            "structural_similarity": p.structural_similarity,
                            "semantic_similarity": p.semantic_similarity
                        }),
                        source_uri: source_uri.clone(),
                        source_line,
                    });
                }
            }

            let proposal =
                shim::propose_shim_mappings(&tool.name, &b.input_schema, &tool.input_schema);
            match proposal.action {
                shim::ShimProposalAction::None => {}
                shim::ShimProposalAction::Proposed => findings.push(CiFinding {
                    id: format!("{}:shim:proposal", tool.name),
                    rule_id: "MCPX-SHIM-REQUIRES-APPROVAL".to_string(),
                    severity: FindingSeverity::Warning,
                    category: "shim".to_string(),
                    tool_name: tool.name.clone(),
                    field_path: "inputSchema.properties".to_string(),
                    message: "trivial shim mapping proposed; approval required".to_string(),
                    details: json!({ "mappings": proposal.mappings }),
                    source_uri: source_uri.clone(),
                    source_line,
                }),
                shim::ShimProposalAction::Blocked => {
                    let reason = proposal.reason.clone();
                    findings.push(CiFinding {
                        id: format!("{}:shim:blocked", tool.name),
                        rule_id: "MCPX-SHIM-NONTRIVIAL".to_string(),
                        severity: FindingSeverity::Blocked,
                        category: "shim".to_string(),
                        tool_name: tool.name.clone(),
                        field_path: "inputSchema.properties".to_string(),
                        message: reason
                            .clone()
                            .unwrap_or_else(|| "non-trivial shim drift detected".to_string()),
                        details: json!({ "reason": reason }),
                        source_uri: source_uri.clone(),
                        source_line,
                    })
                }
            }
        }

        if let Some(props) = tool.properties() {
            for (param_name, prop_schema) in props {
                let pn = structural::analyze_parameter_name(&tool.name, param_name);
                if matches!(pn.verdict, structural::Verdict::Blocked) {
                    findings.push(CiFinding {
                        id: format!("{}:param:{}:name", tool.name, param_name),
                        rule_id: "MCPX-POISON-PARAM-NAME".to_string(),
                        severity: FindingSeverity::Blocked,
                        category: "poisoning".to_string(),
                        tool_name: tool.name.clone(),
                        field_path: format!("inputSchema.properties.{}", param_name),
                        message: "parameter name matched poisoning indicators".to_string(),
                        details: json!({
                            "risky_tokens": pn.risky_tokens,
                            "injection_patterns": pn.injection_patterns,
                            "hidden_chars": pn.hidden_chars
                        }),
                        source_uri: source_uri.clone(),
                        source_line,
                    });
                }

                if let Some(desc) = prop_schema.get("description").and_then(|v| v.as_str()) {
                    let pd =
                        structural::analyze_parameter_description(&tool.name, param_name, desc);
                    if matches!(pd.verdict, structural::Verdict::Blocked) {
                        findings.push(CiFinding {
                            id: format!("{}:param:{}:description", tool.name, param_name),
                            rule_id: "MCPX-POISON-PARAM-DESC".to_string(),
                            severity: FindingSeverity::Blocked,
                            category: "poisoning".to_string(),
                            tool_name: tool.name.clone(),
                            field_path: format!(
                                "inputSchema.properties.{}.description",
                                param_name
                            ),
                            message: "parameter description matched poisoning indicators"
                                .to_string(),
                            details: json!({
                                "injection_patterns": pd.injection_patterns,
                                "hidden_chars": pd.hidden_chars
                            }),
                            source_uri: source_uri.clone(),
                            source_line,
                        });
                    }
                }
            }
        }
    }

    findings
}

fn build_json_report(server_name: &str, findings: &[CiFinding], fail_on: FailOn) -> Value {
    let summary = json!({
        "warning": findings.iter().filter(|f| matches!(f.severity, FindingSeverity::Warning)).count(),
        "breaking": findings.iter().filter(|f| matches!(f.severity, FindingSeverity::Breaking)).count(),
        "blocked": findings.iter().filter(|f| matches!(f.severity, FindingSeverity::Blocked)).count(),
    });
    json!({
        "schema_version": "1",
        "tool": "mcpx",
        "server_name": server_name,
        "fail_on": match fail_on {
            FailOn::Warning => "warning",
            FailOn::Breaking => "breaking",
            FailOn::Blocked => "blocked",
        },
        "summary": summary,
        "findings": findings,
    })
}

fn build_sarif_report(findings: &[CiFinding], default_source_uri: Option<&Path>) -> Value {
    let rules: Vec<Value> = vec![
        (
            "MCPX-BREAKING-SCHEMA",
            "Schema drift that may break tool calls",
            "https://github.com/meghsatpat/mcpx#what-gets-detected",
        ),
        (
            "MCPX-POISON-TOOL-DESC",
            "Tool description poisoning indicator",
            "https://github.com/meghsatpat/mcpx#poisoning-detection",
        ),
        (
            "MCPX-POISON-PARAM-NAME",
            "Parameter name poisoning indicator",
            "https://github.com/meghsatpat/mcpx#poisoning-detection",
        ),
        (
            "MCPX-POISON-PARAM-DESC",
            "Parameter description poisoning indicator",
            "https://github.com/meghsatpat/mcpx#poisoning-detection",
        ),
        (
            "MCPX-SHIM-REQUIRES-APPROVAL",
            "Trivial shim proposal requires explicit approval",
            "https://github.com/meghsatpat/mcpx#auto-shimming-safe-mode",
        ),
        (
            "MCPX-SHIM-NONTRIVIAL",
            "Non-trivial shim drift is blocked",
            "https://github.com/meghsatpat/mcpx#auto-shimming-safe-mode",
        ),
    ]
    .into_iter()
    .map(|(id, name, help_uri)| {
        json!({
            "id": id,
            "name": name,
            "shortDescription": {"text": name},
            "helpUri": help_uri,
            "properties": {
                "tags": ["security", "mcp", "schema-drift", "poisoning"]
            }
        })
    })
    .collect();

    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                FindingSeverity::Warning => "warning",
                FindingSeverity::Breaking => "error",
                FindingSeverity::Blocked => "error",
            };
            let source_uri = f
                .source_uri
                .clone()
                .or_else(|| default_source_uri.map(|p| p.to_string_lossy().to_string()))
                .unwrap_or_else(|| "unknown".to_string());
            let source_line = f.source_line.unwrap_or(1);
            json!({
                "ruleId": f.rule_id,
                "level": level,
                "message": { "text": f.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": source_uri },
                        "region": { "startLine": source_line }
                    },
                    "logicalLocations": [{
                        "fullyQualifiedName": format!("{}.{}", f.tool_name, f.field_path)
                    }]
                }],
                "properties": {
                    "severity": f.severity,
                    "category": f.category,
                    "details": f.details
                }
            })
        })
        .collect();

    json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "mcpx",
                    "informationUri": "https://github.com/meghsatpat/mcpx",
                    "rules": rules
                }
            },
            "results": results
        }]
    })
}

fn filter_only_new_findings(
    findings: &[CiFinding],
    previous_report_path: &Path,
) -> Result<Vec<CiFinding>> {
    let raw = std::fs::read_to_string(previous_report_path).with_context(|| {
        format!(
            "Failed reading previous report file {}",
            previous_report_path.display()
        )
    })?;
    let v: Value = serde_json::from_str(&raw).with_context(|| {
        format!(
            "Failed parsing previous report file {} as JSON",
            previous_report_path.display()
        )
    })?;
    let previous_ids: HashSet<String> = v
        .get("findings")
        .and_then(|f| f.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|f| f.get("id").and_then(|id| id.as_str()).map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    Ok(findings
        .iter()
        .filter(|f| !previous_ids.contains(&f.id))
        .cloned()
        .collect())
}

fn write_outputs(
    format: OutputFormat,
    out: Option<&Path>,
    json_out: &Value,
    sarif_out: &Value,
) -> Result<()> {
    match format {
        OutputFormat::Json => write_one(out, json_out),
        OutputFormat::Sarif => write_one(out, sarif_out),
        OutputFormat::Both => write_both(out, json_out, sarif_out),
    }
}

fn write_one(out: Option<&Path>, payload: &Value) -> Result<()> {
    match out {
        Some(path) => {
            std::fs::write(path, serde_json::to_vec_pretty(payload)?)
                .with_context(|| format!("Failed to write output: {}", path.display()))?;
            eprintln!("Wrote report to {}", path.display());
        }
        None => eprintln!("{}", serde_json::to_string_pretty(payload)?),
    }
    Ok(())
}

fn write_both(out: Option<&Path>, json_out: &Value, sarif_out: &Value) -> Result<()> {
    match out {
        Some(path) => {
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("mcpx-report");
            let parent = path.parent().unwrap_or_else(|| Path::new("."));
            let json_path = parent.join(format!("{}.json", stem));
            let sarif_path = parent.join(format!("{}.sarif", stem));
            std::fs::write(&json_path, serde_json::to_vec_pretty(json_out)?)
                .with_context(|| format!("Failed to write output: {}", json_path.display()))?;
            std::fs::write(&sarif_path, serde_json::to_vec_pretty(sarif_out)?)
                .with_context(|| format!("Failed to write output: {}", sarif_path.display()))?;
            eprintln!(
                "Wrote reports to {} and {}",
                json_path.display(),
                sarif_path.display()
            );
        }
        None => {
            eprintln!("--- BEGIN MCPX JSON REPORT ---");
            eprintln!("{}", serde_json::to_string_pretty(json_out)?);
            eprintln!("--- BEGIN MCPX SARIF REPORT ---");
            eprintln!("{}", serde_json::to_string_pretty(sarif_out)?);
        }
    }
    Ok(())
}

fn load_baseline(baseline: &str) -> Result<ServerBaseline> {
    let store = Store::open_default()?;
    if let Some(b) = store.get_baseline(baseline)? {
        return Ok(b);
    }

    let path = PathBuf::from(baseline);
    if !path.exists() {
        bail!(
            "Baseline '{}' not found as pinned server name or readable file path",
            baseline
        );
    }
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed reading baseline file {}", path.display()))?;
    parse_baseline_json(&raw).with_context(|| {
        format!(
            "Failed parsing baseline file {} as ServerBaseline/tools payload",
            path.display()
        )
    })
}

fn parse_baseline_json(raw: &str) -> Result<ServerBaseline> {
    if let Ok(b) = serde_json::from_str::<ServerBaseline>(raw) {
        return Ok(b);
    }
    if let Ok(tools_list) = serde_json::from_str::<ToolsListResult>(raw) {
        return Ok(ServerBaseline {
            server_name: "ci-baseline".to_string(),
            server_version: None,
            protocol_version: "unknown".to_string(),
            tools: tools_list
                .tools
                .iter()
                .map(ToolSnapshot::from_definition)
                .collect(),
            pinned_at: chrono::Utc::now(),
            mcpx_version: env!("CARGO_PKG_VERSION").to_string(),
        });
    }
    if let Ok(tools) = serde_json::from_str::<Vec<ToolDefinition>>(raw) {
        return Ok(ServerBaseline {
            server_name: "ci-baseline".to_string(),
            server_version: None,
            protocol_version: "unknown".to_string(),
            tools: tools.iter().map(ToolSnapshot::from_definition).collect(),
            pinned_at: chrono::Utc::now(),
            mcpx_version: env!("CARGO_PKG_VERSION").to_string(),
        });
    }
    Err(anyhow!("unsupported baseline JSON format"))
}

fn load_target_tools(target: &str) -> Result<Vec<ToolDefinition>> {
    let path = PathBuf::from(target);
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed reading target file {}", path.display()))?;
    parse_target_tools_json(&raw).with_context(|| {
        format!(
            "Failed parsing target file {} as tools/list or tool array",
            path.display()
        )
    })
}

fn parse_target_tools_json(raw: &str) -> Result<Vec<ToolDefinition>> {
    if let Ok(tools_list) = serde_json::from_str::<ToolsListResult>(raw) {
        return Ok(tools_list.tools);
    }
    if let Ok(tools) = serde_json::from_str::<Vec<ToolDefinition>>(raw) {
        return Ok(tools);
    }
    let v: Value = serde_json::from_str(raw)?;
    if let Some(tools) = v.get("tools") {
        return Ok(serde_json::from_value::<Vec<ToolDefinition>>(
            tools.clone(),
        )?);
    }
    Err(anyhow!("unsupported target JSON format"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn command_symbol_exists() {
        let _ = super::scan
            as fn(
                &str,
                &str,
                &str,
                Option<std::path::PathBuf>,
                &str,
                &[String],
                Option<std::path::PathBuf>,
            ) -> Result<()>;
    }

    #[test]
    fn parse_options() {
        assert!(parse_format("json").is_ok());
        assert!(parse_format("sarif").is_ok());
        assert!(parse_format("both").is_ok());
        assert!(parse_format("xml").is_err());
        assert!(parse_fail_on("warning").is_ok());
        assert!(parse_fail_on("breaking").is_ok());
        assert!(parse_fail_on("blocked").is_ok());
        assert!(parse_fail_on("low").is_err());
    }

    #[test]
    fn parses_target_tools_from_tools_list_object() {
        let raw = r#"{
          "tools": [{
            "name": "search",
            "description": "Search",
            "inputSchema": {"type":"object","properties":{"q":{"type":"string"}}}
          }]
        }"#;
        let tools = parse_target_tools_json(raw).unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "search");
    }

    #[test]
    fn filters_only_new_findings() {
        let old_report = json!({
            "findings": [{"id":"existing:1"}]
        });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.json");
        std::fs::write(&path, serde_json::to_vec(&old_report).unwrap()).unwrap();

        let findings = vec![
            CiFinding {
                id: "existing:1".to_string(),
                rule_id: "MCPX-BREAKING-SCHEMA".to_string(),
                severity: FindingSeverity::Warning,
                category: "schema_drift".to_string(),
                tool_name: "search".to_string(),
                field_path: "description".to_string(),
                message: "x".to_string(),
                details: json!({}),
                source_uri: None,
                source_line: None,
            },
            CiFinding {
                id: "new:2".to_string(),
                rule_id: "MCPX-BREAKING-SCHEMA".to_string(),
                severity: FindingSeverity::Warning,
                category: "schema_drift".to_string(),
                tool_name: "search".to_string(),
                field_path: "description".to_string(),
                message: "x".to_string(),
                details: json!({}),
                source_uri: None,
                source_line: None,
            },
        ];
        let filtered = filter_only_new_findings(&findings, &path).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "new:2");
    }

    #[test]
    fn sarif_contains_physical_location_and_rule_help() {
        let findings = vec![CiFinding {
            id: "a".to_string(),
            rule_id: "MCPX-POISON-PARAM-NAME".to_string(),
            severity: FindingSeverity::Blocked,
            category: "poisoning".to_string(),
            tool_name: "search".to_string(),
            field_path: "inputSchema.properties.q".to_string(),
            message: "bad".to_string(),
            details: json!({}),
            source_uri: Some("schemas/target.json".to_string()),
            source_line: Some(1),
        }];
        let sarif = build_sarif_report(&findings, None);
        assert!(sarif["runs"][0]["tool"]["driver"]["rules"][0]["helpUri"].is_string());
        assert_eq!(
            sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "schemas/target.json"
        );
    }
}
