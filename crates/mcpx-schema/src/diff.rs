use mcpx_core::mcp::ToolDefinition;
use mcpx_core::snapshot::ToolSnapshot;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Safe,
    Warning,
    Breaking,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiffKind {
    ToolAdded,
    ToolRemoved,
    ParameterAdded { required: bool },
    ParameterRemoved { was_required: bool },
    ParameterRenamed { old: String, new: String },
    TypeChanged { old: String, new: String },
    DescriptionChanged,
    RequiredAdded { param: String },
    RequiredRemoved { param: String },
    EnumValuesAdded,
    EnumValuesRemoved,
    DefaultChanged,
    Other { detail: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaDiff {
    pub tool_name: String,
    pub field_path: String,
    pub severity: Severity,
    pub kind: DiffKind,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    pub server_name: String,
    pub diffs: Vec<SchemaDiff>,
    pub max_severity: Severity,
}

impl DiffReport {
    pub fn has_breaking(&self) -> bool {
        self.max_severity == Severity::Breaking
    }

    pub fn has_warnings(&self) -> bool {
        self.max_severity >= Severity::Warning
    }
}

/// Diff a set of baseline tool snapshots against a set of live tool definitions.
pub fn diff_tools(
    server_name: &str,
    baseline: &[ToolSnapshot],
    live: &[ToolDefinition],
) -> DiffReport {
    let mut diffs = Vec::new();

    let baseline_map: HashMap<&str, &ToolSnapshot> =
        baseline.iter().map(|t| (t.name.as_str(), t)).collect();
    let live_map: HashMap<&str, &ToolDefinition> =
        live.iter().map(|t| (t.name.as_str(), t)).collect();

    // Detect removed tools.
    for name in baseline_map.keys() {
        if !live_map.contains_key(name) {
            diffs.push(SchemaDiff {
                tool_name: name.to_string(),
                field_path: "(tool)".into(),
                severity: Severity::Breaking,
                kind: DiffKind::ToolRemoved,
                old_value: Some(name.to_string()),
                new_value: None,
                explanation: format!("Tool '{}' was removed from the server.", name),
            });
        }
    }

    // Detect added tools.
    for name in live_map.keys() {
        if !baseline_map.contains_key(name) {
            diffs.push(SchemaDiff {
                tool_name: name.to_string(),
                field_path: "(tool)".into(),
                severity: Severity::Safe,
                kind: DiffKind::ToolAdded,
                old_value: None,
                new_value: Some(name.to_string()),
                explanation: format!("New tool '{}' was added to the server.", name),
            });
        }
    }

    // Diff tools that exist in both.
    for (name, snap) in &baseline_map {
        if let Some(live_def) = live_map.get(name) {
            // Description diff.
            if snap.description_changed(live_def) {
                diffs.push(SchemaDiff {
                    tool_name: name.to_string(),
                    field_path: "description".into(),
                    severity: Severity::Warning,
                    kind: DiffKind::DescriptionChanged,
                    old_value: snap.description.clone(),
                    new_value: live_def.description.clone(),
                    explanation: format!(
                        "Tool '{}' description changed. This may affect LLM tool selection behavior.",
                        name
                    ),
                });
            }

            // Schema diff — compare properties and required arrays.
            if snap.schema_changed(live_def) {
                diff_input_schemas(name, snap, live_def, &mut diffs);
            }
        }
    }

    let max_severity = diffs
        .iter()
        .map(|d| d.severity)
        .max()
        .unwrap_or(Severity::Safe);

    DiffReport {
        server_name: server_name.to_string(),
        diffs,
        max_severity,
    }
}

fn diff_input_schemas(
    tool_name: &str,
    baseline: &ToolSnapshot,
    live: &ToolDefinition,
    diffs: &mut Vec<SchemaDiff>,
) {
    let old_props = baseline
        .input_schema
        .get("properties")
        .and_then(|v| v.as_object());
    let new_props = live
        .input_schema
        .get("properties")
        .and_then(|v| v.as_object());

    let old_required: HashSet<String> = baseline
        .input_schema
        .get("required")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let new_required: HashSet<String> = live
        .input_schema
        .get("required")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let old_keys: HashSet<&String> = old_props.map(|p| p.keys().collect()).unwrap_or_default();
    let new_keys: HashSet<&String> = new_props.map(|p| p.keys().collect()).unwrap_or_default();

    // Removed parameters.
    for key in old_keys.difference(&new_keys) {
        let was_required = old_required.contains(key.as_str());
        diffs.push(SchemaDiff {
            tool_name: tool_name.to_string(),
            field_path: format!("properties.{}", key),
            severity: if was_required {
                Severity::Breaking
            } else {
                Severity::Warning
            },
            kind: DiffKind::ParameterRemoved { was_required },
            old_value: Some(key.to_string()),
            new_value: None,
            explanation: format!(
                "Parameter '{}' was removed from tool '{}'{}.",
                key,
                tool_name,
                if was_required { " (was required)" } else { "" }
            ),
        });
    }

    // Added parameters.
    for key in new_keys.difference(&old_keys) {
        let is_required = new_required.contains(key.as_str());
        diffs.push(SchemaDiff {
            tool_name: tool_name.to_string(),
            field_path: format!("properties.{}", key),
            severity: if is_required {
                Severity::Breaking
            } else {
                Severity::Safe
            },
            kind: DiffKind::ParameterAdded {
                required: is_required,
            },
            old_value: None,
            new_value: Some(key.to_string()),
            explanation: format!(
                "Parameter '{}' was added to tool '{}'{}.",
                key,
                tool_name,
                if is_required {
                    " (required — breaks existing clients)"
                } else {
                    " (optional)"
                }
            ),
        });
    }

    // Changed parameters (exist in both).
    if let (Some(old_p), Some(new_p)) = (old_props, new_props) {
        for key in old_keys.intersection(&new_keys) {
            if let (Some(old_schema), Some(new_schema)) =
                (old_p.get(key.as_str()), new_p.get(key.as_str()))
            {
                // Type change check.
                let old_type = extract_type(old_schema);
                let new_type = extract_type(new_schema);
                if old_type != new_type {
                    diffs.push(SchemaDiff {
                        tool_name: tool_name.to_string(),
                        field_path: format!("properties.{}.type", key),
                        severity: Severity::Breaking,
                        kind: DiffKind::TypeChanged {
                            old: old_type.clone(),
                            new: new_type.clone(),
                        },
                        old_value: Some(old_type),
                        new_value: Some(new_type),
                        explanation: format!(
                            "Parameter '{}' in tool '{}' changed type.",
                            key, tool_name
                        ),
                    });
                }
            }
        }
    }

    // Newly required parameters (were optional, now required).
    for param in new_required.difference(&old_required) {
        if old_keys.contains(param) {
            diffs.push(SchemaDiff {
                tool_name: tool_name.to_string(),
                field_path: format!("required.{}", param),
                severity: Severity::Breaking,
                kind: DiffKind::RequiredAdded {
                    param: param.clone(),
                },
                old_value: Some("optional".into()),
                new_value: Some("required".into()),
                explanation: format!(
                    "Parameter '{}' in tool '{}' was optional and is now required.",
                    param, tool_name
                ),
            });
        }
    }
}

/// Extract a type string from a JSON Schema property for comparison.
fn extract_type(schema: &serde_json::Value) -> String {
    if let Some(t) = schema.get("type") {
        match t {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Array(arr) => {
                let mut types: Vec<String> = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                types.sort();
                types.join("|")
            }
            _ => "unknown".into(),
        }
    } else if schema.get("oneOf").is_some() || schema.get("anyOf").is_some() {
        "union".into()
    } else {
        "unknown".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpx_core::mcp::ToolDefinition;
    use mcpx_core::snapshot::ToolSnapshot;

    fn make_tool(name: &str, desc: &str, schema: serde_json::Value) -> ToolDefinition {
        ToolDefinition {
            name: name.into(),
            description: Some(desc.into()),
            input_schema: schema,
            output_schema: None,
            annotations: None,
        }
    }

    #[test]
    fn detect_tool_removed() {
        let baseline = vec![ToolSnapshot::from_definition(&make_tool(
            "search",
            "Search",
            serde_json::json!({"type": "object"}),
        ))];
        let live: Vec<ToolDefinition> = vec![];

        let report = diff_tools("test-server", &baseline, &live);
        assert!(report.has_breaking());
        assert!(matches!(report.diffs[0].kind, DiffKind::ToolRemoved));
    }

    #[test]
    fn detect_tool_added() {
        let baseline: Vec<ToolSnapshot> = vec![];
        let live = vec![make_tool(
            "search",
            "Search",
            serde_json::json!({"type": "object"}),
        )];

        let report = diff_tools("test-server", &baseline, &live);
        assert!(!report.has_breaking());
        assert!(matches!(report.diffs[0].kind, DiffKind::ToolAdded));
    }

    #[test]
    fn detect_required_param_added() {
        let old = make_tool(
            "search",
            "Search",
            serde_json::json!({
                "type": "object",
                "properties": { "query": { "type": "string" } },
                "required": ["query"]
            }),
        );
        let new = make_tool(
            "search",
            "Search",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" },
                    "limit": { "type": "number" }
                },
                "required": ["query", "limit"]
            }),
        );

        let baseline = vec![ToolSnapshot::from_definition(&old)];
        let report = diff_tools("test-server", &baseline, &[new]);
        assert!(report.has_breaking());
    }

    #[test]
    fn detect_description_change() {
        let old = make_tool(
            "search",
            "Search for items",
            serde_json::json!({"type": "object"}),
        );
        let new = make_tool(
            "search",
            "Search for active items only",
            serde_json::json!({"type": "object"}),
        );

        let baseline = vec![ToolSnapshot::from_definition(&old)];
        let report = diff_tools("test-server", &baseline, &[new]);
        assert!(report.has_warnings());
        assert!(matches!(report.diffs[0].kind, DiffKind::DescriptionChanged));
    }

    #[test]
    fn no_diff_when_identical() {
        let tool = make_tool(
            "search",
            "Search",
            serde_json::json!({
                "type": "object",
                "properties": { "query": { "type": "string" } },
                "required": ["query"]
            }),
        );
        let baseline = vec![ToolSnapshot::from_definition(&tool)];
        let report = diff_tools("test-server", &baseline, &[tool]);
        assert!(report.diffs.is_empty());
    }
}
