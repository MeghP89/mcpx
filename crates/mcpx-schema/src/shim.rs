//! Request rewriting / backwards-compatibility shimming.
//! Shimming is intentionally conservative and only applies to trivial drift.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};

const DEFAULT_RENAME_SIMILARITY_THRESHOLD: f64 = 0.92;
const DEFAULT_MAX_AUTO_MAPPINGS: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShimAction {
    Passthrough,
    Rewritten,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShimMapping {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShimResult {
    pub tool_name: String,
    pub action: ShimAction,
    pub rewritten_args: Value,
    pub mappings: Vec<ShimMapping>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShimProposalAction {
    None,
    Proposed,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShimProposalResult {
    pub tool_name: String,
    pub action: ShimProposalAction,
    pub mappings: Vec<ShimMapping>,
    pub reason: Option<String>,
}

/// Compatibility wrapper used by existing call sites.
/// Without both baseline/live schemas we cannot safely infer renames, so this stays passthrough.
pub fn rewrite_tool_call_args(_tool_name: &str, args: &Value) -> Value {
    args.clone()
}

/// Safely rewrite `tools/call` arguments by inferring only trivial parameter renames
/// from a baseline and live input schema.
pub fn rewrite_tool_call_args_safe(
    tool_name: &str,
    args: &Value,
    baseline_input_schema: &Value,
    live_input_schema: &Value,
) -> ShimResult {
    let Some(arg_obj) = args.as_object() else {
        return ShimResult {
            tool_name: tool_name.to_string(),
            action: ShimAction::Passthrough,
            rewritten_args: args.clone(),
            mappings: Vec::new(),
            reason: Some("arguments are not a JSON object".to_string()),
        };
    };

    let old_props = extract_properties(baseline_input_schema);
    let new_props = extract_properties(live_input_schema);

    if old_props.is_empty() || new_props.is_empty() {
        return ShimResult {
            tool_name: tool_name.to_string(),
            action: ShimAction::Passthrough,
            rewritten_args: args.clone(),
            mappings: Vec::new(),
            reason: Some("schemas missing properties objects".to_string()),
        };
    }

    let mappings = infer_trivial_renames(
        &old_props,
        &new_props,
        DEFAULT_RENAME_SIMILARITY_THRESHOLD,
        DEFAULT_MAX_AUTO_MAPPINGS,
    );

    match mappings {
        Err(reason) => ShimResult {
            tool_name: tool_name.to_string(),
            action: ShimAction::Blocked,
            rewritten_args: args.clone(),
            mappings: Vec::new(),
            reason: Some(reason),
        },
        Ok(rename_pairs) if rename_pairs.is_empty() => ShimResult {
            tool_name: tool_name.to_string(),
            action: ShimAction::Passthrough,
            rewritten_args: args.clone(),
            mappings: Vec::new(),
            reason: Some("no eligible trivial renames inferred".to_string()),
        },
        Ok(rename_pairs) => {
            let mut out: Map<String, Value> = arg_obj.clone();
            let mut applied = Vec::new();
            for (from, to) in rename_pairs {
                if out.contains_key(&to) {
                    return ShimResult {
                        tool_name: tool_name.to_string(),
                        action: ShimAction::Blocked,
                        rewritten_args: args.clone(),
                        mappings: Vec::new(),
                        reason: Some(format!(
                            "cannot rewrite due to conflicting keys present: '{}' and '{}'",
                            from, to
                        )),
                    };
                }
                if let Some(v) = out.remove(&from) {
                    out.insert(to.clone(), v);
                    applied.push(ShimMapping { from, to });
                }
            }

            if applied.is_empty() {
                ShimResult {
                    tool_name: tool_name.to_string(),
                    action: ShimAction::Passthrough,
                    rewritten_args: args.clone(),
                    mappings: Vec::new(),
                    reason: Some("no source keys present in arguments".to_string()),
                }
            } else {
                ShimResult {
                    tool_name: tool_name.to_string(),
                    action: ShimAction::Rewritten,
                    rewritten_args: Value::Object(out),
                    mappings: applied,
                    reason: None,
                }
            }
        }
    }
}

/// Propose conservative rename-only shims from baseline -> live input schema.
pub fn propose_shim_mappings(
    tool_name: &str,
    baseline_input_schema: &Value,
    live_input_schema: &Value,
) -> ShimProposalResult {
    let old_props = extract_properties(baseline_input_schema);
    let new_props = extract_properties(live_input_schema);
    if old_props.is_empty() || new_props.is_empty() {
        return ShimProposalResult {
            tool_name: tool_name.to_string(),
            action: ShimProposalAction::None,
            mappings: Vec::new(),
            reason: Some("schemas missing properties objects".to_string()),
        };
    }

    let old_keys: HashSet<&String> = old_props.keys().collect();
    let new_keys: HashSet<&String> = new_props.keys().collect();
    let removed: Vec<&String> = old_keys.difference(&new_keys).copied().collect();
    let added: Vec<&String> = new_keys.difference(&old_keys).copied().collect();

    if removed.is_empty() && added.is_empty() {
        return ShimProposalResult {
            tool_name: tool_name.to_string(),
            action: ShimProposalAction::None,
            mappings: Vec::new(),
            reason: Some("no removed/added parameters detected".to_string()),
        };
    }

    let inferred = infer_trivial_renames(
        &old_props,
        &new_props,
        DEFAULT_RENAME_SIMILARITY_THRESHOLD,
        DEFAULT_MAX_AUTO_MAPPINGS,
    );

    let pairs = match inferred {
        Ok(pairs) => pairs,
        Err(reason) => {
            return ShimProposalResult {
                tool_name: tool_name.to_string(),
                action: ShimProposalAction::Blocked,
                mappings: Vec::new(),
                reason: Some(reason),
            };
        }
    };

    if pairs.is_empty() {
        return ShimProposalResult {
            tool_name: tool_name.to_string(),
            action: ShimProposalAction::Blocked,
            mappings: Vec::new(),
            reason: Some(
                "removed/added parameters detected but no safe trivial mapping inferred"
                    .to_string(),
            ),
        };
    }

    // Require complete mapping of removed <-> added sets, otherwise drift is non-trivial.
    if pairs.len() != removed.len() || pairs.len() != added.len() {
        return ShimProposalResult {
            tool_name: tool_name.to_string(),
            action: ShimProposalAction::Blocked,
            mappings: Vec::new(),
            reason: Some("drift is non-trivial (unmatched removed/added parameters)".to_string()),
        };
    }

    ShimProposalResult {
        tool_name: tool_name.to_string(),
        action: ShimProposalAction::Proposed,
        mappings: pairs
            .into_iter()
            .map(|(from, to)| ShimMapping { from, to })
            .collect(),
        reason: None,
    }
}

fn infer_trivial_renames(
    old_props: &HashMap<String, Value>,
    new_props: &HashMap<String, Value>,
    similarity_threshold: f64,
    max_mappings: usize,
) -> Result<Vec<(String, String)>, String> {
    let old_keys: HashSet<&String> = old_props.keys().collect();
    let new_keys: HashSet<&String> = new_props.keys().collect();

    let removed: Vec<&String> = old_keys.difference(&new_keys).copied().collect();
    let added: Vec<&String> = new_keys.difference(&old_keys).copied().collect();

    if removed.is_empty() || added.is_empty() {
        return Ok(Vec::new());
    }

    let mut candidates: Vec<(String, String, f64)> = Vec::new();
    for old_key in &removed {
        for new_key in &added {
            let score = trivial_rename_score(old_key, new_key);
            if score < similarity_threshold {
                continue;
            }

            let old_type = extract_type(old_props.get(*old_key).expect("existing old key"));
            let new_type = extract_type(new_props.get(*new_key).expect("existing new key"));
            if old_type != new_type {
                continue;
            }

            candidates.push(((*old_key).clone(), (*new_key).clone(), score));
        }
    }

    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    // Mutual-best matching to avoid ambiguous rewrites.
    let mut best_new_for_old: HashMap<String, (String, f64)> = HashMap::new();
    let mut best_old_for_new: HashMap<String, (String, f64)> = HashMap::new();
    for (old, new, score) in &candidates {
        match best_new_for_old.get(old) {
            Some((_, best)) if *best >= *score => {}
            _ => {
                best_new_for_old.insert(old.clone(), (new.clone(), *score));
            }
        }
        match best_old_for_new.get(new) {
            Some((_, best)) if *best >= *score => {}
            _ => {
                best_old_for_new.insert(new.clone(), (old.clone(), *score));
            }
        }
    }

    let mut chosen = Vec::new();
    for (old, (new, _)) in &best_new_for_old {
        if let Some((back_old, _)) = best_old_for_new.get(new) {
            if back_old == old {
                chosen.push((old.clone(), new.clone()));
            }
        }
    }

    if chosen.len() > max_mappings {
        return Err(format!(
            "too many rename mappings inferred automatically: {} (max {})",
            chosen.len(),
            max_mappings
        ));
    }

    Ok(chosen)
}

fn trivial_rename_score(old_key: &str, new_key: &str) -> f64 {
    let old_norm = canonical_identifier(old_key);
    let new_norm = canonical_identifier(new_key);
    if !old_norm.is_empty() && old_norm == new_norm {
        1.0
    } else {
        strsim::normalized_levenshtein(old_key, new_key)
    }
}

fn canonical_identifier(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn extract_properties(schema: &Value) -> HashMap<String, Value> {
    schema
        .get("properties")
        .and_then(|v| v.as_object())
        .map(|map| map.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default()
}

fn extract_type(schema: &Value) -> String {
    if let Some(t) = schema.get("type") {
        match t {
            Value::String(s) => s.clone(),
            Value::Array(arr) => {
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

    #[test]
    fn rewrite_wrapper_is_passthrough() {
        let input = serde_json::json!({"q": "hello", "limit": 10});
        let output = rewrite_tool_call_args("search", &input);
        assert_eq!(output, input);
    }

    #[test]
    fn safe_rewrite_applies_trivial_rename() {
        let old_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string" },
                "limit": { "type": "number" }
            }
        });
        let new_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "filepath": { "type": "string" },
                "limit": { "type": "number" }
            }
        });
        let args = serde_json::json!({
            "file_path": "/tmp/a.txt",
            "limit": 10
        });

        let out = rewrite_tool_call_args_safe("read_file", &args, &old_schema, &new_schema);
        assert_eq!(out.action, ShimAction::Rewritten);
        assert_eq!(out.rewritten_args["filepath"], "/tmp/a.txt");
        assert_eq!(out.rewritten_args["limit"], 10);
        assert!(out.rewritten_args.get("file_path").is_none());
        assert_eq!(out.mappings.len(), 1);
        assert_eq!(out.mappings[0].from, "file_path");
        assert_eq!(out.mappings[0].to, "filepath");
    }

    #[test]
    fn safe_rewrite_rejects_low_similarity_rename() {
        let old_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "user_id": { "type": "string" }
            }
        });
        let new_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "admin_token": { "type": "string" }
            }
        });
        let args = serde_json::json!({"user_id": "abc"});

        let out = rewrite_tool_call_args_safe("lookup", &args, &old_schema, &new_schema);
        assert_eq!(out.action, ShimAction::Passthrough);
        assert_eq!(out.rewritten_args, args);
    }

    #[test]
    fn safe_rewrite_rejects_type_change() {
        let old_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "q": { "type": "string" }
            }
        });
        let new_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "query": { "type": "boolean" }
            }
        });
        let args = serde_json::json!({"q": "hello"});

        let out = rewrite_tool_call_args_safe("search", &args, &old_schema, &new_schema);
        assert_eq!(out.action, ShimAction::Passthrough);
        assert_eq!(out.rewritten_args, args);
    }

    #[test]
    fn safe_rewrite_blocks_on_key_conflict() {
        let old_schema = serde_json::json!({
            "type": "object",
            "properties": { "file_path": { "type": "string" } }
        });
        let new_schema = serde_json::json!({
            "type": "object",
            "properties": { "filepath": { "type": "string" } }
        });
        let args = serde_json::json!({
            "file_path": "/tmp/a.txt",
            "filepath": "/tmp/b.txt"
        });

        let out = rewrite_tool_call_args_safe("read_file", &args, &old_schema, &new_schema);
        assert_eq!(out.action, ShimAction::Blocked);
        assert_eq!(out.rewritten_args, args);
    }

    #[test]
    fn propose_trivial_rename_is_proposed() {
        let old_schema = serde_json::json!({
            "type": "object",
            "properties": { "file_path": { "type": "string" } }
        });
        let new_schema = serde_json::json!({
            "type": "object",
            "properties": { "filepath": { "type": "string" } }
        });

        let out = propose_shim_mappings("read_file", &old_schema, &new_schema);
        assert_eq!(out.action, ShimProposalAction::Proposed);
        assert_eq!(out.mappings.len(), 1);
    }

    #[test]
    fn propose_non_trivial_is_blocked() {
        let old_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "user_id": { "type": "string" },
                "query": { "type": "string" }
            }
        });
        let new_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "admin_token": { "type": "string" },
                "query_v2": { "type": "string" }
            }
        });

        let out = propose_shim_mappings("lookup", &old_schema, &new_schema);
        assert_eq!(out.action, ShimProposalAction::Blocked);
    }
}
