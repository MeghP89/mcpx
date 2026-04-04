use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::mcp::ToolDefinition;

/// A snapshot of a single tool's schema at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSnapshot {
    pub name: String,
    pub description: Option<String>,
    pub input_schema: serde_json::Value,
    pub output_schema: Option<serde_json::Value>,
    pub annotations: Option<serde_json::Value>,
    /// BLAKE3 hash of the description string (hex-encoded).
    pub description_hash: String,
    /// BLAKE3 hash of the canonicalized input_schema JSON (hex-encoded).
    pub schema_hash: String,
}

/// A complete baseline for a server — all tools captured at one point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerBaseline {
    /// Identifier for the server (from initialize handshake).
    pub server_name: String,
    /// Server version (from initialize handshake).
    pub server_version: Option<String>,
    /// MCP protocol version negotiated.
    pub protocol_version: String,
    /// All tools at the time of capture.
    pub tools: Vec<ToolSnapshot>,
    /// When this baseline was pinned.
    pub pinned_at: DateTime<Utc>,
    /// mcpx version that created this baseline.
    pub mcpx_version: String,
}

impl ToolSnapshot {
    /// Create a snapshot from a live tool definition.
    pub fn from_definition(def: &ToolDefinition) -> Self {
        let desc = def.description.as_deref().unwrap_or("");
        let description_hash = blake3::hash(desc.as_bytes()).to_hex().to_string();

        let canonical_schema = canonicalize_json(&def.input_schema);
        let schema_hash = blake3::hash(canonical_schema.as_bytes()).to_hex().to_string();

        Self {
            name: def.name.clone(),
            description: def.description.clone(),
            input_schema: def.input_schema.clone(),
            output_schema: def.output_schema.clone(),
            annotations: def.annotations.clone(),
            description_hash,
            schema_hash,
        }
    }

    /// Quick check: has the description changed since this snapshot?
    pub fn description_changed(&self, current: &ToolDefinition) -> bool {
        let desc = current.description.as_deref().unwrap_or("");
        let hash = blake3::hash(desc.as_bytes()).to_hex().to_string();
        hash != self.description_hash
    }

    /// Quick check: has the input schema changed since this snapshot?
    pub fn schema_changed(&self, current: &ToolDefinition) -> bool {
        let canonical = canonicalize_json(&current.input_schema);
        let hash = blake3::hash(canonical.as_bytes()).to_hex().to_string();
        hash != self.schema_hash
    }
}

/// Produce a canonical JSON string for hashing.
/// Sorts object keys recursively so semantically identical schemas
/// produce identical hashes regardless of key ordering.
fn canonicalize_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let entries: Vec<String> = keys
                .iter()
                .map(|k| format!("{}:{}", serde_json::to_string(k).unwrap(), canonicalize_json(&map[*k])))
                .collect();
            format!("{{{}}}", entries.join(","))
        }
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonicalize_json).collect();
            format!("[{}]", items.join(","))
        }
        other => serde_json::to_string(other).unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_sorts_keys() {
        let a: serde_json::Value = serde_json::from_str(r#"{"b":1,"a":2}"#).unwrap();
        let b: serde_json::Value = serde_json::from_str(r#"{"a":2,"b":1}"#).unwrap();
        assert_eq!(canonicalize_json(&a), canonicalize_json(&b));
    }

    #[test]
    fn snapshot_detects_description_change() {
        let def = ToolDefinition {
            name: "test".into(),
            description: Some("original description".into()),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            annotations: None,
        };
        let snap = ToolSnapshot::from_definition(&def);

        let mut modified = def.clone();
        modified.description = Some("modified description".into());
        assert!(snap.description_changed(&modified));
        assert!(!snap.description_changed(&def));
    }

    #[test]
    fn snapshot_detects_schema_change() {
        let def = ToolDefinition {
            name: "test".into(),
            description: None,
            input_schema: serde_json::json!({
                "type": "object",
                "properties": { "q": { "type": "string" } }
            }),
            output_schema: None,
            annotations: None,
        };
        let snap = ToolSnapshot::from_definition(&def);

        let mut modified = def.clone();
        modified.input_schema = serde_json::json!({
            "type": "object",
            "properties": { "query": { "type": "string" } }
        });
        assert!(snap.schema_changed(&modified));
        assert!(!snap.schema_changed(&def));
    }
}
