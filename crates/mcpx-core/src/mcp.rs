use serde::{Deserialize, Serialize};

/// MCP tool definition as returned by `tools/list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
    #[serde(
        rename = "outputSchema",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub output_schema: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<serde_json::Value>,
}

/// The result of a `tools/list` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolsListResult {
    pub tools: Vec<ToolDefinition>,
    #[serde(
        rename = "nextCursor",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub next_cursor: Option<String>,
}

/// Server info from the `initialize` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
}

/// The result of an `initialize` response (partial — we only capture what we need).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeResult {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    #[serde(rename = "serverInfo")]
    pub server_info: ServerInfo,
    #[serde(default)]
    pub capabilities: Option<serde_json::Value>,
}

/// A `tools/call` request's params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallParams {
    pub name: String,
    #[serde(default)]
    pub arguments: Option<serde_json::Value>,
}

impl ToolDefinition {
    /// Get the set of required parameter names from the input schema.
    pub fn required_params(&self) -> Vec<String> {
        self.input_schema
            .get("required")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get the properties object from the input schema.
    pub fn properties(&self) -> Option<&serde_json::Map<String, serde_json::Value>> {
        self.input_schema
            .get("properties")
            .and_then(|v| v.as_object())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tools_list_result() {
        let json = r#"{
            "tools": [{
                "name": "search",
                "description": "Search for items",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": { "type": "string" }
                    },
                    "required": ["query"]
                }
            }]
        }"#;
        let result: ToolsListResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.tools.len(), 1);
        assert_eq!(result.tools[0].name, "search");
        assert_eq!(result.tools[0].required_params(), vec!["query"]);
    }

    #[test]
    fn parse_tool_call_params() {
        let json = r#"{"name": "search", "arguments": {"query": "hello"}}"#;
        let params: ToolCallParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.name, "search");
    }
}
