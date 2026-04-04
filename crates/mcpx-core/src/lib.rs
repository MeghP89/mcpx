pub mod jsonrpc;
pub mod mcp;
pub mod snapshot;

#[cfg(test)]
mod tests {
    #[test]
    fn exports_are_accessible() {
        let _ = super::jsonrpc::Message::from_bytes
            as fn(&[u8]) -> Result<super::jsonrpc::Message, serde_json::Error>;
        let _ = super::mcp::ToolDefinition::required_params
            as fn(&super::mcp::ToolDefinition) -> Vec<String>;
        let _ = super::snapshot::ToolSnapshot::from_definition
            as fn(&super::mcp::ToolDefinition) -> super::snapshot::ToolSnapshot;
    }
}
