pub mod classify;
pub mod diff;
pub mod shim;

#[cfg(test)]
mod tests {
    #[test]
    fn exports_are_accessible() {
        let _ = super::diff::diff_tools
            as fn(
                &str,
                &[mcpx_core::snapshot::ToolSnapshot],
                &[mcpx_core::mcp::ToolDefinition],
            ) -> super::diff::DiffReport;
        let _ = super::classify::summarize as fn(&super::diff::DiffReport) -> String;
        let _ = super::shim::rewrite_tool_call_args
            as fn(&str, &serde_json::Value) -> serde_json::Value;
    }
}
