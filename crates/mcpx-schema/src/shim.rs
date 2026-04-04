//! Request rewriting / backwards-compatibility shimming.
//! Planned for v0.2; this module currently exposes a no-op placeholder.

/// Rewrite `tools/call` arguments to preserve compatibility across schema changes.
///
/// Current behavior: no-op passthrough until shim rules are implemented.
pub fn rewrite_tool_call_args(
    _tool_name: &str,
    args: &serde_json::Value,
) -> serde_json::Value {
    args.clone()
}

#[cfg(test)]
mod tests {
    #[test]
    fn rewrite_is_passthrough_for_now() {
        let input = serde_json::json!({"q": "hello", "limit": 10});
        let output = super::rewrite_tool_call_args("search", &input);
        assert_eq!(output, input);
    }
}
