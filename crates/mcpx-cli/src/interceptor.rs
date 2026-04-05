use anyhow::Result;
use chrono::Utc;
use mcpx_core::jsonrpc::{Message, Response};
use mcpx_core::mcp::{InitializeResult, ToolCallParams, ToolsListResult};
use mcpx_core::snapshot::{ServerBaseline, ToolSnapshot};
use mcpx_poison::structural;
use mcpx_schema::classify;
use mcpx_schema::diff;
use mcpx_store::Store;
use mcpx_transport::proxy::{BlockReason, Direction, InterceptFn, InterceptResult, ProxyState};
use tracing::{debug, error, info, warn};

const MCPX_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Build the interceptor function that the proxy loop calls on every message.
pub fn build_interceptor() -> Result<InterceptFn> {
    // Open the store once — the interceptor closure captures it.
    let store = Store::open_default()?;

    Ok(Box::new(
        move |raw_msg: &str, direction: Direction, state: &mut ProxyState| match direction {
            Direction::ServerToClient => handle_server_message(raw_msg, state, &store),
            Direction::ClientToServer => handle_client_message(raw_msg, state),
        },
    ))
}

fn handle_server_message(raw: &str, state: &mut ProxyState, store: &Store) -> InterceptResult {
    let parsed: Message = match serde_json::from_str(raw) {
        Ok(m) => m,
        Err(_) => return InterceptResult::Forward(raw.to_string()),
    };

    if let Message::Response(resp) = &parsed {
        let id_key = format!("{:?}", resp.id);

        // Check what method this response is for.
        if let Some(method) = state.pending_requests.remove(&id_key) {
            match method.as_str() {
                "initialize" => {
                    if let Some(result) = &resp.result {
                        if let Ok(init) = serde_json::from_value::<InitializeResult>(result.clone())
                        {
                            info!(
                                server = %init.server_info.name,
                                version = ?init.server_info.version,
                                protocol = %init.protocol_version,
                                "Connected to MCP server"
                            );
                            state.server_info = Some(init);
                        }
                    }
                }
                "tools/list" => {
                    if let Some(result) = &resp.result {
                        if let Ok(tools_result) =
                            serde_json::from_value::<ToolsListResult>(result.clone())
                        {
                            return handle_tools_list(raw, &tools_result, state, store);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    InterceptResult::Forward(raw.to_string())
}

fn handle_client_message(raw: &str, state: &mut ProxyState) -> InterceptResult {
    let parsed: Message = match serde_json::from_str(raw) {
        Ok(m) => m,
        Err(_) => return InterceptResult::Forward(raw.to_string()),
    };

    // Check if client is calling a tool that's been blocked.
    if let Message::Request(ref req) = parsed {
        if req.method == "tools/call" {
            if let Some(params) = &req.params {
                if let Ok(call) = serde_json::from_value::<ToolCallParams>(params.clone()) {
                    if let Some(reason) = state.blocked_tools.get(&call.name) {
                        warn!(
                            tool = %call.name,
                            reason_code = reason.code,
                            event_id = ?reason.event_id,
                            "Blocking tools/call — tool is blocked"
                        );
                        let err_response = Response::error_with_data(
                            req.id.clone(),
                            -32001,
                            format!("[mcpx] Tool '{}' is blocked: {}", call.name, reason.message),
                            Some(serde_json::json!({
                                "reason_code": reason.code,
                                "event_id": reason.event_id,
                                "tool_name": call.name,
                                "remediation_steps": [
                                    "Run `mcpx diff` to review detected drift details",
                                    "Run `mcpx events list <server>` to inspect the recorded event",
                                    "If expected, run `mcpx baselines delete <server>` and reconnect to re-pin"
                                ]
                            })),
                        );
                        let json = serde_json::to_string(&err_response).unwrap();
                        return InterceptResult::Inject(json);
                    }
                }
            }
        }
    }

    InterceptResult::Forward(raw.to_string())
}

fn handle_tools_list(
    raw: &str,
    tools_result: &ToolsListResult,
    state: &mut ProxyState,
    store: &Store,
) -> InterceptResult {
    let server_name = state
        .server_info
        .as_ref()
        .map(|s| s.server_info.name.clone())
        .unwrap_or_else(|| "unknown".to_string());

    let server_version = state
        .server_info
        .as_ref()
        .and_then(|s| s.server_info.version.clone());

    let protocol_version = state
        .server_info
        .as_ref()
        .map(|s| s.protocol_version.clone())
        .unwrap_or_else(|| "unknown".to_string());

    // Capture snapshots of all tools.
    let live_snapshots: Vec<ToolSnapshot> = tools_result
        .tools
        .iter()
        .map(ToolSnapshot::from_definition)
        .collect();

    let current_baseline = ServerBaseline {
        server_name: server_name.clone(),
        server_version: server_version.clone(),
        protocol_version: protocol_version.clone(),
        tools: live_snapshots,
        pinned_at: Utc::now(),
        mcpx_version: MCPX_VERSION.to_string(),
    };

    // Try to load existing baseline from store.
    let existing = match store.get_baseline(&server_name) {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to load baseline: {}", e);
            None
        }
    };

    match existing {
        None => {
            // First time seeing this server — pin the baseline.
            info!(
                server = %server_name,
                tools = current_baseline.tools.len(),
                "No baseline found — auto-pinning"
            );
            if let Err(e) = store.pin_baseline(&current_baseline) {
                error!("Failed to pin baseline: {}", e);
            }
            state.baseline = Some(current_baseline.tools);
            state.baseline_pinned = true;
        }
        Some(baseline) => {
            // Diff against the pinned baseline.
            let report = diff::diff_tools(&server_name, &baseline.tools, &tools_result.tools);

            // Record the snapshot for history.
            if let Err(e) = store.record_snapshot(&server_name, &current_baseline) {
                error!("Failed to record snapshot: {}", e);
            }

            if report.diffs.is_empty() {
                debug!(server = %server_name, "Schema unchanged from baseline");
            } else {
                let summary = classify::summarize(&report);
                // Always log changes to stderr.
                eprintln!("{}", summary);

                // Record the event.
                let detail = serde_json::to_value(&report).ok();
                let event_id = store
                    .record_event(
                        &server_name,
                        if report.has_breaking() {
                            "breaking_change"
                        } else {
                            "schema_change"
                        },
                        detail.as_ref(),
                    )
                    .ok();

                // Run poisoning detection on description changes.
                for d in &report.diffs {
                    if matches!(d.kind, diff::DiffKind::DescriptionChanged) {
                        if let (Some(old), Some(new)) = (&d.old_value, &d.new_value) {
                            let analysis = structural::analyze(&d.tool_name, old, new, 0.85);
                            match analysis.verdict {
                                structural::Verdict::Blocked => {
                                    eprintln!("[mcpx]");
                                    eprintln!("[mcpx]   \x1b[1;31m✘ BLOCKED\x1b[0m  Tool '{}' — poisoning detected", d.tool_name);
                                    if !analysis.injection_patterns.is_empty() {
                                        eprintln!(
                                            "[mcpx]     Patterns:  {}",
                                            analysis.injection_patterns.join(", ")
                                        );
                                    }
                                    if !analysis.hidden_chars.is_empty() {
                                        eprintln!(
                                            "[mcpx]     Hidden:    {}",
                                            analysis.hidden_chars.join(", ")
                                        );
                                    }
                                    eprintln!(
                                        "[mcpx]     Structural similarity: {:.2}",
                                        analysis.structural_similarity
                                    );
                                    if let Some(sem) = analysis.semantic_similarity {
                                        eprintln!("[mcpx]     Semantic similarity:  {:.2}", sem);
                                    }
                                    eprintln!("[mcpx]     Old: \"{}\"", truncate_desc(old, 80));
                                    eprintln!("[mcpx]     New: \"{}\"", truncate_desc(new, 80));
                                    state.blocked_tools.insert(
                                        d.tool_name.clone(),
                                        BlockReason {
                                            code: "prompt_poisoning_detected",
                                            message: "description drift matched prompt-injection patterns".to_string(),
                                            event_id,
                                        },
                                    );
                                }
                                structural::Verdict::Suspicious => {
                                    eprintln!("[mcpx]");
                                    eprintln!("[mcpx]   \x1b[1;33m⚠ SUSPICIOUS\x1b[0m  Tool '{}' — description drift", d.tool_name);
                                    eprintln!(
                                        "[mcpx]     Structural similarity: {:.2}",
                                        analysis.structural_similarity
                                    );
                                    if let Some(sem) = analysis.semantic_similarity {
                                        eprintln!("[mcpx]     Semantic similarity:  {:.2}", sem);
                                    }
                                    eprintln!("[mcpx]     Old: \"{}\"", truncate_desc(old, 80));
                                    eprintln!("[mcpx]     New: \"{}\"", truncate_desc(new, 80));
                                }
                                structural::Verdict::Clean => {}
                            }
                        }
                    }
                }

                // Block tools with breaking changes.
                if report.has_breaking() {
                    for d in &report.diffs {
                        if d.severity == diff::Severity::Breaking {
                            state
                                .blocked_tools
                                .entry(d.tool_name.clone())
                                .or_insert(BlockReason {
                                    code: "breaking_schema_change",
                                    message:
                                        "breaking schema changes detected since pinned baseline"
                                            .to_string(),
                                    event_id,
                                });
                        }
                    }
                }
            }

            state.baseline = Some(baseline.tools);
            state.baseline_pinned = true;
        }
    }

    // Always forward the tools/list response — we don't modify it,
    // we just observe and potentially block individual tool calls later.
    InterceptResult::Forward(raw.to_string())
}

fn truncate_desc(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpx_transport::proxy::ProxyState;

    #[test]
    fn blocked_tool_call_is_injected_with_error() {
        let mut state = ProxyState::new();
        state.blocked_tools.insert(
            "search".into(),
            BlockReason {
                code: "breaking_schema_change",
                message: "breaking schema changes detected since pinned baseline".into(),
                event_id: Some(42),
            },
        );

        let raw = r#"{
            "jsonrpc":"2.0",
            "id":1,
            "method":"tools/call",
            "params":{"name":"search","arguments":{"q":"x"}}
        }"#;

        match handle_client_message(raw, &mut state) {
            InterceptResult::Inject(json) => {
                let response: Response = serde_json::from_str(&json).unwrap();
                let error = response.error.unwrap();
                assert_eq!(error.code, -32001);
                assert_eq!(error.data.unwrap()["reason_code"], "breaking_schema_change");
            }
            _ => panic!("expected injected error response"),
        }
    }

    #[test]
    fn unblocked_tool_call_is_forwarded() {
        let mut state = ProxyState::new();
        let raw = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search"}}"#;

        match handle_client_message(raw, &mut state) {
            InterceptResult::Forward(msg) => assert_eq!(msg, raw),
            _ => panic!("expected forwarded message"),
        }
    }

    #[test]
    fn invalid_json_is_forwarded() {
        let mut state = ProxyState::new();
        let raw = "not-json";

        match handle_client_message(raw, &mut state) {
            InterceptResult::Forward(msg) => assert_eq!(msg, raw),
            _ => panic!("expected forwarded message"),
        }
    }
}
