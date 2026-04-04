use std::collections::HashMap;
use std::sync::Arc;

use mcpx_core::jsonrpc::Message;
use mcpx_core::mcp::InitializeResult;
use mcpx_core::snapshot::ToolSnapshot;
use tokio::sync::Mutex;
use tracing::{debug, info};

use crate::stdio;

/// Tracks state needed by the interceptor across the proxy lifetime.
pub struct ProxyState {
    /// Map of pending request IDs to their method names.
    /// We need this to identify which responses correspond to `tools/list`.
    pub pending_requests: HashMap<String, String>,
    /// Server info captured from `initialize` response.
    pub server_info: Option<InitializeResult>,
    /// The pinned baseline (loaded from DB or captured on first `tools/list`).
    pub baseline: Option<Vec<ToolSnapshot>>,
    /// Tools that have been flagged as having breaking changes.
    pub blocked_tools: Vec<String>,
    /// Whether the baseline has been set (first connection complete).
    pub baseline_pinned: bool,
}

impl ProxyState {
    pub fn new() -> Self {
        Self {
            pending_requests: HashMap::new(),
            server_info: None,
            baseline: None,
            blocked_tools: Vec::new(),
            baseline_pinned: false,
        }
    }
}

impl Default for ProxyState {
    fn default() -> Self {
        Self::new()
    }
}

/// The interceptor callback type.
/// Takes a raw JSON string (a single JSON-RPC message), the direction,
/// and the shared proxy state. Returns:
/// - `Ok(Some(msg))` to forward the (possibly modified) message
/// - `Ok(None)` to suppress the message (don't forward)
/// - `Err(response)` to inject an error response back to the client
pub enum InterceptResult {
    /// Forward this message (possibly modified).
    Forward(String),
    /// Suppress this message entirely.
    Suppress,
    /// Inject this response back to the client instead of forwarding.
    Inject(String),
}

#[derive(Debug, Clone, Copy)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

/// The interceptor function signature.
pub type InterceptFn = Box<
    dyn Fn(&str, Direction, &mut ProxyState) -> InterceptResult,
>;

/// Run the stdio proxy loop.
///
/// Spawns the downstream MCP server, reads from client stdin and server stdout,
/// runs each message through the interceptor chain, and forwards accordingly.
pub async fn run_stdio_proxy(
    command: &str,
    args: &[String],
    interceptor: InterceptFn,
) -> anyhow::Result<()> {
    let mut transport = stdio::StdioTransport::spawn(command, args).await?;
    let mut client_rx = stdio::read_client_stdin();

    let state = Arc::new(Mutex::new(ProxyState::new()));

    info!(command = command, "mcpx proxy started");

    loop {
        tokio::select! {
            // Message from client → intercept → forward to server
            Some(msg) = client_rx.recv() => {
                let mut st = state.lock().await;

                // Track request IDs so we can identify responses.
                if let Ok(parsed) = serde_json::from_str::<Message>(&msg) {
                    if let Message::Request(ref req) = parsed {
                        let id_key = format!("{:?}", req.id);
                        st.pending_requests.insert(id_key, req.method.clone());
                    }
                }

                match (interceptor)(&msg, Direction::ClientToServer, &mut st) {
                    InterceptResult::Forward(m) => {
                        if transport.tx_to_server.send(m).await.is_err() {
                            debug!("Server channel closed, exiting");
                            break;
                        }
                    }
                    InterceptResult::Suppress => {
                        debug!("Suppressed client→server message");
                    }
                    InterceptResult::Inject(response) => {
                        stdio::write_client_stdout(&response).await?;
                    }
                }
            }

            // Message from server → intercept → forward to client
            Some(msg) = transport.rx_from_server.recv() => {
                let mut st = state.lock().await;

                match (interceptor)(&msg, Direction::ServerToClient, &mut st) {
                    InterceptResult::Forward(m) => {
                        stdio::write_client_stdout(&m).await?;
                    }
                    InterceptResult::Suppress => {
                        debug!("Suppressed server→client message");
                    }
                    InterceptResult::Inject(response) => {
                        // Unusual for server→client direction, but supported.
                        stdio::write_client_stdout(&response).await?;
                    }
                }
            }

            // Both channels closed
            else => {
                debug!("All channels closed, exiting proxy loop");
                break;
            }
        }
    }

    info!("mcpx proxy shutting down");
    let _ = transport.kill().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_state_defaults_are_empty() {
        let state = ProxyState::new();
        assert!(state.pending_requests.is_empty());
        assert!(state.server_info.is_none());
        assert!(state.baseline.is_none());
        assert!(state.blocked_tools.is_empty());
        assert!(!state.baseline_pinned);
    }

    #[test]
    fn default_matches_new() {
        let state = ProxyState::default();
        assert!(state.pending_requests.is_empty());
        assert!(state.blocked_tools.is_empty());
    }
}
