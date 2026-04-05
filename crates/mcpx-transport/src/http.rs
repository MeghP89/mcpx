use futures_util::StreamExt;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tracing::{debug, error};

/// A transport for handling HTTP communication with an upstream MCP server.
/// This is used when the downstream server is remote, and we want to forward
/// JSON-RPC messages over HTTP instead of stdio.
pub struct HttpTransport {
    client: reqwest::Client,
    upstream_url: String,
    session_id: Arc<Mutex<Option<String>>>,
    /// Send messages TO the remote server's stdin.
    pub tx_to_server: mpsc::Sender<String>,
    /// Receive messages FROM the remote server's stdout.
    pub rx_from_server: mpsc::Receiver<String>,
}

impl HttpTransport {
    pub async fn connect(upstream_url: &str, header_args: &[String]) -> anyhow::Result<Self> {
        let client = reqwest::Client::new();
        let session_id = Arc::new(Mutex::new(None));

        // proxy -> server
        let (tx_to_server, mut rx_to_server) = mpsc::channel::<String>(256);
        // server -> proxy
        let (tx_from_server, rx_from_server) = mpsc::channel::<String>(256);

        let url = upstream_url.to_string();
        let session_id_clone = session_id.clone();
        let client_clone = client.clone();

        // Parse custom headers
        let mut headers = reqwest::header::HeaderMap::new();
        for header in header_args {
            if let Some((key, value)) = header.split_once(':') {
                match (
                    reqwest::header::HeaderName::from_str(key.trim()),
                    reqwest::header::HeaderValue::from_str(value.trim()),
                ) {
                    (Ok(k), Ok(v)) => {
                        headers.insert(k, v);
                    }
                    _ => {
                        eprintln!("[mcpx] Skipping invalid header: {}", header);
                    }
                }
            }
        }

        tokio::spawn(async move {
            while let Some(msg) = rx_to_server.recv().await {
                // Build the POST request
                let mut req = client_clone
                    .post(&url)
                    .headers(headers.clone())
                    .header("content-type", "application/json")
                    .header("Accept", "application/json, text/event-stream");

                // Include session ID if we have one
                if let Some(session) = session_id_clone.lock().await.as_ref() {
                    req = req.header("Mcp-Session-ID", session);
                }

                let resp = match req.body(msg).send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("HTTP request error: {}", e);
                        continue;
                    }
                };

                // Capture the session ID from the response headers if we don't have one yet
                if let Some(id) = resp.headers().get("Mcp-Session-ID") {
                    if let Ok(val) = id.to_str() {
                        let mut lock = session_id_clone.lock().await;
                        if lock.is_none() {
                            *lock = Some(val.to_string());
                            debug!("Captured session ID: {}", val);
                        }
                    }
                }

                // Check content type and handle response accordingly
                let content_type = resp
                    .headers()
                    .get("content-type")
                    .and_then(|ct| ct.to_str().ok())
                    .unwrap_or("")
                    .to_string();

                if content_type.contains("text/event-stream") {
                    // Handle event stream response
                    let mut stream = resp.bytes_stream();
                    let mut buffer = String::new();
                    while let Some(item) = stream.next().await {
                        match item {
                            Ok(chunk) => {
                                let text = match std::str::from_utf8(&chunk) {
                                    Ok(t) => t,
                                    Err(_) => {
                                        error!("Received non-UTF8 chunk in event stream");
                                        continue;
                                    }
                                };

                                buffer.push_str(text);

                                while let Some(newline_pos) = buffer.find('\n') {
                                    let line = buffer[..newline_pos].trim().to_string();
                                    buffer = buffer[newline_pos + 1..].to_string();

                                    if let Some(data) = line.strip_prefix("data:") {
                                        let payload = data.trim();
                                        if !payload.is_empty()
                                            && tx_from_server
                                                .send(payload.to_string())
                                                .await
                                                .is_err()
                                        {
                                            return;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Error reading event stream: {}", e);
                                break;
                            }
                        }
                    }
                } else {
                    match resp.text().await {
                        Ok(body) if !body.trim().is_empty() => {
                            if tx_from_server.send(body).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => error!("Failed to read response body: {}", e),
                        _ => {}
                    }
                }
            }
        });
        Ok(Self {
            client,
            upstream_url: upstream_url.to_string(),
            session_id,
            tx_to_server,
            rx_from_server,
        })
    }

    pub async fn shutdown(&self) -> anyhow::Result<()> {
        // Send DELETE to close session
        if let Some(id) = self.session_id.lock().await.as_ref() {
            let _ = self
                .client
                .delete(&self.upstream_url)
                .header("Mcp-Session-ID", id)
                .send()
                .await;
            debug!("Sent session shutdown request");
        }
        Ok(())
    }
}
