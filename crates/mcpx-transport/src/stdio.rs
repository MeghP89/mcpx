use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tracing::{debug, error, trace};

/// A stdio transport that spawns a child MCP server process
/// and provides channels for bidirectional JSON-RPC communication.
pub struct StdioTransport {
    child: Child,
    /// Send messages TO the child server's stdin.
    pub tx_to_server: mpsc::Sender<String>,
    /// Receive messages FROM the child server's stdout.
    pub rx_from_server: mpsc::Receiver<String>,
}

impl StdioTransport {
    /// Spawn a child process and wire up stdin/stdout channels.
    ///
    /// `command` is the program to run, `args` are its arguments.
    /// Environment variables are inherited from the current process.
    pub async fn spawn(command: &str, args: &[String]) -> Result<Self> {
        let mut child = Command::new(command)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit()) // pass server stderr through
            .spawn()
            .with_context(|| format!("Failed to spawn MCP server: {} {:?}", command, args))?;

        let child_stdin = child.stdin.take().expect("stdin was piped");
        let child_stdout = child.stdout.take().expect("stdout was piped");

        // Channel: proxy → server stdin
        let (tx_to_server, mut rx_to_server) = mpsc::channel::<String>(256);

        // Channel: server stdout → proxy
        let (tx_from_server, rx_from_server) = mpsc::channel::<String>(256);

        // Task: read from rx_to_server, write to child stdin
        tokio::spawn(async move {
            let mut stdin = child_stdin;
            while let Some(msg) = rx_to_server.recv().await {
                trace!(direction = "→server", bytes = msg.len(), "writing to server stdin");
                if let Err(e) = stdin.write_all(msg.as_bytes()).await {
                    error!("Failed to write to server stdin: {}", e);
                    break;
                }
                if let Err(e) = stdin.write_all(b"\n").await {
                    error!("Failed to write newline to server stdin: {}", e);
                    break;
                }
                if let Err(e) = stdin.flush().await {
                    error!("Failed to flush server stdin: {}", e);
                    break;
                }
            }
            debug!("Server stdin writer exiting");
        });

        // Task: read from child stdout, send to tx_from_server
        tokio::spawn(async move {
            let reader = BufReader::new(child_stdout);
            let mut lines = reader.lines();
            loop {
                match lines.next_line().await {
                    Ok(Some(line)) => {
                        if line.trim().is_empty() {
                            continue;
                        }
                        trace!(direction = "←server", bytes = line.len(), "read from server stdout");
                        if tx_from_server.send(line).await.is_err() {
                            debug!("Server stdout reader: receiver dropped");
                            break;
                        }
                    }
                    Ok(None) => {
                        debug!("Server stdout closed (EOF)");
                        break;
                    }
                    Err(e) => {
                        error!("Error reading server stdout: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(Self {
            child,
            tx_to_server,
            rx_from_server,
        })
    }

    /// Wait for the child process to exit.
    pub async fn wait(&mut self) -> Result<std::process::ExitStatus> {
        self.child
            .wait()
            .await
            .context("Failed to wait for child process")
    }

    /// Kill the child process.
    pub async fn kill(&mut self) -> Result<()> {
        self.child.kill().await.context("Failed to kill child process")
    }
}

/// Read JSON-RPC messages from our own stdin (the client side).
/// Returns a receiver that yields one line per message.
pub fn read_client_stdin() -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel::<String>(256);

    tokio::spawn(async move {
        let stdin = tokio::io::stdin();
        let reader = BufReader::new(stdin);
        let mut lines = reader.lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    if line.trim().is_empty() {
                        continue;
                    }
                    trace!(direction = "←client", bytes = line.len(), "read from client stdin");
                    if tx.send(line).await.is_err() {
                        debug!("Client stdin reader: receiver dropped");
                        break;
                    }
                }
                Ok(None) => {
                    debug!("Client stdin closed (EOF)");
                    break;
                }
                Err(e) => {
                    error!("Error reading client stdin: {}", e);
                    break;
                }
            }
        }
    });

    rx
}

/// Write a JSON-RPC message to our own stdout (back to the client).
pub async fn write_client_stdout(msg: &str) -> Result<()> {
    let mut stdout = tokio::io::stdout();
    stdout
        .write_all(msg.as_bytes())
        .await
        .context("Failed to write to stdout")?;
    stdout
        .write_all(b"\n")
        .await
        .context("Failed to write newline to stdout")?;
    stdout.flush().await.context("Failed to flush stdout")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{read_client_stdin, write_client_stdout, StdioTransport};

    #[tokio::test]
    async fn spawn_invalid_command_fails() {
        let args: Vec<String> = vec![];
        let result = StdioTransport::spawn("definitely-not-a-real-command-mcpx", &args).await;
        assert!(result.is_err());
    }

    #[test]
    fn api_symbols_exist() {
        let _ = read_client_stdin as fn() -> tokio::sync::mpsc::Receiver<String>;
        let _ = write_client_stdout;
    }
}
