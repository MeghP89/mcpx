use anyhow::{bail, Result};
use tracing::info;

use crate::interceptor;
use mcpx_transport::proxy;

/// Execute the `mcpx run` command — spawn the downstream server and proxy all traffic.
pub async fn execute(
    upstream: &Option<String>,
    header_args: &[String],
    command_args: &[String],
) -> Result<()> {
    if upstream.is_some() && !command_args.is_empty() {
        bail!("Cannot use --upstream and a command at the same time. Use one or the other.");
    }
    if upstream.is_none() && command_args.is_empty() {
        bail!(
            "Provide either --upstream <url> or a command after --\n\
               Examples:\n  mcpx run -- npx -y @modelcontextprotocol/server-github\n  \
               mcpx run --upstream https://mcp.example.com/mcp"
        );
    }

    let interceptor = interceptor::build_interceptor()?;

    match upstream {
        Some(url) => {
            info!(upstream_url = %url, "Running in upstream mode");
            proxy::run_http_proxy(url, header_args, interceptor).await?;
        }
        None => {
            let command = &command_args[0];
            let args = &command_args[1..];
            info!(command = %command, args = ?args, "Running in local process mode");
            proxy::run_stdio_proxy(command, args, interceptor).await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn empty_command_args_returns_error() {
        let result = super::execute(&None, &[], &[]).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn both_upstream_and_command_returns_error() {
        let args = vec!["echo".to_string()];
        let result = super::execute(&Some("https://example.com/mcp".into()), &[], &args).await;
        assert!(result.is_err());
    }
}
