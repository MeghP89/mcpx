use anyhow::{bail, Result};
use tracing::info;

use crate::interceptor;
use mcpx_transport::proxy;

/// Execute the `mcpx run` command — spawn the downstream server and proxy all traffic.
pub async fn execute(command_args: &[String]) -> Result<()> {
    if command_args.is_empty() {
        bail!("No command specified. Usage: mcpx run -- <command> [args...]");
    }

    let command = &command_args[0];
    let args = &command_args[1..];

    info!(
        command = %command,
        args = ?args,
        "Starting mcpx proxy"
    );

    let interceptor = interceptor::build_interceptor()?;

    proxy::run_stdio_proxy(command, args, interceptor).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn empty_command_args_returns_error() {
        let args: Vec<String> = vec![];
        let result = super::execute(&args).await;
        assert!(result.is_err());
    }
}
