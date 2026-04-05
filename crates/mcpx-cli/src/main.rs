mod commands;
mod interceptor;

use clap::{Parser, Subcommand};

const CLI_AFTER_HELP: &str = "\
Examples:
  mcpx run -- uv run main.py
  mcpx run --auto-approve-shims -- uv run main.py
  mcpx run -- npx -y @modelcontextprotocol/server-github
  mcpx run --upstream https://example.com/mcp -H \"Authorization: Bearer abc123\"
  mcpx baselines list
  mcpx baselines show MyTestServer
  mcpx diff MyTestServer
  mcpx events MyTestServer --limit 50
  mcpx shims list MyTestServer
  mcpx shims approve MyTestServer search
  mcpx ci scan --baseline MyTestServer --target ./live-schema.json --format sarif --out report.sarif
Workflow:
  1) Run your MCP server through `mcpx run -- ...`
  2) First `tools/list` auto-pins a baseline
  3) Use `baselines` and `events` to inspect drift history
";

#[derive(Parser)]
#[command(
    name = "mcpx",
    about = "MCP Schema Guardian Proxy for runtime schema drift and poisoning detection",
    long_about = "mcpx is a transparent MCP proxy that monitors tool schema/description changes at runtime, records audit history, and blocks unsafe tool calls when breaking drift or poisoning is detected.",
    after_help = CLI_AFTER_HELP,
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging (repeat for more: -v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
}

#[derive(Subcommand)]
enum Commands {
    /// Run as a transparent proxy wrapping an MCP server
    Run {
        /// Connect to a remote MCP server over HTTP instead of spawning a local process
        #[arg(long)]
        upstream: Option<String>,
        /// Custom headers to include in HTTP requests when using --upstream. Format: "Header-Name: value"
        #[arg(long, short = 'H')]
        header: Vec<String>,
        /// The command and arguments to spawn the MCP server.
        /// Separate from mcpx args with --.
        /// Example: mcpx run -- npx -y @modelcontextprotocol/server-github
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
        /// Auto-approve and apply eligible trivial shims instead of requiring manual approval.
        #[arg(long, default_value_t = false)]
        auto_approve_shims: bool,
    },

    /// Manage pinned baselines (list/show/delete)
    Baselines {
        #[command(subcommand)]
        action: BaselinesAction,
    },

    /// Show baseline summary for a server and how to perform live diffing
    Diff {
        /// Server name to diff
        server_name: String,
    },

    /// Show recent audit events for a server
    Events {
        /// Server name
        server_name: String,
        /// Maximum number of events to show
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },

    /// List and approve shim proposals
    Shims {
        #[command(subcommand)]
        action: ShimsAction,
    },

    /// CI/CD pipeline integration and schema scanning
    Ci {
        #[command(subcommand)]
        action: CiAction,
    },
}

#[derive(Subcommand)]
enum BaselinesAction {
    /// List all pinned baselines
    List,
    /// Show details of a specific baseline
    Show {
        /// Server name
        server_name: String,
    },
    /// Delete a pinned baseline
    Delete {
        /// Server name
        server_name: String,
    },
}

#[derive(Subcommand)]
enum ShimsAction {
    /// List shim proposals/decisions for a server
    List {
        /// Server name
        server_name: String,
    },
    /// Approve latest shim proposal for a specific tool
    Approve {
        /// Server name
        server_name: String,
        /// Tool name
        tool_name: String,
    },
}

#[derive(Subcommand)]
enum CiAction {
    /// Scan a target schema against a baseline for CI reporting
    Scan {
        /// Path or name of the pinned baseline
        #[arg(long)]
        baseline: String,

        /// Path to the live/target schema to check
        #[arg(long)]
        target: String,

        /// Output format (json, sarif, or both)
        #[arg(long, default_value = "json")]
        format: String,

        /// Output file path (prints to stdout if omitted)
        #[arg(long)]
        out: Option<std::path::PathBuf>,

        /// Minimum severity that triggers a non-zero exit code (warning, breaking, blocked)
        #[arg(long, default_value = "breaking")]
        fail_on: String,
        /// Suppress one or more rule IDs (repeatable), e.g. --suppress MCPX-POISON-PARAM-NAME
        #[arg(long)]
        suppress: Vec<String>,
        /// Optional path to previous mcpx JSON report; when set, only new findings fail the build
        #[arg(long)]
        only_new_since: Option<std::path::PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Set up tracing based on verbosity.
    let filter = match cli.verbose {
        0 => "mcpx=info",
        1 => "mcpx=debug",
        2 => "mcpx=trace",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr) // MCP stdio uses stdout, so logs go to stderr
        .init();

    match cli.command {
        Commands::Run {
            upstream,
            header,
            command,
            auto_approve_shims,
        } => {
            commands::run::execute(&upstream, &header, &command, auto_approve_shims).await?;
        }
        Commands::Baselines { action } => match action {
            BaselinesAction::List => commands::baselines::list()?,
            BaselinesAction::Show { server_name } => commands::baselines::show(&server_name)?,
            BaselinesAction::Delete { server_name } => commands::baselines::delete(&server_name)?,
        },
        Commands::Diff { server_name } => {
            commands::diff::execute(&server_name)?;
        }
        Commands::Events { server_name, limit } => {
            commands::events::list(&server_name, limit)?;
        }
        Commands::Shims { action } => match action {
            ShimsAction::List { server_name } => commands::shims::list(&server_name)?,
            ShimsAction::Approve {
                server_name,
                tool_name,
            } => commands::shims::approve(&server_name, &tool_name)?,
        },
        Commands::Ci { action } => match action {
            CiAction::Scan {
                baseline,
                target,
                format,
                out,
                fail_on,
                suppress,
                only_new_since,
            } => commands::ci::scan(
                &baseline,
                &target,
                &format,
                out,
                &fail_on,
                &suppress,
                only_new_since,
            )?,
        },
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_events_with_default_limit() {
        let cli = Cli::try_parse_from(["mcpx", "events", "demo-server"]).unwrap();
        match cli.command {
            Commands::Events { server_name, limit } => {
                assert_eq!(server_name, "demo-server");
                assert_eq!(limit, 20);
            }
            _ => panic!("expected events command"),
        }
    }

    #[test]
    fn parses_events_with_custom_limit() {
        let cli = Cli::try_parse_from(["mcpx", "events", "demo-server", "--limit", "7"]).unwrap();
        match cli.command {
            Commands::Events { server_name, limit } => {
                assert_eq!(server_name, "demo-server");
                assert_eq!(limit, 7);
            }
            _ => panic!("expected events command"),
        }
    }

    #[test]
    fn parses_run_with_trailing_args() {
        let cli = Cli::try_parse_from(["mcpx", "run", "--", "echo", "hello"]).unwrap();
        match cli.command {
            Commands::Run {
                command,
                header,
                upstream,
                auto_approve_shims,
            } => {
                assert_eq!(command, vec!["echo".to_string(), "hello".to_string()]);
                assert_eq!(header, Vec::<String>::new());
                assert_eq!(upstream, None);
                assert!(!auto_approve_shims);
            }
            _ => panic!("expected run command"),
        }
    }

    #[test]
    fn parses_shims_list() {
        let cli = Cli::try_parse_from(["mcpx", "shims", "list", "demo-server"]).unwrap();
        match cli.command {
            Commands::Shims { action } => match action {
                ShimsAction::List { server_name } => assert_eq!(server_name, "demo-server"),
                _ => panic!("expected shims list command"),
            },
            _ => panic!("expected shims command"),
        }
    }

    #[test]
    fn parses_ci_scan() {
        let cli = Cli::try_parse_from([
            "mcpx",
            "ci",
            "scan",
            "--baseline",
            "demo-server",
            "--target",
            "./live-schema.json",
            "--format",
            "sarif",
            "--fail-on",
            "blocked",
            "--suppress",
            "MCPX-POISON-PARAM-NAME",
        ])
        .unwrap();
        match cli.command {
            Commands::Ci { action } => match action {
                CiAction::Scan {
                    baseline,
                    target,
                    format,
                    fail_on,
                    suppress,
                    ..
                } => {
                    assert_eq!(baseline, "demo-server");
                    assert_eq!(target, "./live-schema.json");
                    assert_eq!(format, "sarif");
                    assert_eq!(fail_on, "blocked");
                    assert_eq!(suppress, vec!["MCPX-POISON-PARAM-NAME".to_string()]);
                }
            },
            _ => panic!("expected ci command"),
        }
    }
}
