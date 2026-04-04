use anyhow::Result;
use mcpx_store::Store;

fn print_section(title: &str) {
    eprintln!("{title}");
    eprintln!("{}", "=".repeat(title.len()));
}

/// The `diff` command currently shows the last recorded baseline.
/// Full diffing against a live server requires running the proxy — this
/// command is a placeholder that will be expanded when we add
/// one-shot connection mode (connect, capture, diff, disconnect).
pub fn execute(server_name: &str) -> Result<()> {
    let store = Store::open_default()?;

    match store.get_baseline(server_name)? {
        Some(baseline) => {
            print_section("Diff Status");
            eprintln!("Server    : {}", server_name);
            eprintln!("Tools     : {}", baseline.tools.len());
            eprintln!(
                "Pinned At : {}",
                baseline.pinned_at.format("%Y-%m-%d %H:%M:%S UTC")
            );
            eprintln!();
            print_section("How To View Live Diff");
            eprintln!("1. Start proxy: mcpx run -- <command for {}>", server_name);
            eprintln!("2. Connect your MCP client through mcpx");
            eprintln!(
                "3. Observe schema changes in stderr and `mcpx events {}`",
                server_name
            );
            // TODO: add one-shot mode that connects, captures tools/list, diffs, and exits
        }
        None => {
            eprintln!(
                "No baseline found for '{}'. Run the proxy first to auto-pin.",
                server_name
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    #[test]
    fn command_symbol_exists() {
        let _ = super::execute as fn(&str) -> Result<()>;
    }
}
