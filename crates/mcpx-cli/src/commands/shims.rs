use anyhow::Result;
use mcpx_store::Store;

fn print_section(title: &str) {
    eprintln!("{title}");
    eprintln!("{}", "=".repeat(title.len()));
}

pub fn list(server_name: &str) -> Result<()> {
    let store = Store::open_default()?;
    let shims = store.list_shims(server_name)?;

    if shims.is_empty() {
        eprintln!(
            "No shim proposals/decisions found for server '{}'.",
            server_name
        );
        return Ok(());
    }

    print_section("Shim Decisions");
    eprintln!("Server: {}", server_name);
    eprintln!();
    for s in shims {
        eprintln!(
            "[{}] {}  tool={}  status={}",
            s.id,
            s.updated_at.format("%Y-%m-%d %H:%M:%S UTC"),
            s.tool_name,
            s.status
        );
        let mappings = serde_json::to_string_pretty(&s.mappings)?;
        eprintln!("    mappings:");
        for line in mappings.lines() {
            eprintln!("      {}", line);
        }
        eprintln!();
    }
    Ok(())
}

pub fn approve(server_name: &str, tool_name: &str) -> Result<()> {
    let store = Store::open_default()?;
    if store.approve_latest_shim(server_name, tool_name)? {
        eprintln!(
            "Approved latest shim proposal for server='{}' tool='{}'.",
            server_name, tool_name
        );
    } else {
        eprintln!(
            "No proposed shim found to approve for server='{}' tool='{}'.",
            server_name, tool_name
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    #[test]
    fn command_symbols_exist() {
        let _ = super::list as fn(&str) -> Result<()>;
        let _ = super::approve as fn(&str, &str) -> Result<()>;
    }
}
