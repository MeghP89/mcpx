use anyhow::Result;
use mcpx_store::Store;

fn print_section(title: &str) {
    eprintln!("{title}");
    eprintln!("{}", "=".repeat(title.len()));
}

pub fn list(server_name: &str, limit: usize) -> Result<()> {
    let store = Store::open_default()?;
    let events = store.list_events(server_name, limit)?;

    if events.is_empty() {
        eprintln!("No events found for server '{}'.", server_name);
        return Ok(());
    }

    print_section("Audit Events");
    eprintln!("Server: {}", server_name);
    eprintln!("Limit : {}", limit);
    eprintln!();

    for (idx, event) in events.into_iter().enumerate() {
        eprintln!(
            "[{}] {}  {}",
            idx + 1,
            event.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
            event.event_type
        );
        if let Some(detail) = event.detail {
            let detail_json = serde_json::to_string_pretty(&detail)?;
            eprintln!("    Details:");
            for line in detail_json.lines() {
                eprintln!("      {}", line);
            }
        }
        eprintln!();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    #[test]
    fn command_symbol_exists() {
        let _ = super::list as fn(&str, usize) -> Result<()>;
    }
}
