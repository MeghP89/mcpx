use anyhow::Result;
use mcpx_store::Store;

fn print_section(title: &str) {
    eprintln!("{title}");
    eprintln!("{}", "=".repeat(title.len()));
}

pub fn list() -> Result<()> {
    let store = Store::open_default()?;
    let names = store.list_baselines()?;

    if names.is_empty() {
        eprintln!(
            "No baselines pinned yet. Run `mcpx run -- <command>` to auto-pin on first connection."
        );
        return Ok(());
    }

    let mut rows: Vec<(String, usize, String)> = Vec::new();
    for name in &names {
        let baseline = store.get_baseline(name)?;
        if let Some(b) = baseline {
            rows.push((
                b.server_name,
                b.tools.len(),
                b.pinned_at.format("%Y-%m-%d %H:%M UTC").to_string(),
            ));
        }
    }

    print_section("Pinned Baselines");
    let server_w = rows
        .iter()
        .map(|(s, _, _)| s.len())
        .max()
        .unwrap_or(6)
        .max("Server".len());
    eprintln!(
        "{:<server_w$}  {:>5}  Pinned At (UTC)",
        "Server",
        "Tools",
        server_w = server_w
    );
    eprintln!(
        "{}",
        "-".repeat(server_w + 2 + 5 + 2 + "Pinned At (UTC)".len())
    );
    for (server, tools, pinned) in rows {
        eprintln!(
            "{:<server_w$}  {:>5}  {}",
            server,
            tools,
            pinned,
            server_w = server_w
        );
    }
    Ok(())
}

pub fn show(server_name: &str) -> Result<()> {
    let store = Store::open_default()?;
    match store.get_baseline(server_name)? {
        Some(baseline) => {
            print_section("Baseline Details");
            eprintln!("Server    : {}", baseline.server_name);
            eprintln!(
                "Version   : {}",
                baseline.server_version.as_deref().unwrap_or("unknown")
            );
            eprintln!("Protocol  : {}", baseline.protocol_version);
            eprintln!(
                "Pinned At : {}",
                baseline.pinned_at.format("%Y-%m-%d %H:%M:%S UTC")
            );
            eprintln!("Tools     : {}", baseline.tools.len());
            eprintln!();

            print_section("Tools");
            for tool in &baseline.tools {
                eprintln!("- {}", tool.name,);
                eprintln!(
                    "  Description: {}",
                    tool.description.as_deref().unwrap_or("(no description)")
                );
                let props = tool
                    .input_schema
                    .get("properties")
                    .and_then(|v| v.as_object());
                if let Some(p) = props {
                    eprintln!("  Parameters:");
                    for (key, schema) in p {
                        let typ = schema.get("type").and_then(|v| v.as_str()).unwrap_or("any");
                        eprintln!("    - {}: {}", key, typ);
                    }
                } else {
                    eprintln!("  Parameters: (none)");
                }
            }
            Ok(())
        }
        None => {
            eprintln!("No baseline found for server '{}'.", server_name);
            Ok(())
        }
    }
}

pub fn delete(server_name: &str) -> Result<()> {
    let store = Store::open_default()?;
    if store.delete_baseline(server_name)? {
        eprintln!("Deleted baseline for '{}'.", server_name);
    } else {
        eprintln!("No baseline found for '{}'.", server_name);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    #[test]
    fn command_symbols_exist() {
        let _ = super::list as fn() -> Result<()>;
        let _ = super::show as fn(&str) -> Result<()>;
        let _ = super::delete as fn(&str) -> Result<()>;
    }
}
