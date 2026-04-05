# mcpx

**MCP Schema Guardian Proxy** — runtime detection of breaking schema changes, poisoning attempts, and controlled backwards-compatible request translation for Model Context Protocol servers.

## The Problem

MCP servers expose tool schemas at runtime with no versioning contract. When a server updates — renaming a parameter, changing a type, altering a description — clients break **silently**. The LLM doesn't crash. It hallucinates a workaround, producing confident wrong answers.

Worse, attackers can exploit this by subtly editing tool descriptions to redirect agent behavior ([tool poisoning](https://owasp.org/www-project-top-10-for-large-language-model-applications/)). A single description change can make your agent exfiltrate credentials without any schema violation.

**No existing tool catches this at runtime.** CI tools like `mcpdiff` catch changes at build time, but only for servers you control. MCP gateways handle auth and routing but pass schemas through unchanged.

## What mcpx Does

mcpx is a transparent proxy that sits between your MCP client and server:

```
┌────────────┐       ┌────────┐       ┌────────────┐
│ Claude     │◄─────►│  mcpx  │◄─────►│ MCP Server │
│ Desktop    │ stdio │        │ stdio │ (local)    │
└────────────┘       └────────┘       └────────────┘

┌────────────┐       ┌────────┐  HTTP/SSE  ┌────────────┐
│ Claude     │◄─────►│  mcpx  │◄──────────►│ MCP Server │
│ Desktop    │ stdio │        │            │ (remote)   │
└────────────┘       └────────┘            └────────────┘
```

On **first connection**, it snapshots every tool's schema and description as a pinned baseline. On **every subsequent connection**, it diffs the live schema against the baseline and:

- **Detects breaking changes** — removed tools, new required params, type changes
- **Detects poisoning** — tool/parameter description injection, hidden Unicode, suspicious parameter names
- **Blocks unsafe tool calls** — returns a clear error instead of letting the LLM hallucinate
- **Logs everything** — full audit trail of every schema change over time
- **Proposes safe shims** — trivial rename-only mappings can be approved or auto-approved

## Quick Start

```bash
# Install
./install.sh
# installs to ~/.local/bin/mcpx by default

# Optional:
# ./install.sh --prefix /usr/local
# ./install.sh --debug
# ./install.sh --ml              # Enable Level 3 semantic similarity detection

# Use as a drop-in proxy wrapper
# Before:  "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]
# After:
mcpx run -- npx -y @modelcontextprotocol/server-github
mcpx run --auto-approve-shims -- npx -y @modelcontextprotocol/server-github

# Or connect to a remote MCP server over HTTP/SSE
mcpx run --upstream https://mcp.example.com/mcp

# With custom headers (e.g. auth tokens)
mcpx run --upstream https://mcp.example.com/mcp -H "Authorization: Bearer sk-..."
```

In your Claude Desktop config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "github": {
      "command": "mcpx",
      "args": ["run", "--", "npx", "-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "..."
      }
    },
    "remote-server": {
      "command": "mcpx",
      "args": ["run", "--upstream", "https://mcp.example.com/mcp", "-H", "Authorization: Bearer sk-..."]
    }
  }
}
```

That's it. One line change. mcpx handles the rest.

## CLI Commands

```bash
mcpx run -- <command>        # Proxy a local MCP server (stdio)
mcpx run --auto-approve-shims -- <command> # Auto-approve/apply eligible trivial shims
mcpx run --upstream <url>    # Proxy a remote MCP server (HTTP/SSE)
mcpx run --upstream <url> -H "Header: value"  # With custom headers
mcpx baselines list          # Show pinned baselines
mcpx baselines show <name>   # Show baseline details
mcpx baselines delete <name> # Re-pin on next connection
mcpx diff <name>             # Show schema drift
mcpx events <name>           # Show recent audit events
mcpx shims list <name>       # Show shim proposals/decisions for a server
mcpx shims approve <name> <tool> # Approve latest proposal for a tool
```

## What Gets Detected

| Change | Severity | Action |
|--------|----------|--------|
| Tool removed | Breaking | Block calls |
| Required param added | Breaking | Block calls |
| Param type changed | Breaking | Block calls |
| Optional param removed | Warning | Log |
| Description changed | Warning | Poisoning analysis |
| Hidden Unicode in description | Blocked | Block calls |
| Injection patterns in description | Blocked | Block calls |
| Suspicious parameter name (e.g. `system_override_instruction`) | Blocked | Block calls |
| Injection/hidden chars in parameter description | Blocked | Block calls |
| Trivial rename drift (`file_path` -> `filepath`) | Proposed | Require approval (or auto-approve) |
| Non-trivial drift (`user_id` -> `admin_token`) | Blocked | Manual baseline update |
| New tool added | Safe | Log |
| Optional param added | Safe | Log |

## Poisoning Detection

mcpx scans:
- Tool descriptions
- Parameter names
- Parameter descriptions

**Level 1** (always on): BLAKE3 hash comparison — any change is flagged.

**Level 2** (default): Structural analysis — Levenshtein similarity, plus regex detection of:
- Instruction override attempts (`"ignore previous instructions"`)
- Credential access directives (`"read ~/.ssh/id_rsa"`)
- Data exfiltration patterns (`"send to https://..."`)
- Hidden Unicode characters (zero-width spaces, RTL overrides)
- BCC exfiltration (the Postmark MCP attack pattern)
- High-risk parameter name tokens (`exec`, `eval`, `system`, `prompt`, `override`, etc.)

**Level 3** (opt-in, `--ml` flag): Semantic similarity — uses a local [all-MiniLM-L6-v2](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2) embedding model (~80MB, downloaded once) to detect meaning-preserving rewording that evades structural checks. Descriptions with semantic similarity below 0.80 are flagged as suspicious.

```bash
# Install with Level 3 enabled
./install.sh --ml

# Or with cargo
cargo install --path crates/mcpx-cli --features ml
```

## Auto-Shimming (Safe Mode)

Shimming is intentionally constrained to avoid turning the proxy into a confused deputy.

Pipeline order is strict:
1. Run poisoning checks first.
2. If poisoning is detected, block and do not shim.
3. If clean, evaluate trivial drift and generate shim proposals.

Current shim rules:
- Only rename-only, trivial mappings are eligible.
- Type compatibility is required.
- Ambiguous/non-trivial mappings are blocked.
- Runtime rewrite blocks on key conflicts and validates mapped values for sensitive targets.

Approval modes:
- **Default (recommended):** proposal-only. Tool is blocked with `shim_requires_approval` until you approve.
- **Auto mode:** `--auto-approve-shims` auto-approves and applies eligible trivial shims.

Manual approval workflow:

```bash
mcpx shims list MyServer
mcpx shims approve MyServer search
```

All proposals/approvals are recorded in SQLite and reflected in `mcpx events`.

## Architecture

mcpx is built as a Rust workspace with focused crates:

- **mcpx-core** — JSON-RPC 2.0 and MCP protocol types, snapshot capture
- **mcpx-transport** — stdio and HTTP/SSE bidirectional proxy, message pump
- **mcpx-schema** — recursive JSON Schema diffing, constrained shim proposal/rewrite engine
- **mcpx-poison** — structural similarity analysis, injection pattern detection
- **mcpx-poison-ml** — (optional) semantic similarity via ONNX embedding model
- **mcpx-store** — SQLite storage for baselines, snapshots, audit logs
- **mcpx-cli** — CLI binary with clap


## Extending mcpx

If you want to add features, use this file map:

- New CLI command: `crates/mcpx-cli/src/main.rs` + `crates/mcpx-cli/src/commands/`
- New DB tables/queries/events: `crates/mcpx-store/src/lib.rs`
- New schema drift rules: `crates/mcpx-schema/src/diff.rs`
- New poisoning detectors: `crates/mcpx-poison/src/patterns.rs` and `structural.rs`
- New transport mode: `crates/mcpx-transport/src/`
- Shared protocol types: `crates/mcpx-core/src/`

Recommended workflow:

1. Add tests for the crate you are touching.
2. Implement the smallest useful change.
3. Run `cargo test --workspace`.
4. Run `cargo check --workspace --all-targets` for cross-crate integration checks.

Starter feature ideas:

1. `mcpx diff --live` one-shot connection mode (capture/diff/exit).
2. `mcpx events <server> --type <event_type>` filtering.
3. Shim MVP for renamed parameters in `crates/mcpx-schema/src/shim.rs`.
4. `mcpx.toml` policy config for thresholds and allow/block overrides.

## Roadmap

- [x] v0.1 — stdio proxy, auto-baseline, schema diffing, poisoning detection (levels 1+2), blocking
- [ ] v0.2 — ~~HTTP/SSE transport~~, ~~auto-shimming (backwards-compatible request rewriting)~~, CI export (JSON/SARIF)
- [ ] v0.3 — ~~semantic similarity (local embeddings)~~, TUI dashboard, `mcpdiff` baseline format interop
- [ ] v0.4 — multi-server composition, policy-as-code (TOML config), Homebrew tap

## Building from Source

```bash
git clone https://github.com/meghsatpat/mcpx.git
cd mcpx
cargo build --release
# Binary at target/release/mcpx

# With semantic similarity (Level 3):
cargo build --release --features ml
```

## CI and Release Workflows

This repository includes standard GitHub Actions workflows:

- `CI` (`.github/workflows/ci.yml`)
  - `cargo fmt --check`
  - `cargo clippy -- -D warnings`
  - `cargo test --workspace`
  - `cargo check --workspace --all-targets`
  - cross-platform release builds on Ubuntu/macOS/Windows
- `Security Audit` (`.github/workflows/security-audit.yml`)
  - runs `cargo audit` on dependency changes and weekly schedule
- `Dependency Review` (`.github/workflows/dependency-review.yml`)
  - checks new/changed dependencies in pull requests
- `Release` (`.github/workflows/release.yml`)
  - on tag push (`v*`), builds `mcpx` binaries and attaches them to a GitHub Release

## License

MIT
