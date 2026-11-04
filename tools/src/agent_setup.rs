//! `sandbox agent-setup`: point an agent's user-level instructions at the luoto briefing and
//! register the sandbox MCP server in its config, without clobbering what the user has.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

const BRIEFING: &str = "/opt/luoto/AGENTS.md";
const HELPER: &str = "/usr/local/bin/sandbox";

fn home() -> Result<PathBuf> {
    std::env::var("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}

fn expand(p: &str) -> Result<PathBuf> {
    Ok(match p.strip_prefix("~/") {
        Some(rest) => home()?.join(rest),
        None => PathBuf::from(p),
    })
}

fn link_briefing(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            std::fs::remove_file(path)?;
        }
        Ok(_) => {
            let text = std::fs::read_to_string(path).unwrap_or_default();
            if !text.contains(BRIEFING) {
                let mut text = text;
                text.push_str(&format!(
                    "\n\n<!-- luoto -->\nThis environment is a luoto sandbox: read {BRIEFING} before using the network.\n"
                ));
                std::fs::write(path, text)?;
            }
            return Ok(());
        }
        Err(_) => {}
    }
    std::os::unix::fs::symlink(BRIEFING, path)?;
    Ok(())
}

fn merge_json(path: &Path, keys: &[&str], value: Value) -> Result<()> {
    let mut doc: Value = match std::fs::read_to_string(path) {
        Ok(t) if !t.trim().is_empty() => {
            serde_json::from_str(&t).with_context(|| format!("{} is not JSON", path.display()))?
        }
        _ => json!({}),
    };
    let mut cur = &mut doc;
    for k in keys {
        if !cur.is_object() {
            bail!("{} has an unexpected shape", path.display());
        }
        cur = cur
            .as_object_mut()
            .context("object")?
            .entry(k.to_string())
            .or_insert_with(|| json!({}));
    }
    *cur = value;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(&doc)?)?;
    Ok(())
}

fn register_mcp(kind: &str) -> Result<()> {
    let h = home()?;
    match kind {
        "claude" => merge_json(
            &h.join(".claude.json"),
            &["mcpServers", "luoto-sandbox"],
            json!({"type": "stdio", "command": HELPER, "args": ["mcp"], "env": {}}),
        ),
        "opencode" => merge_json(
            &h.join(".config/opencode/opencode.json"),
            &["mcp", "luoto-sandbox"],
            json!({"type": "local", "command": [HELPER, "mcp"], "enabled": true}),
        ),
        "agy" => merge_json(
            &h.join(".gemini/config/mcp_config.json"),
            &["mcpServers", "luoto-sandbox"],
            json!({"type": "stdio", "command": HELPER, "args": ["mcp"]}),
        ),
        "copilot" => merge_json(
            &h.join(".copilot/mcp-config.json"),
            &["mcpServers", "luoto-sandbox"],
            json!({"type": "local", "command": HELPER, "args": ["mcp"], "tools": ["*"]}),
        ),
        "codex" => {
            let p = h.join(".codex/config.toml");
            let text = std::fs::read_to_string(&p).unwrap_or_default();
            if !text.contains("[mcp_servers.luoto-sandbox]") {
                if let Some(parent) = p.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(
                    &p,
                    format!(
                        "{text}\n[mcp_servers.luoto-sandbox]\ncommand = \"{HELPER}\"\nargs = [\"mcp\"]\n"
                    ),
                )?;
            }
            Ok(())
        }
        other => bail!("unknown MCP config kind `{other}`"),
    }
}

pub fn run(mcp: Option<&str>, briefing: &[String]) -> Result<ExitCode> {
    for b in briefing {
        link_briefing(&expand(b)?)?;
    }
    if let Some(kind) = mcp {
        register_mcp(kind)?;
    }
    Ok(ExitCode::SUCCESS)
}
