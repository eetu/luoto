//! `sandbox mcp`: an MCP server (JSON-RPC 2.0 over stdio) so any MCP-capable agent can read
//! the egress policy and file access requests without parsing CLI output.

use std::io::{BufRead, Write};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Result;
use luoto_shared::api::SandboxStatus;
use serde_json::{Value, json};

use crate::{
    check_url, describe, describe_check, gate, parse_tool, render_status, request_access,
    request_install,
};

const INSTRUCTIONS: &str = "You are inside a luoto sandbox: network egress is filtered by a \
policy only the user controls from the host, and real credentials never enter the sandbox. \
Use sandbox_status to see what is allowed, sandbox_check before relying on a URL, and \
sandbox_request_access when access is genuinely needed, and sandbox_request_install for a \
system package or toolchain the env should keep — then tell the user what you requested and \
why. Never try to work around a block.";

fn tools() -> Value {
    json!([
        {
            "name": "sandbox_status",
            "description": "Show this sandbox's allowed egress rules, credentialed hosts, recent denials and pending access requests.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false}
        },
        {
            "name": "sandbox_check",
            "description": "Check whether an HTTP(S) request to a URL would be allowed by the sandbox policy. Sends no traffic.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Full URL, e.g. https://docs.rs/serde"},
                    "method": {"type": "string", "description": "HTTP method", "default": "GET"}
                },
                "required": ["url"],
                "additionalProperties": false
            }
        },
        {
            "name": "sandbox_recent_denials",
            "description": "List recent blocked egress attempts from this sandbox (what was blocked and why).",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false}
        },
        {
            "name": "sandbox_request_access",
            "description": "Ask the user to allow egress to a host, or to add one of luoto's presets (a registry's hosts, e.g. npm). Only the user can approve, on the host. Use the narrowest access: read unless writes are required; one exact host.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Exact host, e.g. docs.rs"},
                    "preset": {"type": "string", "description": "Instead of a host, one of luoto's presets for a registry or service: npm, pypi, crates, go, maven, …"},
                    "access": {"type": "string", "enum": ["read", "write"], "default": "read"},
                    "paths": {"type": "array", "items": {"type": "string"}, "description": "Optional path globs, e.g. /serde/**"},
                    "reason": {"type": "string", "description": "Why this is needed, shown to the user"},
                    "wait_seconds": {"type": "integer", "minimum": 0, "maximum": 900, "default": 0, "description": "Wait this long for the user's decision"}
                },
                "required": ["reason"],
                "additionalProperties": false
            }
        },
        {
            "name": "sandbox_request_install",
            "description": "Ask the user to install a system package (apt, apk or dnf) or a toolchain (mise) in this env for good: approved, it is installed now and again whenever the container is recreated. A `sudo apt-get install` of your own lasts only until then.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "package": {"type": "string", "description": "System package, e.g. postgresql-client"},
                    "tool": {"type": "string", "description": "mise toolchain as TOOL@VERSION, e.g. node@24 or cargo:ripgrep@latest"},
                    "reason": {"type": "string", "description": "Why this is needed, shown to the user"},
                    "wait_seconds": {"type": "integer", "minimum": 0, "maximum": 900, "default": 0, "description": "Wait this long for the user's decision"}
                },
                "required": ["reason"],
                "additionalProperties": false
            }
        }
    ])
}

fn text(s: String, is_error: bool) -> Value {
    json!({"content": [{"type": "text", "text": s}], "isError": is_error})
}

fn call(name: &str, args: &Value) -> Value {
    let result: Result<Value> = (|| match name {
        "sandbox_status" => {
            let s: SandboxStatus = gate::get_json("/_sandbox/status")?;
            Ok(text(render_status(&s), false))
        }
        "sandbox_check" => {
            let r = check_url(
                args["url"].as_str().unwrap_or_default(),
                args["method"].as_str().unwrap_or("GET"),
            )?;
            Ok(text(describe_check(&r), false))
        }
        "sandbox_recent_denials" => {
            let s: SandboxStatus = gate::get_json("/_sandbox/status")?;
            Ok(text(
                serde_json::to_string_pretty(&s.recent_denials)?,
                false,
            ))
        }
        "sandbox_request_access" => {
            let host = args["host"].as_str().unwrap_or_default();
            let reason = args["reason"].as_str().unwrap_or_default();
            if let Some(name) = args["preset"].as_str() {
                let wait = args["wait_seconds"].as_u64().unwrap_or(0).min(900);
                let wait = (wait > 0).then(|| Duration::from_secs(wait));
                let preset = luoto_shared::api::Install::Preset {
                    name: name.to_string(),
                };
                return Ok(match request_install(preset, reason, wait) {
                    Ok(o) => text(describe(&o), false),
                    Err(e) => text(format!("request refused: {e:#}"), true),
                });
            }
            let write = args["access"].as_str() == Some("write");
            let paths = args["paths"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let wait = args["wait_seconds"].as_u64().unwrap_or(0).min(900);
            let wait = (wait > 0).then(|| Duration::from_secs(wait));
            Ok(match request_access(host, write, paths, reason, wait) {
                Ok(o) => text(describe(&o), false),
                Err(e) => text(format!("request refused: {e:#}"), true),
            })
        }
        "sandbox_request_install" => {
            let reason = args["reason"].as_str().unwrap_or_default();
            let install = match (args["package"].as_str(), args["tool"].as_str()) {
                (Some(p), None) => luoto_shared::api::Install::Package {
                    name: p.to_string(),
                },
                (None, Some(t)) => parse_tool(t),
                _ => return Ok(text("give either `package` or `tool`".into(), true)),
            };
            let wait = args["wait_seconds"].as_u64().unwrap_or(0).min(900);
            let wait = (wait > 0).then(|| Duration::from_secs(wait));
            Ok(match request_install(install, reason, wait) {
                Ok(o) => text(describe(&o), false),
                Err(e) => text(format!("request refused: {e:#}"), true),
            })
        }
        other => Ok(text(format!("unknown tool `{other}`"), true)),
    })();
    result.unwrap_or_else(|e| text(format!("{e:#}"), true))
}

pub fn serve() -> Result<ExitCode> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            let err = json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "parse error"}});
            writeln!(stdout, "{err}")?;
            stdout.flush()?;
            continue;
        };
        let Some(id) = msg.get("id").cloned() else {
            continue; // notification
        };
        let method = msg["method"].as_str().unwrap_or_default();
        let result = match method {
            "initialize" => Some(json!({
                "protocolVersion": msg["params"]["protocolVersion"].as_str().unwrap_or("2025-06-18"),
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "luoto-sandbox", "version": luoto_shared::VERSION},
                "instructions": INSTRUCTIONS
            })),
            "ping" => Some(json!({})),
            "tools/list" => Some(json!({"tools": tools()})),
            "tools/call" => Some(call(
                msg["params"]["name"].as_str().unwrap_or_default(),
                &msg["params"]["arguments"],
            )),
            _ => None,
        };
        let reply = match result {
            Some(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
            None => {
                json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": format!("method not found: {method}")}})
            }
        };
        writeln!(stdout, "{reply}")?;
        stdout.flush()?;
    }
    Ok(ExitCode::SUCCESS)
}
