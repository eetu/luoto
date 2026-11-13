//! `sandbox agent-setup`: point an agent's user-level instructions at the luoto briefing,
//! register the sandbox MCP server and answer its first-run questions in its config, without
//! clobbering what the user has.

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

/// Set `value` at `keys` in the JSON file at `path`, keeping the rest; `null` removes the key,
/// and a file or table without it stays as it is.
fn merge_json(path: &Path, keys: &[&str], value: Value) -> Result<()> {
    let mut doc: Value = match std::fs::read_to_string(path) {
        Ok(t) if !t.trim().is_empty() => {
            serde_json::from_str(&t).with_context(|| format!("{} is not JSON", path.display()))?
        }
        _ if value.is_null() => return Ok(()),
        _ => json!({}),
    };
    if value.is_null() {
        let Some((last, parents)) = keys.split_last() else {
            bail!("no key to remove in {}", path.display());
        };
        let mut cur = &mut doc;
        for k in parents {
            match cur.get_mut(*k) {
                Some(next) => cur = next,
                None => return Ok(()),
            }
        }
        if cur.as_object_mut().and_then(|o| o.remove(*last)).is_some() {
            std::fs::write(path, serde_json::to_string_pretty(&doc)?)?;
        }
        return Ok(());
    }
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

/// Add `value` to the list at `keys` in the JSON file at `path` unless it holds it already;
/// the user's own entries stay.
fn append_json(path: &Path, keys: &[&str], value: Value) -> Result<()> {
    let mut doc: Value = match std::fs::read_to_string(path) {
        Ok(t) if !t.trim().is_empty() => {
            serde_json::from_str(&t).with_context(|| format!("{} is not JSON", path.display()))?
        }
        _ => json!({}),
    };
    let Some((last, parents)) = keys.split_last() else {
        bail!("no key to add to in {}", path.display());
    };
    let mut cur = &mut doc;
    for k in parents {
        cur = cur
            .as_object_mut()
            .with_context(|| format!("{} has an unexpected shape", path.display()))?
            .entry(k.to_string())
            .or_insert_with(|| json!({}));
    }
    let list = cur
        .as_object_mut()
        .with_context(|| format!("{} has an unexpected shape", path.display()))?
        .entry(last.to_string())
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .with_context(|| format!("{} has an unexpected shape", path.display()))?;
    if list.contains(&value) {
        return Ok(());
    }
    list.push(value);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(&doc)?)?;
    Ok(())
}

/// [`merge_json`] for a TOML file (Codex's config), keeping its comments and layout.
fn merge_toml(path: &Path, keys: &[&str], value: Value) -> Result<()> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .with_context(|| format!("{} is not TOML", path.display()))?;
    if value.is_null() {
        let Some((last, parents)) = keys.split_last() else {
            bail!("no key to remove in {}", path.display());
        };
        let mut table = doc.as_table_mut();
        for k in parents {
            match table.get_mut(k).and_then(|i| i.as_table_mut()) {
                Some(t) => table = t,
                None => return Ok(()),
            }
        }
        if table.remove(last).is_some() {
            std::fs::write(path, doc.to_string())?;
        }
        return Ok(());
    }
    let value = toml_value(value)?;
    let Some((last, parents)) = keys.split_last() else {
        bail!("no key to set in {}", path.display());
    };
    let mut table = doc.as_table_mut();
    for k in parents {
        table = table
            .entry(k)
            .or_insert_with(toml_edit::table)
            .as_table_mut()
            .with_context(|| format!("{} has an unexpected shape", path.display()))?;
    }
    table[*last] = toml_edit::Item::Value(value);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, doc.to_string())?;
    Ok(())
}

/// `value` as TOML: a string, bool, number, or a list of them.
fn toml_value(value: Value) -> Result<toml_edit::Value> {
    Ok(match value {
        Value::String(s) => s.into(),
        Value::Bool(b) => b.into(),
        Value::Number(n) if n.is_i64() => n.as_i64().unwrap_or_default().into(),
        Value::Number(n) => n.as_f64().unwrap_or_default().into(),
        Value::Array(items) => items
            .into_iter()
            .map(toml_value)
            .collect::<Result<toml_edit::Array>>()?
            .into(),
        other => bail!("{other} has no TOML form here"),
    })
}

/// Whether the JSON or TOML file at `path` has a value at `keys`.
fn has_key(path: &Path, keys: &[&str]) -> Result<bool> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Ok(false);
    };
    if path.extension().is_some_and(|e| e == "toml") {
        let doc: toml_edit::DocumentMut = text
            .parse()
            .with_context(|| format!("{} is not TOML", path.display()))?;
        let mut item = doc.as_item();
        for k in keys {
            match item.get(k) {
                Some(next) => item = next,
                None => return Ok(false),
            }
        }
        return Ok(true);
    }
    if text.trim().is_empty() {
        return Ok(false);
    }
    let doc: Value =
        serde_json::from_str(&text).with_context(|| format!("{} is not JSON", path.display()))?;
    Ok(keys
        .iter()
        .try_fold(&doc, |v, k| v.get(*k))
        .is_some_and(|v| !v.is_null()))
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

/// One `--set`: a value at a path of keys in a JSON or TOML file of the dev user's home;
/// `null` removes the key. With `if_absent`, a key that holds a value keeps it.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonSet {
    file: String,
    path: Vec<String>,
    value: Value,
    #[serde(default)]
    append: bool,
    #[serde(default)]
    if_absent: bool,
}

/// The OSC 7501 report of `state` (idle, working, done, blocked, error), for `app`; none for
/// another state or an app name that isn't a plain word.
fn status_report(state: &str, app: Option<&str>) -> Option<String> {
    if !["idle", "working", "done", "blocked", "error"].contains(&state) {
        return None;
    }
    let mut fields = format!("state={state}");
    if let Some(app) = app {
        if app.is_empty()
            || app.len() > 40
            || !app
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }
        fields.push_str(&format!(":app={app}"));
    }
    Some(format!("\x1b]7501;{fields}\x1b\\"))
}

/// Write the report to the controlling terminal (a hook's own output goes to the agent, not
/// the screen), which shows it if it knows OSC 7501 and ignores it otherwise; nothing without
/// one (a headless run). Never fails the hook.
pub fn report_status(state: &str, app: Option<&str>) {
    if let Some(report) = status_report(state, app)
        && let Ok(mut tty) = std::fs::OpenOptions::new().write(true).open("/dev/tty")
    {
        let _ = std::io::Write::write_all(&mut tty, report.as_bytes());
    }
}

pub fn run(mcp: Option<&str>, briefing: &[String], set: &[String]) -> Result<ExitCode> {
    for b in briefing {
        link_briefing(&expand(b)?)?;
    }
    if let Some(kind) = mcp {
        register_mcp(kind)?;
    }
    for s in set {
        let j: JsonSet = serde_json::from_str(s).context("--set takes {file, path, value}")?;
        if !j.file.starts_with("~/") || j.file.contains("..") {
            bail!("--set writes only in the home folder (got {})", j.file);
        }
        let keys: Vec<&str> = j.path.iter().map(String::as_str).collect();
        let path = expand(&j.file)?;
        if j.if_absent && has_key(&path, &keys)? {
            continue;
        }
        if j.append {
            append_json(&path, &keys, j.value)?;
        } else if path.extension().is_some_and(|e| e == "toml") {
            merge_toml(&path, &keys, j.value)?;
        } else {
            merge_json(&path, &keys, j.value)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_report_is_osc_7501_of_a_known_state() {
        assert_eq!(
            status_report("done", Some("claude-code")).unwrap(),
            "\x1b]7501;state=done:app=claude-code\x1b\\"
        );
        assert!(status_report("rm -rf", None).is_none());
        assert!(status_report("done", Some("a;b")).is_none());
    }

    #[test]
    fn a_hook_is_added_once_beside_the_users_own() {
        let path = std::env::temp_dir().join(format!("luoto-test-{}.json", std::process::id()));
        std::fs::write(
            &path,
            r#"{"hooks": {"Stop": [{"hooks": [{"command": "mine"}]}]}}"#,
        )
        .unwrap();
        let ours = json!({"hooks": [{"type": "command", "command": "sandbox state done"}]});
        append_json(&path, &["hooks", "Stop"], ours.clone()).unwrap();
        append_json(&path, &["hooks", "Stop"], ours.clone()).unwrap();
        append_json(&path, &["hooks", "Notification"], ours).unwrap();
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(doc["hooks"]["Stop"].as_array().unwrap().len(), 2);
        assert_eq!(doc["hooks"]["Stop"][0]["hooks"][0]["command"], "mine");
        assert_eq!(doc["hooks"]["Notification"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn toml_settings_keep_the_rest_of_the_file() {
        let path = std::env::temp_dir().join(format!("luoto-test-{}.toml", std::process::id()));
        std::fs::write(
            &path,
            "# mine\napproval_policy = \"never\"\n\n[mcp_servers.luoto-sandbox]\ncommand = \"x\"\n",
        )
        .unwrap();
        merge_toml(&path, &["model"], json!("gpt-5.5")).unwrap();
        merge_toml(&path, &["model_reasoning_effort"], json!("high")).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let doc: toml_edit::DocumentMut = text.parse().unwrap();
        assert_eq!(doc["model"].as_str(), Some("gpt-5.5"));
        assert_eq!(doc["model_reasoning_effort"].as_str(), Some("high"));
        assert!(text.starts_with("# mine") && text.contains("[mcp_servers.luoto-sandbox]"));
    }

    #[test]
    fn a_value_if_absent_leaves_the_users_own() {
        let dir = std::env::temp_dir().join(format!("luoto-absent-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let notify = |file: &Path| {
            let set = json!({
                "file": "~/x",
                "path": ["notify"],
                "value": ["/opt/luoto/bin/sandbox", "state", "done", "--app", "codex"],
                "if_absent": true,
            });
            let j: JsonSet = serde_json::from_value(set).unwrap();
            let keys: Vec<&str> = j.path.iter().map(String::as_str).collect();
            if !(j.if_absent && has_key(file, &keys).unwrap()) {
                merge_toml(file, &keys, j.value).unwrap();
            }
        };
        let fresh = dir.join("fresh.toml");
        notify(&fresh);
        let doc: toml_edit::DocumentMut = std::fs::read_to_string(&fresh).unwrap().parse().unwrap();
        let args: Vec<&str> = doc["notify"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(
            args,
            ["/opt/luoto/bin/sandbox", "state", "done", "--app", "codex"]
        );
        let mine = dir.join("mine.toml");
        std::fs::write(&mine, "notify = [\"my-notifier\"]\n").unwrap();
        notify(&mine);
        assert_eq!(
            std::fs::read_to_string(&mine).unwrap(),
            "notify = [\"my-notifier\"]\n"
        );
        let json = dir.join("s.json");
        std::fs::write(&json, r#"{"a": {"b": 1}, "c": null}"#).unwrap();
        assert!(has_key(&json, &["a", "b"]).unwrap());
        assert!(!has_key(&json, &["a", "x"]).unwrap() && !has_key(&json, &["c"]).unwrap());
        assert!(!has_key(&dir.join("none.json"), &["a"]).unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn null_removes_a_key_and_only_it() {
        let dir = std::env::temp_dir().join(format!("luoto-null-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let toml = dir.join("config.toml");
        std::fs::write(
            &toml,
            "# mine
profile = \"local\"\n[profiles.local]\nmodel = \"q\"\n",
        )
        .unwrap();
        merge_toml(&toml, &["profile"], Value::Null).unwrap();
        merge_toml(&toml, &["absent", "key"], Value::Null).unwrap();
        let text = std::fs::read_to_string(&toml).unwrap();
        assert!(
            !text.contains("profile = ") && text.contains("[profiles.local]"),
            "{text}"
        );
        let json = dir.join("settings.json");
        std::fs::write(&json, r#"{"env":{"A":"1","B":"2"},"theme":"dark"}"#).unwrap();
        merge_json(&json, &["env", "A"], Value::Null).unwrap();
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(&json).unwrap()).unwrap();
        assert_eq!(doc, json!({"env": {"B": "2"}, "theme": "dark"}));
        // Nothing to remove: no file is made.
        let none = dir.join("none.json");
        merge_json(&none, &["x"], Value::Null).unwrap();
        assert!(!none.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
