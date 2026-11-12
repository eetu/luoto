//! `luoto doctor --report`: what a bug report needs in one file (versions, the runtime and VM,
//! doctor's checks, each env's config and state, the watcher's log, the gates' and the vault's
//! lifecycle and error events), with what identifies you or grants access taken out by
//! [`Redactor`]. The file is readable only by you; host, repository and env names stay, so the
//! user is told to read it before sharing it.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::Result;
use chrono::Utc;
use luoto_shared::events::{Event, EventKind};

use crate::env::Ctx;
use crate::paths::{self, Paths};
use crate::runtime::Runtime;
use crate::state::EnvState;
use crate::{config, events, machine, names};

const WATCH_LINES: usize = 200;
/// Per container: the newest lifecycle and error events, and the newest diagnostic lines.
const EVENTS: usize = 40;
const DIAGNOSTICS: usize = 40;
/// The newest lines of a container's log that are read.
const LOG_TAIL: &str = "5000";

/// Write the report: to `file`, else a timestamped file in the current folder.
pub fn write(ctx: Option<&Ctx>, checks: &[String], file: Option<&str>) -> Result<()> {
    let paths = Paths::get()?;
    let envs = config::list_envs(&paths).unwrap_or_default();
    let states: Vec<(String, Option<EnvState>)> = envs
        .iter()
        .map(|e| (e.clone(), EnvState::load(&paths, e).ok().flatten()))
        .collect();
    let secrets: Vec<String> = states
        .iter()
        .filter_map(|(_, s)| s.as_ref().map(|s| s.vault_token.clone()))
        .collect();

    let mut out = String::new();
    let _ = writeln!(
        out,
        "luoto doctor report, {}\n",
        Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );
    section(&mut out, "luoto", &about(ctx, &paths));
    section(&mut out, "checks (luoto doctor)", &checks.join("\n"));
    section(
        &mut out,
        "config.toml",
        &read_or(&paths.global_config(), "(none)"),
    );
    let running = ctx.and_then(|c| c.rt.states().ok());
    for (env, state) in &states {
        section(
            &mut out,
            &format!("env {env}"),
            &env_summary(&paths, env, state.as_ref(), running.as_ref()),
        );
    }
    section(
        &mut out,
        &format!("watcher log (the last {WATCH_LINES} lines)"),
        &tail(&read_or(&paths.watch_log(), "(none)"), WATCH_LINES),
    );
    let mut logged = Vec::new();
    if let (Some(ctx), Some(states)) = (ctx, &running)
        && !states.vm_stopped
    {
        let containers = envs.iter().map(|e| names::gate(e)).chain([names::vault()]);
        for c in containers.filter(|c| states.exists(c)) {
            section(
                &mut out,
                &format!("{c}: lifecycle and errors"),
                &container_log(&ctx.rt, &c),
            );
            logged.push(c);
        }
    }

    let redactor = Redactor::for_host(secrets);
    let text = redactor.redact(&crate::text::lines(&out));
    let path = match file {
        Some(f) => crate::workspace::expand(f),
        None => PathBuf::from(format!(
            "luoto-report-{}.txt",
            Utc::now().format("%Y%m%d-%H%M%S")
        )),
    };
    paths::write_private(&path, text.as_bytes())?;
    let mut holds = vec![
        "luoto's version, the OS, the runtime, luoto's VM and the checks above".to_string(),
        match envs.len() {
            0 => "config.toml (no envs yet)".into(),
            n => format!(
                "config.toml, and the config and state of {n} env(s): {}",
                envs.join(", ")
            ),
        },
        format!("the watcher's last {WATCH_LINES} log lines"),
    ];
    if !logged.is_empty() {
        holds.push(format!(
            "the latest lifecycle and error events of {}",
            logged.join(", ")
        ));
    }
    println!(
        "\nwrote {}{}. It holds:\n  {}\n\
         Taken out: secret references (env: names stay), tokens, vault tokens, your home \
         folder (as ~), your user and git names, email addresses and credentials in URLs.\n\
         Host, repository and env names stay: read it before you share it.",
        path.display(),
        if cfg!(unix) {
            ", readable only by you"
        } else {
            ""
        },
        holds.join("\n  ")
    );
    Ok(())
}

fn section(out: &mut String, title: &str, body: &str) {
    let _ = writeln!(out, "== {title}\n{}\n", body.trim_end());
}

fn read_or(path: &Path, missing: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|_| missing.into())
}

/// The last `n` lines of `text`.
fn tail(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

/// Versions, the OS, the runtime and luoto's VM.
fn about(ctx: Option<&Ctx>, paths: &Paths) -> String {
    let mut out = format!(
        "luoto {} ({}, instance {})\nbinary: {}\nos: {}\nconfig: {}\ndata: {}\n",
        luoto_shared::VERSION,
        if crate::release::pinned() {
            "release"
        } else {
            "source build"
        },
        names::instance(),
        std::env::current_exe().map_or_else(|_| "?".into(), |p| p.display().to_string()),
        os(),
        paths.config.display(),
        paths.data.display(),
    );
    let Some(ctx) = ctx else {
        out.push_str("runtime: not loaded (see the checks)\n");
        return out;
    };
    let _ = writeln!(
        out,
        "runtime: {} ({}), connection {}",
        ctx.rt.bin,
        ctx.rt.version().unwrap_or_else(|e| format!("error: {e:#}")),
        ctx.rt.connection.as_deref().unwrap_or("(default)")
    );
    if machine::is_luoto(ctx.rt.connection.as_deref()) {
        let _ = writeln!(
            out,
            "VM {}: {}",
            machine::NAME,
            machine::info(&ctx.rt.bin).unwrap_or_else(|| "not found".into())
        );
    }
    let _ = writeln!(
        out,
        "gVisor: {}\nimages: {}",
        ctx.global.gvisor.as_deref().unwrap_or("(not set up)"),
        ctx.global
            .images
            .as_deref()
            .map_or_else(|| "the release's".into(), |t| format!("local, tag {t}"))
    );
    out
}

fn os() -> String {
    let (os, arch) = (std::env::consts::OS, std::env::consts::ARCH);
    let version = if cfg!(target_os = "macos") {
        std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    } else {
        std::fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|t| {
                t.lines()
                    .find_map(|l| l.strip_prefix("PRETTY_NAME="))
                    .map(|v| v.trim_matches('"').to_string())
            })
    };
    match version.filter(|v| !v.is_empty()) {
        Some(v) => format!("{os} {v} ({arch})"),
        None => format!("{os} ({arch})"),
    }
}

/// An env's config file, its state with the vault token taken out, the files in its state
/// folder, and its containers' states.
fn env_summary(
    paths: &Paths,
    env: &str,
    state: Option<&EnvState>,
    running: Option<&crate::runtime::States>,
) -> String {
    let mut out = format!(
        "config ({}):\n{}\n",
        paths.env_config(env).display(),
        read_or(&paths.env_config(env), "(unreadable)").trim_end()
    );
    let state = state.map(|s| {
        let mut s = s.clone();
        s.vault_token = "<redacted>".into();
        serde_json::to_string_pretty(&s).unwrap_or_default()
    });
    let _ = writeln!(
        out,
        "state:\n{}",
        state.as_deref().unwrap_or("(none: never started)")
    );
    let files: BTreeSet<String> = std::fs::read_dir(paths.env_state(env))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    let _ = writeln!(
        out,
        "state files: {}",
        files.into_iter().collect::<Vec<_>>().join(", ")
    );
    if let Some(r) = running {
        let (dev, gate) = r.env(env);
        let _ = writeln!(out, "containers: dev {dev}, gate {gate}");
    }
    out
}

/// What a gate or the vault logged of note: lifecycle events (starts, reloads, locks, limits),
/// errors (upstream failures, refused certificates), and its diagnostic lines.
fn container_log(rt: &Runtime, container: &str) -> String {
    let tail = if rt.flavor == crate::runtime::Flavor::Apple {
        "-n"
    } else {
        "--tail"
    };
    let mut reads = vec![vec![
        "logs".to_string(),
        tail.into(),
        LOG_TAIL.into(),
        container.into(),
    ]];
    if events::in_file(rt, container) {
        reads.push(events::file_args(container, false, LOG_TAIL.parse().ok()));
    }
    let mut text = String::new();
    for args in reads {
        match rt.command().args(&args).stdin(Stdio::null()).output() {
            Ok(out) => {
                text.push_str(&String::from_utf8_lossy(&out.stdout));
                text.push('\n');
                text.push_str(&String::from_utf8_lossy(&out.stderr));
                text.push('\n');
            }
            Err(e) => return format!("(could not read its log: {e})"),
        }
    }
    let (events, diagnostics) = notable(&text);
    let mut s = String::new();
    for e in &events[events.len().saturating_sub(EVENTS)..] {
        let _ = writeln!(s, "{}", events::fmt_event(e));
    }
    if events.is_empty() {
        s.push_str("(no lifecycle or error events)\n");
    }
    let shown = &diagnostics[diagnostics.len().saturating_sub(DIAGNOSTICS)..];
    if !shown.is_empty() {
        let _ = writeln!(s, "diagnostics:\n{}", shown.join("\n"));
    }
    s
}

/// The lifecycle and error events in a container log, oldest first, and its other lines.
fn notable(log: &str) -> (Vec<Event>, Vec<String>) {
    let mut events: Vec<Event> = events::parse_lines(log)
        .into_iter()
        .filter(|e| {
            matches!(e.kind, Some(EventKind::Lifecycle | EventKind::TlsReject))
                || e.status.is_some_and(|s| s >= 500)
        })
        .collect();
    events.sort_by_key(|e| (e.ts, e.seq));
    let diagnostics = log
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.is_empty() && !l.starts_with('{'))
        .map(crate::text::display)
        .collect();
    (events, diagnostics)
}

/// Takes out of report text what identifies a person or grants access. Every rule works on
/// plain text, so a config, a log line and doctor's output are treated alike.
pub struct Redactor {
    /// Known secrets (the envs' vault tokens), wherever they appear.
    secrets: Vec<String>,
    /// The home folder in each spelling it has in text (escaped in TOML and JSON, with
    /// forward slashes on Windows), longest first; it becomes `~`.
    homes: Vec<String>,
    /// The git author's name and email, wherever they appear.
    identity: Vec<String>,
    /// User names, as whole words in any case.
    users: Vec<String>,
}

/// User names that name no one; replacing them would garble luoto's own words (`luoto-dev`).
const GENERIC_USERS: [&str; 10] = [
    "root",
    "admin",
    "administrator",
    "user",
    "dev",
    "ubuntu",
    "runner",
    "vagrant",
    "guest",
    "luoto",
];

impl Redactor {
    pub fn new(
        home: Option<&str>,
        users: &[String],
        identity: &[String],
        secrets: Vec<String>,
    ) -> Self {
        let mut homes: Vec<String> = home
            .filter(|h| h.len() > 1)
            .map(|h| vec![h.to_string(), h.replace('\\', "\\\\"), h.replace('\\', "/")])
            .unwrap_or_default();
        homes.sort_by_key(|h| std::cmp::Reverse(h.len()));
        homes.dedup();
        let mut users: Vec<String> = users
            .iter()
            .map(|u| u.trim().to_string())
            .filter(|u| u.len() >= 2 && !GENERIC_USERS.contains(&u.to_ascii_lowercase().as_str()))
            .collect();
        users.sort();
        users.dedup();
        Redactor {
            secrets: secrets.into_iter().filter(|s| s.len() >= 8).collect(),
            homes,
            identity: identity
                .iter()
                .map(|s| s.trim().to_string())
                .filter(|s| s.len() >= 3)
                .collect(),
            users,
        }
    }

    /// For this machine: its home folder, the user's names and git identity, and `secrets`.
    pub fn for_host(secrets: Vec<String>) -> Self {
        let home = directories::BaseDirs::new().map(|b| b.home_dir().display().to_string());
        let mut users: Vec<String> = ["USER", "USERNAME", "LOGNAME"]
            .iter()
            .filter_map(|v| std::env::var(v).ok())
            .collect();
        if let Some(h) = &home
            && let Some(last) = Path::new(h).file_name()
        {
            users.push(last.to_string_lossy().into_owned());
        }
        let identity: Vec<String> = ["user.name", "user.email"]
            .iter()
            .filter_map(|k| crate::personal::host_git(k))
            .collect();
        Self::new(home.as_deref(), &users, &identity, secrets)
    }

    pub fn redact(&self, text: &str) -> String {
        let mut t = text.to_string();
        for s in &self.secrets {
            t = t.replace(s.as_str(), "<redacted>");
        }
        for h in &self.homes {
            t = replace_path(&t, h, "~");
        }
        for i in &self.identity {
            t = t.replace(i.as_str(), "<name>");
        }
        let t = secret_refs(&t);
        let t = url_credentials(&t);
        let t = auth_schemes(&t);
        let t = assignments(&t);
        let t = emails(&t);
        let t = tokens(&t);
        let mut t = t;
        for u in &self.users {
            t = whole_words(&t, u, "<user>");
        }
        t
    }
}

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// `from` (a path) replaced by `to` where it ends a path component, so `/home/al` doesn't
/// match in `/home/alice`.
fn replace_path(text: &str, from: &str, to: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find(from) {
        let after = &rest[i + from.len()..];
        let ends = after
            .bytes()
            .next()
            .is_none_or(|b| !(is_word(b) || b == b'-' || b == b'.'));
        out.push_str(&rest[..i]);
        out.push_str(if ends { to } else { from });
        rest = after;
    }
    out.push_str(rest);
    out
}

/// Every whole-word occurrence of `word`, in any ASCII case, replaced by `to`.
fn whole_words(text: &str, word: &str, to: &str) -> String {
    let (t, w) = (text.as_bytes(), word.as_bytes());
    let mut out = String::with_capacity(text.len());
    let (mut i, mut copied) = (0, 0);
    while i + w.len() <= t.len() {
        if t[i..i + w.len()].eq_ignore_ascii_case(w)
            && (i == 0 || !is_word(t[i - 1]))
            && t.get(i + w.len()).is_none_or(|&b| !is_word(b))
        {
            out.push_str(&text[copied..i]);
            out.push_str(to);
            i += w.len();
            copied = i;
        } else {
            i += 1;
        }
    }
    out.push_str(&text[copied..]);
    out
}

/// Replace `text[start..end]` for each span `find` returns, scanning from the left; `find`
/// gets the text and a position and returns the span to replace that starts there, if any.
fn replace_spans(
    text: &str,
    to: &str,
    find: impl Fn(&[u8], usize) -> Option<(usize, usize)>,
) -> String {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let (mut i, mut copied) = (0, 0);
    while i < b.len() {
        match find(b, i) {
            Some((start, end)) if start >= copied && end > start => {
                out.push_str(&text[copied..start]);
                out.push_str(to);
                copied = end;
                i = end;
            }
            _ => i += 1,
        }
    }
    out.push_str(&text[copied..]);
    out
}

/// Secret refs' schemes; what follows one is taken out. `env:` names stay.
const SCHEMES: [&str; 4] = ["op://", "vault://", "keyring:", "file:"];

/// Where a secret ref's body that starts at `start` ends: refs may hold spaces (`op://Dev/x/
/// private key`), so it runs to a quote, bracket, separator, `: ` or the line's end.
fn ref_end(b: &[u8], start: usize) -> usize {
    let mut j = start;
    while j < b.len() {
        match b[j] {
            b'"' | b'\'' | b'`' | b'(' | b')' | b'[' | b']' | b'{' | b'}' | b'<' | b'>' | b','
            | b';' | b'\n' | b'\r' | b'\t' => break,
            b' ' if j == start => break,
            b':' if b.get(j + 1).is_none_or(u8::is_ascii_whitespace) => break,
            _ => j += 1,
        }
    }
    while j > start && b[j - 1] == b' ' {
        j -= 1;
    }
    j
}

fn secret_refs(text: &str) -> String {
    replace_spans(text, "<redacted>", |b, i| {
        if i > 0 && is_word(b[i - 1]) {
            return None;
        }
        let scheme = SCHEMES.iter().find(|s| b[i..].starts_with(s.as_bytes()))?;
        let start = i + scheme.len();
        Some((start, ref_end(b, start)))
    })
}

/// Where a URL's authority (`user:pass@host:port`) that starts at `start` ends.
fn authority_end(b: &[u8], start: usize) -> usize {
    let mut j = start;
    while j < b.len() && !b[j].is_ascii_whitespace() && !b"/?#\"'`<>()[]{},;".contains(&b[j]) {
        j += 1;
    }
    j
}

/// The user and password in `scheme://user:password@host` (an ssh `git@` stays).
fn url_credentials(text: &str) -> String {
    replace_spans(text, "<redacted>", |b, i| {
        if !b[i..].starts_with(b"://") {
            return None;
        }
        let start = i + 3;
        let end = authority_end(b, start);
        let at = start + b[start..end].iter().rposition(|&c| c == b'@')?;
        (at > start && &b[start..at] != b"git").then_some((start, at))
    })
}

fn token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"._~+/=-".contains(&b)
}

/// The credential after `Bearer` or `Basic` (an Authorization header in a log line).
fn auth_schemes(text: &str) -> String {
    replace_spans(text, "<redacted>", |b, i| {
        if i > 0 && is_word(b[i - 1]) {
            return None;
        }
        let word = ["bearer ", "basic "].into_iter().find(|w| {
            b.len() >= i + w.len() && b[i..i + w.len()].eq_ignore_ascii_case(w.as_bytes())
        })?;
        let start = i + word.len();
        let mut end = start;
        while end < b.len() && token_char(b[end]) {
            end += 1;
        }
        (end - start >= 8).then_some((start, end))
    })
}

/// Whether a key (`token`, `DB_PASSWORD`, `x-api-key`) names a secret, judged by its last
/// `-` or `.` part: an env `auth-service` in `env auth-service: isolated` names none.
fn sensitive_key(key: &str) -> bool {
    const PARTS: [&str; 16] = [
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "apikey",
        "api_key",
        "api-key",
        "access_key",
        "accesskey",
        "private_key",
        "privatekey",
        "credential",
        "auth",
        "cookie",
        "session",
    ];
    let k = key
        .rsplit(['-', '.'])
        .next()
        .unwrap_or(key)
        .to_ascii_lowercase();
    PARTS.iter().any(|p| k.contains(p))
        || ["key", "pass", "pwd", "pat", "sig"].contains(&k.as_str())
}

/// The key that ends just before `at` (a `=` or `:`): `token = `, `"token": `, `TOKEN=`.
fn key_before(b: &[u8], at: usize) -> Option<&str> {
    let mut j = at;
    while j > 0 && b[j - 1] == b' ' {
        j -= 1;
    }
    if j > 0 && matches!(b[j - 1], b'"' | b'\'') {
        j -= 1;
    }
    let end = j;
    while j > 0 && (is_word(b[j - 1]) || b[j - 1] == b'-' || b[j - 1] == b'.') {
        j -= 1;
    }
    (j < end)
        .then(|| std::str::from_utf8(&b[j..end]).ok())
        .flatten()
}

/// Values given to keys that name secrets (`password = "…"`, `token: …`, `?sig=…`): a quoted
/// value to its closing quote, else to the next separator; after a `:` (a header, YAML) to
/// the line's end. Refs are left to `secret_refs`, which keeps their scheme.
fn assignments(text: &str) -> String {
    replace_spans(text, "<redacted>", |b, i| {
        if !matches!(b[i], b'=' | b':') || !sensitive_key(key_before(b, i)?) {
            return None;
        }
        let rest = &b[i + 1..];
        if rest.starts_with(b"//") || rest.starts_with(b":") || rest.starts_with(b"=") {
            return None;
        }
        let mut start = i + 1;
        while start < b.len() && b[start] == b' ' {
            start += 1;
        }
        // Already redacted, a ref, or a structure whose items are judged on their own.
        let left = |v: &[u8]| {
            v.is_empty()
                || [&b"<"[..], b"[", b"{", b"true", b"false", b"env:"]
                    .iter()
                    .any(|p| v.starts_with(p))
                || SCHEMES.iter().any(|s| v.starts_with(s.as_bytes()))
        };
        let value = &b[start..];
        if left(value) {
            return None;
        }
        if let Some(&q) = value.first().filter(|q| matches!(q, b'"' | b'\'')) {
            let open = start + 1;
            let close = b[open..]
                .iter()
                .position(|&c| c == q || c == b'\n')
                .map_or(b.len(), |p| open + p);
            return (!left(&b[open..close])).then_some((open, close));
        }
        let stop: &[u8] = if b[i] == b':' {
            b"\n\r,;\"'"
        } else {
            b" \t\n\r&,;\"')"
        };
        let end = b[start..]
            .iter()
            .position(|c| stop.contains(c))
            .map_or(b.len(), |p| start + p);
        Some((start, end))
    })
}

/// `someone@example.com`; the `git@` of an ssh remote stays.
fn emails(text: &str) -> String {
    let local_char = |c: u8| c.is_ascii_alphanumeric() || b"._%+-".contains(&c);
    let domain_char = |c: u8| c.is_ascii_alphanumeric() || c == b'.' || c == b'-';
    replace_spans(text, "<email>", |b, i| {
        if !local_char(b[i]) || (i > 0 && local_char(b[i - 1])) {
            return None;
        }
        let at = i + b[i..].iter().position(|&c| !local_char(c))?;
        if b.get(at) != Some(&b'@') || at == i || &b[i..at] == b"git" || b[i] == b'.' {
            return None;
        }
        let mut end = at + 1;
        while end < b.len() && domain_char(b[end]) {
            end += 1;
        }
        while end > at + 1 && matches!(b[end - 1], b'.' | b'-') {
            end -= 1;
        }
        let domain = &b[at + 1..end];
        let tld = domain.rsplit(|&c| c == b'.').next()?;
        (domain.contains(&b'.') && tld.len() >= 2 && tld.iter().all(u8::is_ascii_alphabetic))
            .then_some((i, end))
    })
}

/// Prefixes of well-known credentials (GitHub, GitLab, Slack, OpenAI and Anthropic, Stripe,
/// npm, PyPI, Hugging Face, AWS, Google, JWTs).
const TOKEN_PREFIXES: [&str; 22] = [
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "xoxa-",
    "xoxb-",
    "xoxp-",
    "xoxr-",
    "xoxs-",
    "sk-",
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "npm_",
    "pypi-",
    "hf_",
    "AKIA",
    "AIza",
    "eyJ",
];

/// Shannon entropy of `s`, in bits per byte.
fn entropy(s: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &c in s {
        counts[usize::from(c)] += 1;
    }
    let n = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn mixed(s: &[u8]) -> bool {
    s.iter().any(u8::is_ascii_uppercase)
        && s.iter().any(u8::is_ascii_lowercase)
        && s.iter().any(u8::is_ascii_digit)
}

/// Whether a run of `[A-Za-z0-9_-]` is a credential: a known prefix and enough after it,
/// mixed case with digits at 20 or more, or a stretch of 32 or more letters and digits (hex
/// keys and tokens).
fn word_token(run: &[u8]) -> bool {
    if TOKEN_PREFIXES
        .iter()
        .any(|p| run.starts_with(p.as_bytes()) && run.len() >= p.len() + 16)
    {
        return true;
    }
    if run.len() >= 20 && mixed(run) {
        return true;
    }
    run.split(|&c| c == b'-' || c == b'_').any(|seg| {
        seg.len() >= 32
            && seg.iter().any(u8::is_ascii_digit)
            && seg.iter().any(u8::is_ascii_alphabetic)
    })
}

/// Credentials in text: base64 secrets (they may hold `/` and `+`, so they are judged by
/// their randomness as well), then word-like tokens. Image digests (`sha256:…`) stay.
fn tokens(text: &str) -> String {
    let b64 = |c: u8| c.is_ascii_alphanumeric() || b"+/=_-".contains(&c);
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'-';
    let after_digest = |b: &[u8], i: usize| b[..i].ends_with(b"sha256:");
    let t = replace_spans(text, "<token>", |b, i| {
        if !b64(b[i]) || (i > 0 && b64(b[i - 1])) || after_digest(b, i) {
            return None;
        }
        let end = i + b[i..].iter().position(|&c| !b64(c)).unwrap_or(b.len() - i);
        let run = &b[i..end];
        (run.len() >= 32
            && run.iter().any(|c| b"+/=".contains(c))
            && mixed(run)
            && entropy(run) >= 4.5)
            .then_some((i, end))
    });
    replace_spans(&t, "<token>", |b, i| {
        if !word(b[i]) || (i > 0 && word(b[i - 1])) || after_digest(b, i) {
            return None;
        }
        let end = i + b[i..].iter().position(|&c| !word(c)).unwrap_or(b.len() - i);
        word_token(&b[i..end]).then_some((i, end))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r() -> Redactor {
        Redactor::new(
            Some("/Users/alice"),
            &["alice".into(), "dev".into(), "a".into()],
            &["Alice Example".into(), "alice@corp.example".into()],
            vec!["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into()],
        )
    }

    #[test]
    fn secret_refs_lose_all_but_their_scheme() {
        let text = r#"oauth_token = "op://Private/claude-code/token"
key = "op://Private/github ssh/private key?ssh-format=openssh"
token = "vault://secret/luoto#gh"
api_key = "keyring:luoto/anthropic.api_key"
private_key = "file:~/keys/app.pem"
DATABASE_URL = "env:DATABASE_URL"
refused credential `gh` (op://Dev/gh/token), `luoto vault reload` reads it
resolve secret file:/etc/x: no such file"#;
        let out = r().redact(text);
        for kept in [
            r#"oauth_token = "op://<redacted>""#,
            r#"key = "op://<redacted>""#,
            r#"token = "vault://<redacted>""#,
            r#"api_key = "keyring:<redacted>""#,
            r#"private_key = "file:<redacted>""#,
            r#"DATABASE_URL = "env:DATABASE_URL""#,
            "(op://<redacted>)",
            "file:<redacted>: no such file",
        ] {
            assert!(out.contains(kept), "{kept} not in\n{out}");
        }
        for gone in [
            "Private",
            "claude-code",
            "openssh",
            "secret/luoto",
            "anthropic.api_key",
            "keys/app",
            "/etc/x",
            "Dev/gh",
        ] {
            assert!(!out.contains(gone), "{gone} in\n{out}");
        }
    }

    #[test]
    fn plain_words_that_look_like_schemes_stay() {
        let text = "the file: x\ndesktop://a\nprofile:x\nkeyring: unlocked";
        assert_eq!(r().redact(text), text);
    }

    #[test]
    fn vault_tokens_go_by_value_and_by_key() {
        let token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let out = r().redact(&format!(
            "{{\n  \"octet\": 3,\n  \"vault_token\": \"{token}\"\n}}\nbound with {token}."
        ));
        assert!(!out.contains(token), "{out}");
        assert!(out.contains("\"octet\": 3"), "{out}");
        // A token not known by value still goes: by its key, or as a long hex string.
        let other = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        let out = r().redact(&format!("\"vault_token\": \"{other}\"\nseen {other}"));
        assert!(!out.contains(other), "{out}");
    }

    #[test]
    fn the_home_folder_becomes_a_tilde_in_every_spelling() {
        let out = r().redact(
            "dir = \"/Users/alice/dev/web\"\nbinary: /Users/alice/.local/bin/luoto\n\
             /Users/alice\n/Users/alicex/y",
        );
        assert!(out.contains("dir = \"~/dev/web\""), "{out}");
        assert!(out.contains("binary: ~/.local/bin/luoto"), "{out}");
        assert!(out.contains("\n~\n"), "{out}");
        // Another user's folder that starts alike isn't the home.
        assert!(out.contains("/Users/alicex/y"), "{out}");
        let win = Redactor::new(Some(r"C:\Users\Alice"), &[], &[], vec![]);
        assert_eq!(
            win.redact(r#"dir = "C:\\Users\\Alice\\dev" C:\Users\Alice\x C:/Users/Alice/y"#),
            r#"dir = "~\\dev" ~\x ~/y"#
        );
    }

    #[test]
    fn user_and_git_names_go_but_generic_ones_stay() {
        let out = r().redact(
            "repos = [\"alice/web\", \"ALICE/api\"]\nluoto-dev-web runs as dev\n\
             author Alice Example <alice@corp.example>\nmalice and alices stay",
        );
        assert!(out.contains("[\"<user>/web\", \"<user>/api\"]"), "{out}");
        assert!(out.contains("luoto-dev-web runs as dev"), "{out}");
        assert!(out.contains("author <name> <<name>>"), "{out}");
        assert!(out.contains("malice and alices stay"), "{out}");
    }

    #[test]
    fn email_addresses_go_and_look_alikes_stay() {
        let out = r().redact(
            "from bob.smith+x@mail.example.org, git@github.com:acme/web.git\n\
             ghcr.io/eetu/luoto-gate@sha256:0011 node@24 @scope/pkg@1.2.3 pkg@latest",
        );
        assert!(out.contains("from <email>,"), "{out}");
        assert!(out.contains("git@github.com:acme/web.git"), "{out}");
        assert!(
            out.contains("luoto-gate@sha256:0011 node@24 @scope/pkg@1.2.3 pkg@latest"),
            "{out}"
        );
    }

    #[test]
    fn credentials_in_urls_go() {
        let out = r().redact(
            "https://x-access-token:ghs_abc@github.com/acme/web.git\n\
             https://bob@dev.azure.com/org/p/_git/r\n\
             postgres://app:hunter2@db.internal:5432/app\n\
             ssh://git@github.com/acme/web.git\nhttps://github.com/acme/web",
        );
        assert!(
            out.contains("https://<redacted>@github.com/acme/web.git"),
            "{out}"
        );
        assert!(
            out.contains("https://<redacted>@dev.azure.com/org"),
            "{out}"
        );
        assert!(
            out.contains("postgres://<redacted>@db.internal:5432/app"),
            "{out}"
        );
        assert!(out.contains("ssh://git@github.com/acme/web.git"), "{out}");
        assert!(out.contains("https://github.com/acme/web"), "{out}");
        assert!(
            !out.contains("hunter2") && !out.contains("ghs_abc"),
            "{out}"
        );
    }

    #[test]
    fn tokens_go_wherever_they_are() {
        let gh = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";
        let pat = "github_pat_11ABCDEFG0aaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let ant = "sk-ant-oat01-Zx9_Yw8-Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0Fe9Dc8Ba7";
        let aws = "AKIAIOSFODNN7EXAMPLE";
        let aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let hex = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        let text = format!(
            "[env]\nGH={gh}\nrun = [\"npm config set //registry.npmjs.org/:_authToken={pat}\"]\n\
             x {ant} y\n{aws} {aws_secret}\n{jwt}\ncommit {hex}\n"
        );
        let out = r().redact(&text);
        for t in [gh, pat, ant, aws, aws_secret, jwt, hex] {
            for part in t.split(['.', '/']).filter(|p| p.len() >= 8) {
                assert!(!out.contains(part), "{part} in\n{out}");
            }
        }
    }

    #[test]
    fn ordinary_words_and_paths_stay() {
        let text = "image ghcr.io/eetu/luoto-gate@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08: ok\n\
                    env my-really-long-project-name-2: isolated (gVisor)\n\
                    env auth-service: isolated (gVisor)\n\
                    == luoto-token-api-gate: lifecycle and errors\n\
                    /workspace/frontend/src/lib/components/EnvPanel.svelte\n\
                    NODE_EXTRA_CA_CERTS=/etc/luoto/ca-bundle.pem\n\
                    ~/.local/share/mise/installs/node/24.1.0/bin\n\
                    luoto-dev-web-gate running, 2026-11-08T12:00:00Z\n\
                    protected_branches = [\"main\"]\ninstallation_id = 7890123\n\
                    sk-short and the docs.rs/serde path";
        assert_eq!(r().redact(text), text);
    }

    #[test]
    fn values_of_secret_keys_go() {
        let out = r().redact(
            "[env]\nAPI_KEY = \"abc123\"\nDB_PASSWORD=hunter2 next\n\
             GET /cb?code=1&sig=c2lnbmF0dXJl&x=1\nAuthorization: Bearer abcdefgh12345\n\
             Cookie: session=abc; theme=dark\nauthor = \"Bob\"\n\
             x-api-key: k3y-v4lue\nclient.secret=s3cr3t\n\
             token = \"op://x/y/z\"\nmax_body = 10",
        );
        for gone in [
            "abc123",
            "hunter2",
            "c2lnbmF0dXJl",
            "abcdefgh12345",
            "session=abc",
            "Bob",
            "k3y-v4lue",
            "s3cr3t",
        ] {
            assert!(!out.contains(gone), "{gone} in\n{out}");
        }
        for kept in [
            "next",
            "&x=1",
            "token = \"op://<redacted>\"",
            "max_body = 10",
            "API_KEY = \"<redacted>\"",
        ] {
            assert!(out.contains(kept), "{kept} not in\n{out}");
        }
    }

    #[test]
    fn a_report_keeps_its_shape_and_loses_what_identifies_or_grants() {
        let text = r#"[workspace]
dir = "/Users/alice/dev/web"

[credentials.github]
installation_id = 7890123
private_key = "op://Dev/luoto-github-app/private key"
repos = ["alice/web", "acme/api"]

[credentials.custom.stripe]
host = "api.stripe.com"
secret = "op://Dev/stripe-test/key"
placeholder_env = { STRIPE_API_KEY = "sk_test_luoto_placeholder" }
header = "authorization"
format = "Bearer {secret}"

[env]
RUST_LOG = "debug"
OPENAI_API_KEY = "sk-proj-abcDEF123456ghiJKL789mnoPQR"

[deps]
run = ["git config --global user.email alice@corp.example"]
{
  "home": "/home/dev",
  "user": "alice"
}
10:01:00 `web`: an upstream refused credential `github` (keyring:luoto/github.token)
binary: /Users/alice/.local/bin/luoto
"#;
        let expected = r#"[workspace]
dir = "~/dev/web"

[credentials.github]
installation_id = 7890123
private_key = "op://<redacted>"
repos = ["<user>/web", "acme/api"]

[credentials.custom.stripe]
host = "api.stripe.com"
secret = "op://<redacted>"
placeholder_env = { STRIPE_API_KEY = "<redacted>" }
header = "authorization"
format = "Bearer {secret}"

[env]
RUST_LOG = "debug"
OPENAI_API_KEY = "<redacted>"

[deps]
run = ["git config --global user.email <name>"]
{
  "home": "/home/dev",
  "user": "<user>"
}
10:01:00 `web`: an upstream refused credential `github` (keyring:<redacted>)
binary: ~/.local/bin/luoto
"#;
        assert_eq!(r().redact(text), expected);
    }

    #[test]
    fn redaction_is_stable_on_its_own_output() {
        let once = r().redact(
            "alice@corp.example op://a/b https://u:p@h/x ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
        );
        assert_eq!(r().redact(&once), once);
    }

    #[test]
    fn notable_events_are_lifecycle_and_errors() {
        let log = r#"{"seq":1,"run":"r","env":"e","kind":"lifecycle","message":"gate 0.3.1 started (3 rules)","ts":"2026-11-08T10:00:00Z"}
{"seq":2,"run":"r","env":"e","kind":"http","verdict":"allow","method":"GET","host":"registry.npmjs.org","path":"/x","status":200,"ts":"2026-11-08T10:00:01Z"}
{"seq":3,"run":"r","env":"e","kind":"http","verdict":"allow","method":"GET","host":"api.example","path":"/y","status":502,"ts":"2026-11-08T10:00:02Z"}
{"seq":4,"run":"r","env":"e","kind":"http","verdict":"deny","method":"GET","host":"docs.rs","reason":"no_rule","ts":"2026-11-08T10:00:03Z"}
{"seq":5,"run":"r","env":"e","kind":"tls_reject","host":"pinned.example","ts":"2026-11-08T10:00:04Z"}
2026-11-08T10:00:05Z  WARN could not mint certificate host=x
"#;
        let (events, diagnostics) = notable(log);
        let seqs: Vec<u64> = events.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, [1, 3, 5]);
        assert_eq!(
            diagnostics,
            ["2026-11-08T10:00:05Z  WARN could not mint certificate host=x"]
        );
    }
}
