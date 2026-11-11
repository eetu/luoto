//! Model servers (`[model_servers.<name>]`): an OpenAI- and/or Anthropic-compatible API on this
//! machine, your network or the internet, that agents use beside their providers. The gate
//! allows only the model endpoints of the APIs a server serves, on its exact host and port, and
//! adds its token; the sandbox reaches one on this machine as [`HOST`].

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use anyhow::{Context, Result, bail};
use luoto_shared::profiles::{self, AgentModelServer, JsonSet};
use serde_json::Value;

use crate::config::{AgentOpts, EnvConfig, GlobalConfig, ModelServer};
use crate::prompt::{Ask, menu_help};
use crate::text;
use crate::wizard::{Question, Secret, SecretAsk, Step, ask_menu, secret};

pub const ANTHROPIC: &str = "anthropic";
pub const OPENAI: &str = "openai";
pub const APIS: [&str; 2] = [ANTHROPIC, OPENAI];

/// This machine as the sandbox reaches it: podman's `/etc/hosts` has the name, Docker
/// Desktop's DNS answers it.
pub const HOST: &str = "host.docker.internal";

/// The token the sandbox holds for a server; the gate puts the real one in its place.
pub const PLACEHOLDER: &str = "luoto-model-server-placeholder";
/// The variable that holds it, for agents that read a token from one (Codex).
pub const TOKEN_ENV: &str = "LUOTO_MODEL_TOKEN";

/// A server's address, parsed.
#[derive(Debug, Clone, PartialEq)]
pub struct Endpoint {
    pub https: bool,
    /// Lowercase; an IPv6 address without brackets.
    pub host: String,
    pub port: u16,
    /// Its path before `/v1`, no trailing slash: empty, or `/openai`.
    pub base: String,
}

impl Endpoint {
    pub fn parse(url: &str) -> Result<Endpoint, String> {
        let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = url.strip_prefix("http://") {
            (false, r)
        } else {
            return Err(format!("`{url}` is not an http:// or https:// address"));
        };
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        if authority.contains('@') {
            return Err("an address takes no user or password; a token goes in `token`".into());
        }
        let (host, port) = match authority.strip_prefix('[') {
            Some(r) => {
                let (h, p) = r.split_once(']').ok_or("an unclosed `[` in the address")?;
                (h, p.strip_prefix(':'))
            }
            None => match authority.rsplit_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (authority, None),
            },
        };
        let port = match port {
            Some(p) => p
                .parse::<u16>()
                .ok()
                .filter(|p| *p > 0)
                .ok_or_else(|| format!("`{p}` is not a port"))?,
            None if https => 443,
            None => 80,
        };
        let host = host.to_ascii_lowercase();
        if host.is_empty()
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
        {
            return Err(format!("`{host}` is not a host name or address"));
        }
        let path = path.trim_end_matches('/');
        if path.contains(['?', '#', '*', '\\', '%']) || path.split('/').any(|s| s == "..") {
            return Err(format!("`/{path}` is not a plain path"));
        }
        let mut base = if path.is_empty() {
            String::new()
        } else {
            format!("/{path}")
        };
        if base.ends_with("/v1") {
            base.truncate(base.len() - 3);
        }
        Ok(Endpoint {
            https,
            host,
            port,
            base,
        })
    }

    /// On this machine: `localhost`, a loopback address.
    pub fn this_machine(&self) -> bool {
        self.host == "localhost" || self.host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
    }

    /// An address of a private network, written as one.
    pub fn private_address(&self) -> bool {
        self.host
            .parse::<IpAddr>()
            .is_ok_and(luoto_shared::host::is_private)
    }

    /// The host the sandbox names and the gate dials.
    pub fn sandbox_host(&self) -> &str {
        if self.this_machine() {
            HOST
        } else {
            &self.host
        }
    }

    /// The server as the sandbox reaches it, without `/v1`.
    pub fn sandbox_url(&self) -> String {
        self.url_with(self.sandbox_host())
    }

    /// The server as this machine reaches it, without `/v1`.
    pub fn url(&self) -> String {
        self.url_with(&self.host)
    }

    fn url_with(&self, host: &str) -> String {
        let scheme = if self.https { "https" } else { "http" };
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_string()
        };
        let port = if self.port == if self.https { 443 } else { 80 } {
            String::new()
        } else {
            format!(":{}", self.port)
        };
        format!("{scheme}://{host}{port}{}", self.base)
    }
}

/// The model endpoints of `apis` under `base`: the model list, and each API's own.
pub fn endpoints(apis: &[String], base: &str) -> Vec<String> {
    let mut paths = vec!["/v1/models", "/v1/models/*"];
    if apis.iter().any(|a| a == ANTHROPIC) {
        paths.extend(["/v1/messages", "/v1/messages/count_tokens"]);
    }
    if apis.iter().any(|a| a == OPENAI) {
        paths.extend([
            "/v1/chat/completions",
            "/v1/completions",
            "/v1/responses",
            "/v1/embeddings",
        ]);
    }
    paths.iter().map(|p| format!("{base}{p}")).collect()
}

/// A server's name: what its tables and the agents' config keys are called.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 40
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// `[model_servers.<name>]` checked: its address, or what is wrong with it.
pub fn check(name: &str, s: &ModelServer) -> Result<Endpoint> {
    let at = format!("model_servers.{name}");
    if !valid_name(name) {
        bail!("{at}: a name is lowercase letters, digits, `-` and `_`");
    }
    if s.api.is_empty() {
        bail!("{at}: `api` names what it serves: \"anthropic\", \"openai\" or both");
    }
    if let Some(a) = s.api.iter().find(|a| !APIS.contains(&a.as_str())) {
        bail!("{at}: api `{a}` is not \"anthropic\" or \"openai\"");
    }
    let ep = Endpoint::parse(&s.url).map_err(|e| anyhow::anyhow!("{at}: {e}"))?;
    if s.token.is_some() && !ep.https && !ep.this_machine() {
        bail!(
            "{at}: a token goes to a server off this machine only over HTTPS (`https://…`); \
             one that takes none needs no `token`"
        );
    }
    if let Some(h) = &s.header
        && (h.is_empty() || !h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
    {
        bail!("{at}: `{h}` is not a header name");
    }
    Ok(ep)
}

/// What an agent's model is on server `name`: its own `model` where it starts there, else
/// the server's.
pub fn model_for<'a>(opts: &'a AgentOpts, name: &str, s: &'a ModelServer) -> Option<&'a str> {
    if opts.model_server.as_deref() == Some(name) {
        opts.model.as_deref().or(s.model.as_deref())
    } else {
        s.model.as_deref()
    }
}

/// The servers luoto has written into an agent's config: each one's entries, and the one it
/// starts on.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Written {
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub each: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
}

impl Written {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// What luoto changes in an agent's config for the env's `servers` (`m`, the agent's way with
/// them): the removals of what it wrote `before` for servers it no longer starts on or that
/// are gone, and each server's entries with the default's. With what it has written then.
pub struct Sets {
    pub removes: Vec<JsonSet>,
    pub adds: Vec<JsonSet>,
    pub now: Written,
}

pub fn sets(
    m: &AgentModelServer,
    opts: &AgentOpts,
    servers: &BTreeMap<String, ModelServer>,
    before: &Written,
) -> Sets {
    let mut now = Written::default();
    let mut adds = Vec::new();
    for (name, s) in servers.iter().filter(|(_, s)| s.api.contains(&m.api)) {
        let Ok(ep) = Endpoint::parse(&s.url) else {
            continue;
        };
        let vars = Vars {
            name,
            url: ep.sandbox_url(),
            model: model_for(opts, name, s),
            context: s.context,
        };
        adds.extend(m.each.iter().filter_map(|set| fill(set, &vars)));
        now.each.insert(name.clone());
        if opts.model_server.as_deref() == Some(name.as_str()) {
            adds.extend(m.default.iter().filter_map(|set| fill(set, &vars)));
            now.default = Some(name.clone());
        }
    }
    let mut removes: Vec<JsonSet> = Vec::new();
    let mut remove = |file: &str, path: Vec<String>| {
        let set = JsonSet {
            file: file.to_string(),
            path,
            value: Value::Null,
        };
        if !removes.contains(&set) {
            removes.push(set);
        }
    };
    for gone in before.each.difference(&now.each) {
        for set in &m.each {
            if let Some(path) = owned_path(set, gone) {
                remove(&set.file, path);
            }
        }
    }
    if before.default.is_some() && now.default.is_none() {
        for set in &m.default {
            remove(&set.file, set.path.clone());
        }
    }
    Sets { removes, adds, now }
}

struct Vars<'a> {
    name: &'a str,
    url: String,
    model: Option<&'a str>,
    context: Option<u64>,
}

/// The output cap that goes with a context window where an agent wants one beside it
/// (OpenCode 1.x): no server gives one, so 32000, what agents ask for by default, or a quarter
/// of a smaller window, which leaves the rest for the input.
fn output_cap(context: u64) -> u64 {
    (context / 4).min(32_000)
}

/// `set` with its placeholders filled in; none when it names `{model}` or `{context}` (or
/// `{output}`, from it) and that isn't known. A value that is `{context:n}` or `{output:n}`
/// alone becomes a number.
fn fill(set: &JsonSet, v: &Vars) -> Option<JsonSet> {
    let names = |p: &str| {
        set.path.iter().any(|x| x.contains(p))
            || serde_json::to_string(&set.value).is_ok_and(|t| t.contains(p))
    };
    let windowed = names("{context") || names("{output");
    if (names("{model}") && v.model.is_none()) || (windowed && v.context.is_none()) {
        return None;
    }
    let number = match set.value.as_str() {
        Some("{context:n}") => v.context,
        Some("{output:n}") => v.context.map(output_cap),
        _ => None,
    };
    if let Some(n) = number {
        return Some(JsonSet {
            file: set.file.clone(),
            path: set
                .path
                .iter()
                .map(|p| {
                    p.replace("{name}", v.name)
                        .replace("{model}", v.model.unwrap_or_default())
                })
                .collect(),
            value: Value::from(n),
        });
    }
    let text = |t: &str| {
        t.replace("{name}", v.name)
            .replace("{url}", &v.url)
            .replace("{model}", v.model.unwrap_or_default())
            .replace(
                "{context}",
                &v.context.map(|c| c.to_string()).unwrap_or_default(),
            )
            .replace("{token}", PLACEHOLDER)
    };
    fn value(v: &Value, text: &dyn Fn(&str) -> String) -> Value {
        match v {
            Value::String(s) => Value::String(text(s)),
            Value::Array(a) => Value::Array(a.iter().map(|x| value(x, text)).collect()),
            Value::Object(o) => {
                Value::Object(o.iter().map(|(k, x)| (text(k), value(x, text))).collect())
            }
            other => other.clone(),
        }
    }
    Some(JsonSet {
        file: set.file.clone(),
        path: set.path.iter().map(|p| text(p)).collect(),
        value: value(&set.value, &text),
    })
}

/// The part of `set`'s path that is server `name`'s own, up to the key `{name}` fills: what
/// goes with the server.
fn owned_path(set: &JsonSet, name: &str) -> Option<Vec<String>> {
    let at = set.path.iter().position(|p| p.contains("{name}"))?;
    Some(
        set.path[..=at]
            .iter()
            .map(|p| p.replace("{name}", name))
            .collect(),
    )
}

/// Ports model servers listen on by default, and who: where the questions look on this
/// machine, and what their help names.
pub const COMMON_PORTS: [(u16, &str); 5] = [
    (11434, "Ollama"),
    (1234, "LM Studio"),
    (8000, "MTPLX, vLLM"),
    (8080, "llama.cpp"),
    (4000, "LiteLLM"),
];

/// What a server answered: whether it did, whether it wants a token, its models, and which
/// APIs it serves (`None`: unknown, it didn't answer that far).
#[derive(Debug, Default, Clone)]
pub struct Probe {
    pub answered: bool,
    pub needs_token: bool,
    pub models: Vec<String>,
    /// The context windows the server gives for its models, by model.
    pub contexts: BTreeMap<String, u64>,
    /// Who its models say they are from, when that names the server (`mtplx`).
    pub owner: Option<String>,
    pub anthropic: Option<bool>,
    pub openai: Option<bool>,
}

impl Probe {
    /// The APIs it serves, as `api` names them; empty when unknown.
    pub fn apis(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.anthropic == Some(true) {
            out.push(ANTHROPIC.to_string());
        }
        if self.openai == Some(true) {
            out.push(OPENAI.to_string());
        }
        out
    }

    /// What it is, in a menu's few words.
    fn describe(&self) -> String {
        if self.needs_token {
            return "answers, needs a token".into();
        }
        let apis = match (self.anthropic, self.openai) {
            (Some(true), Some(true)) => "Anthropic and OpenAI API",
            (Some(true), _) => "Anthropic API",
            (_, Some(true)) => "OpenAI API",
            _ => "answers",
        };
        match self.models.len() {
            0 => apis.to_string(),
            1 => format!("{apis}, 1 model"),
            n => format!("{apis}, {n} models"),
        }
    }
}

/// Ask the server at `ep`, as this machine reaches it, what it is (`token` in `header`): its
/// model list, and whether its APIs' endpoints exist, from an empty request, which a server
/// answers with 400 where one does and 404 where not. Nothing is generated.
pub fn probe(ep: &Endpoint, token: Option<&str>, header: &str) -> Probe {
    let url = ep.url();
    let local = ep.this_machine();
    let Some((code, body)) = curl("GET", &format!("{url}/v1/models"), token, header, local) else {
        return Probe::default();
    };
    let mut p = Probe {
        answered: true,
        ..Default::default()
    };
    if code == 401 || code == 403 {
        p.needs_token = true;
        return p;
    }
    if code == 200 {
        p.models = model_ids(&body);
        p.contexts = contexts(&body);
        p.owner = owner(&body);
    }
    p.anthropic = has_endpoint(ep, token, header, "/v1/messages");
    p.openai = has_endpoint(ep, token, header, "/v1/chat/completions");
    p
}

/// Whether the server at `ep` has `path`, from an empty POST: 404 where it doesn't. None when
/// it didn't answer.
pub fn has_endpoint(ep: &Endpoint, token: Option<&str>, header: &str, path: &str) -> Option<bool> {
    curl(
        "POST",
        &format!("{}{path}", ep.url()),
        token,
        header,
        ep.this_machine(),
    )
    .map(|(c, _)| c != 404)
}

/// The model IDs of a `/v1/models` answer (OpenAI's and Anthropic's shape alike).
fn model_ids(body: &str) -> Vec<String> {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let mut ids: Vec<String> = v["data"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| m["id"].as_str())
        .filter(|id| !id.is_empty() && id.len() <= 200 && !id.contains(char::is_control))
        .map(str::to_string)
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// The context window a `/v1/models` answer gives for each model, under the names servers use
/// for it (`context_length`, vLLM's `max_model_len`, `max_context_length`).
fn contexts(body: &str) -> BTreeMap<String, u64> {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    v["data"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| {
            let id = m["id"].as_str()?;
            let n = [
                "context_length",
                "max_model_len",
                "max_context_length",
                "context_window",
            ]
            .iter()
            .find_map(|k| m[*k].as_u64())
            .filter(|n| *n > 0)?;
            Some((id.to_string(), n))
        })
        .collect()
}

/// The `owned_by` all of a `/v1/models` answer's models share, when it names a server rather
/// than a placeholder (`library`, `organization_owner`).
fn owner(body: &str) -> Option<String> {
    const GENERIC: [&str; 7] = [
        "library",
        "organization_owner",
        "organization-owner",
        "owner",
        "system",
        "user",
        "openai",
    ];
    let v: Value = serde_json::from_str(body).ok()?;
    let owners: BTreeSet<&str> = v["data"]
        .as_array()?
        .iter()
        .filter_map(|m| m["owned_by"].as_str())
        .collect();
    let [one] = owners.into_iter().collect::<Vec<_>>()[..] else {
        return None;
    };
    let one = one.to_ascii_lowercase();
    (valid_name(&one) && !GENERIC.contains(&one.as_str())).then_some(one)
}

/// `curl` to `url`: the status and body, or none when nothing answered. A token goes in its
/// config on stdin, never on its command line.
fn curl(
    method: &str,
    url: &str,
    token: Option<&str>,
    header: &str,
    local: bool,
) -> Option<(u16, String)> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut c = Command::new(if cfg!(windows) { "curl.exe" } else { "curl" });
    c.args(["-sS", "--max-time", "3", "-X", method, "-o", "-"])
        .args(["-w", "\n%{http_code}", "-K", "-"]);
    if local {
        c.args(["--noproxy", "*"]);
    }
    if method == "POST" {
        c.args(["-H", "content-type: application/json", "--data", "{}"]);
    }
    c.arg(url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = c.spawn().ok()?;
    let mut config = String::new();
    if let Some(t) = token {
        let value = if header.eq_ignore_ascii_case("authorization") {
            format!("Bearer {t}")
        } else {
            t.to_string()
        };
        let quoted = format!("{header}: {value}")
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        config.push_str(&format!("header = \"{quoted}\"\n"));
    }
    child.stdin.take()?.write_all(config.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let (body, code) = text.rsplit_once('\n')?;
    Some((code.trim().parse().ok()?, body.to_string()))
}

/// The model servers that answer on this machine's [`COMMON_PORTS`].
pub fn scan() -> Vec<(u16, Probe)> {
    std::thread::scope(|s| {
        let asks: Vec<_> = COMMON_PORTS
            .iter()
            .map(|&(port, _)| {
                s.spawn(move || {
                    let ep = Endpoint {
                        https: false,
                        host: "localhost".into(),
                        port,
                        base: String::new(),
                    };
                    (port, probe(&ep, None, "authorization"))
                })
            })
            .collect();
        asks.into_iter()
            .filter_map(|a| a.join().ok())
            .filter(|(_, p)| p.answered)
            .collect()
    })
}

/// What the model server questions settle on: the server (one the env has, or a new one) and
/// the agent's model there.
pub struct Picked {
    pub name: String,
    pub server: ModelServer,
    pub model: String,
}

#[derive(Clone)]
enum Row {
    Have(String),
    Found(u16, Probe),
    Another,
}

/// Which model server agent `a` starts on: one the env has, one answering on this machine,
/// or another address; then its token where it wants one, and the model. `Back` is Esc at
/// the first question.
pub fn ask(global: &GlobalConfig, a: &profiles::Agent, cfg: &EnvConfig) -> Result<Step<Picked>> {
    let m = a
        .model_server
        .as_ref()
        .with_context(|| format!("{} can't use a model server", a.title()))?;
    let found = crate::progress::wait("looking for model servers on this machine", scan);
    let current = cfg.agents.get(&a.name).and_then(|o| o.model_server.clone());
    let mut rows: Vec<(Row, String, String)> = Vec::new();
    for (name, s) in cfg
        .model_servers
        .iter()
        .filter(|(_, s)| s.api.contains(&m.api))
    {
        let mark = if current.as_deref() == Some(name.as_str()) {
            " (current)"
        } else {
            ""
        };
        rows.push((
            Row::Have(name.clone()),
            format!("{name}{mark}"),
            s.url.clone(),
        ));
    }
    let have_ports: Vec<u16> = cfg
        .model_servers
        .values()
        .filter_map(|s| Endpoint::parse(&s.url).ok())
        .filter(Endpoint::this_machine)
        .map(|e| e.port)
        .collect();
    for (port, p) in found {
        let serves = |known: Option<bool>| known != Some(false);
        let fits = if m.api == ANTHROPIC {
            serves(p.anthropic)
        } else {
            serves(p.openai)
        };
        if have_ports.contains(&port) || !fits {
            continue;
        }
        let what = p.describe();
        rows.push((Row::Found(port, p), format!("localhost:{port}"), what));
    }
    rows.push((
        Row::Another,
        "Another address".into(),
        "not running yet, or on your network or the internet".into(),
    ));
    let at = rows
        .iter()
        .position(|(_, l, _)| l.ends_with(" (current)"))
        .unwrap_or(0);
    loop {
        let Some(row) = ask_menu(Question {
            text: format!("Which model server should {} use?", a.title()),
            rows: rows.clone(),
            at,
            help: menu_help("back"),
        })?
        else {
            return Ok(Step::Back);
        };
        let picked = match row {
            Row::Have(name) => {
                let s = cfg.model_servers[&name].clone();
                let ep = Endpoint::parse(&s.url).map_err(|e| anyhow::anyhow!(e))?;
                let token = match &s.token {
                    Some(r) => readable_token(global, r),
                    None => None,
                };
                let p = crate::progress::wait("asking it for its models", || {
                    probe(&ep, token.as_deref(), header_of(&s))
                });
                let now = cfg.agents.get(&a.name).and_then(|o| o.model.clone());
                match ask_model(a, &p.models, now.as_deref().or(s.model.as_deref()))? {
                    Step::Got(model) => {
                        let context = p.contexts.get(&model).copied().or(s.context);
                        Some(Picked {
                            name,
                            server: ModelServer { context, ..s },
                            model,
                        })
                    }
                    Step::Back => None,
                }
            }
            Row::Found(port, p) => {
                let ep = Endpoint {
                    https: false,
                    host: "localhost".into(),
                    port,
                    base: String::new(),
                };
                new_server(global, a, cfg, &ep, p)?
            }
            Row::Another => match ask_address()? {
                Step::Got(ep) => {
                    let p = crate::progress::wait(&format!("asking {}", ep.url()), || {
                        probe(&ep, None, "authorization")
                    });
                    new_server(global, a, cfg, &ep, p)?
                }
                Step::Back => None,
            },
        };
        if let Some(p) = picked {
            let s = &p.server;
            if let Ok(ep) = Endpoint::parse(&s.url) {
                let token = s.token.as_deref().and_then(|r| readable_token(global, r));
                if has_endpoint(&ep, token.as_deref(), header_of(s), &m.endpoint) == Some(false) {
                    let why = format!(
                        "It has no {}, which {} calls: it can't use the server.",
                        m.endpoint,
                        a.title()
                    );
                    println!("{}", text::wrap(&why, "  ", text::columns()));
                    continue;
                }
            }
            return Ok(Step::Got(p));
        }
    }
}

/// A server new to the env at `ep` (`p`, what it answered): what it serves, its token, its
/// name, the model. None for Esc on the way, back to the server menu.
fn new_server(
    global: &GlobalConfig,
    a: &profiles::Agent,
    cfg: &EnvConfig,
    ep: &Endpoint,
    mut p: Probe,
) -> Result<Option<Picked>> {
    let m = a.model_server.as_ref().context("a model server agent")?;
    if ep.this_machine() {
        let mut note = String::from(
            "The model server runs on this machine with your privileges, outside luoto's VM: \
             code in the env can reach its model API, and only that. Keeping it sandboxed and \
             up to date is yours.",
        );
        if cfg!(target_os = "linux") {
            note.push_str(
                " On Linux it must listen on this machine's address, not only 127.0.0.1.",
            );
        }
        println!("{}", text::wrap(&note, "  ", text::columns()));
    }
    let name = suggest_name(ep, p.owner.as_deref(), cfg);
    let takes_token = if p.needs_token {
        true
    } else if p.answered {
        false
    } else {
        let rows = vec![
            (
                false,
                "No token".to_string(),
                "it answers anyone who reaches it".to_string(),
            ),
            (
                true,
                "A token".to_string(),
                "the gate adds it to each request".to_string(),
            ),
        ];
        match ask_menu(Question {
            text: "Does it need a token?".into(),
            rows,
            at: usize::from(!ep.this_machine()),
            help: menu_help("back"),
        })? {
            Some(t) => t,
            None => return Ok(None),
        }
    };
    if takes_token && !ep.https && !ep.this_machine() {
        println!(
            "{}",
            text::wrap(
                "A token goes to a server off this machine only over HTTPS: give its https:// \
                 address.",
                "  ",
                text::columns()
            )
        );
        return Ok(None);
    }
    let mut token = None;
    if takes_token {
        let label = format!("The token of {}", ep.url());
        let acct = format!("model_server.{name}");
        let title = format!("luoto model server {name}");
        let help = menu_help("back");
        let ask = SecretAsk {
            label: &label,
            acct: &acct,
            title: &title,
            later: false,
            known: &[],
            current: None,
            help: &help,
            kind: None,
        };
        match secret(&ask, global)? {
            Step::Got(Secret::Ref(r)) => {
                if let Some(value) = readable_token(global, &r) {
                    p = crate::progress::wait("asking it for its models", || {
                        probe(ep, Some(&value), "authorization")
                    });
                }
                token = Some(r);
            }
            Step::Got(Secret::Later) | Step::Back => return Ok(None),
        }
    }
    let api = match p.apis() {
        apis if !apis.is_empty() => apis,
        _ => match ask_api(m)? {
            Some(apis) => apis,
            None => return Ok(None),
        },
    };
    if !api.contains(&m.api) {
        println!(
            "{}",
            text::wrap(
                &format!(
                    "It serves the {} API; {} speaks {}.",
                    api.join(" and "),
                    a.title(),
                    m.api
                ),
                "  ",
                text::columns()
            )
        );
        return Ok(None);
    }
    let model = match ask_model(a, &p.models, None)? {
        Step::Got(m) => m,
        Step::Back => return Ok(None),
    };
    let private = !ep.this_machine() && !ep.private_address() && private_host(&ep.host);
    let context = p.contexts.get(&model).copied();
    Ok(Some(Picked {
        name,
        server: ModelServer {
            url: ep.url(),
            api,
            model: None,
            context,
            token,
            header: None,
            private,
        },
        model,
    }))
}

/// The address of a server, as this machine reaches it.
fn ask_address() -> Result<Step<Endpoint>> {
    let ports: Vec<String> = COMMON_PORTS
        .iter()
        .map(|(p, what)| format!("{what} {p}"))
        .collect();
    let help = format!(
        "http://localhost:<port> ({}), http://192.168.1.50:8080, https://models.example.com; \
         Esc: back",
        ports.join(", ")
    );
    let typed = inquire::Text::new("Its address:")
        .with_initial_value("http://localhost:")
        .with_help_message(&help)
        .with_validator(|v: &str| {
            Ok(match Endpoint::parse(v.trim()) {
                Ok(_) => inquire::validator::Validation::Valid,
                Err(e) => inquire::validator::Validation::Invalid(e.into()),
            })
        })
        .ask()?;
    Ok(match typed {
        Some(t) => Step::Got(Endpoint::parse(t.trim()).map_err(|e| anyhow::anyhow!(e))?),
        None => Step::Back,
    })
}

/// What a server that didn't answer serves: both, or the agent's API alone.
fn ask_api(m: &AgentModelServer) -> Result<Option<Vec<String>>> {
    let both = vec![ANTHROPIC.to_string(), OPENAI.to_string()];
    let (label, short) = if m.api == ANTHROPIC {
        ("Anthropic API", "/v1/messages")
    } else {
        ("OpenAI API", "/v1/chat/completions, /v1/responses")
    };
    let rows = vec![
        (vec![m.api.clone()], label.to_string(), short.to_string()),
        (
            both,
            "Both".to_string(),
            "Anthropic's and OpenAI's".to_string(),
        ),
    ];
    ask_menu(Question {
        text: "Which API does it serve?".into(),
        rows,
        at: 0,
        help: menu_help("back"),
    })
}

/// The model the agent uses there: one of `models` the server lists, else typed.
fn ask_model(a: &profiles::Agent, models: &[String], now: Option<&str>) -> Result<Step<String>> {
    let question = format!("Which model should {} use there?", a.title());
    if !models.is_empty() {
        let rows = models
            .iter()
            .map(|m| (m.clone(), m.clone(), String::new()))
            .collect();
        let at = now
            .and_then(|n| models.iter().position(|m| m == n))
            .unwrap_or(0);
        return Ok(ask_menu(Question {
            text: question,
            rows,
            at,
            help: menu_help("back"),
        })?
        .into());
    }
    let typed = inquire::Text::new(&question)
        .with_initial_value(now.unwrap_or_default())
        .with_help_message(
            "as the server names it (`ollama list`, LM Studio's model list); Esc: back",
        )
        .with_validator(|v: &str| {
            Ok(if v.trim().is_empty() || v.contains(char::is_control) {
                inquire::validator::Validation::Invalid("a model name".into())
            } else {
                inquire::validator::Validation::Valid
            })
        })
        .ask()?;
    Ok(typed.map(|t| t.trim().to_string()).into())
}

/// A name for a new server at `ep` that the env doesn't have yet: who its models are from
/// (`owner`), else its port or host.
fn suggest_name(ep: &Endpoint, owner: Option<&str>, cfg: &EnvConfig) -> String {
    let base = if let Some(o) = owner {
        o.to_string()
    } else if ep.this_machine() {
        match ep.port {
            11434 => "ollama".to_string(),
            1234 => "lm-studio".to_string(),
            8080 => "llama-cpp".to_string(),
            4000 => "litellm".to_string(),
            p => format!("local-{p}"),
        }
    } else if ep.host.parse::<IpAddr>().is_ok() {
        format!("server-{}", ep.host.replace(['.', ':'], "-"))
    } else {
        let label = ep.host.split('.').next().unwrap_or("server");
        let clean: String = label
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        clean.trim_matches('-').to_string()
    };
    let base = if valid_name(&base) {
        base
    } else {
        "server".into()
    };
    (1..)
        .map(|i| {
            if i == 1 {
                base.clone()
            } else {
                format!("{base}-{i}")
            }
        })
        .find(|n| !cfg.model_servers.contains_key(n))
        .unwrap_or(base)
}

/// Whether host name `host` resolves to private addresses only, as a self-hosted server's do.
fn private_host(host: &str) -> bool {
    use std::net::ToSocketAddrs;
    let addrs: Vec<_> = (host, 443)
        .to_socket_addrs()
        .map(|a| a.collect())
        .unwrap_or_default();
    !addrs.is_empty()
        && addrs
            .iter()
            .all(|a: &std::net::SocketAddr| luoto_shared::host::is_private(a.ip()))
}

/// The value of token ref `r` for asking the server, or none (said why) when it doesn't read.
fn readable_token(global: &GlobalConfig, r: &str) -> Option<String> {
    match crate::secrets::resolve(global, r) {
        Ok(v) => Some(v),
        Err(e) => {
            eprintln!("its token didn't read ({e:#}); its models aren't listed");
            None
        }
    }
}

fn header_of(s: &ModelServer) -> &str {
    s.header.as_deref().unwrap_or("authorization")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(url: &str, api: &[&str], model: Option<&str>) -> ModelServer {
        ModelServer {
            url: url.into(),
            api: api.iter().map(|a| a.to_string()).collect(),
            model: model.map(str::to_string),
            context: None,
            token: None,
            header: None,
            private: false,
        }
    }

    #[test]
    fn an_address_reads_as_the_server_and_its_root() {
        let ep = Endpoint::parse("http://LOCALHOST:11434/").unwrap();
        assert!(ep.this_machine() && !ep.https);
        assert_eq!(
            (ep.host.as_str(), ep.port, ep.base.as_str()),
            ("localhost", 11434, "")
        );
        assert_eq!(ep.sandbox_url(), "http://host.docker.internal:11434");
        let ep = Endpoint::parse("https://models.example.com/openai/v1").unwrap();
        assert_eq!((ep.port, ep.base.as_str()), (443, "/openai"));
        assert_eq!(ep.sandbox_url(), "https://models.example.com/openai");
        assert!(Endpoint::parse("http://[::1]:8000").unwrap().this_machine());
        assert!(
            Endpoint::parse("http://192.168.1.50:8080")
                .unwrap()
                .private_address()
        );
        for bad in [
            "localhost:11434",
            "http://user:pw@host",
            "http://host:99999",
            "http://host/a/../b",
            "http://ho st",
        ] {
            assert!(Endpoint::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_window_a_server_gives_reaches_the_agents_that_cant_tell_it() {
        let body = r#"{"data":[{"id":"q","context_length":204800},{"id":"v","max_model_len":32768},{"id":"n"}]}"#;
        assert_eq!(
            contexts(body),
            [("q".to_string(), 204800), ("v".to_string(), 32768)].into()
        );
        let claude = luoto_shared::profiles::agent("claude").unwrap();
        let mut s = server("http://localhost:8000", &["anthropic", "openai"], Some("q"));
        let opts = AgentOpts {
            model_server: Some("m".into()),
            ..Default::default()
        };
        let window = |s: &ModelServer| {
            let servers = [("m".to_string(), s.clone())].into();
            super::sets(
                claude.model_server.as_ref().unwrap(),
                &opts,
                &servers,
                &Written::default(),
            )
            .adds
            .into_iter()
            .find(|x| x.path.last().map(String::as_str) == Some("CLAUDE_CODE_MAX_CONTEXT_TOKENS"))
            .map(|x| x.value)
        };
        assert_eq!(window(&s), None);
        s.context = Some(204800);
        assert_eq!(window(&s), Some(Value::String("204800".into())));
        let opencode = luoto_shared::profiles::agent("opencode").unwrap();
        let servers = [("m".to_string(), s.clone())].into();
        let adds = super::sets(
            opencode.model_server.as_ref().unwrap(),
            &opts,
            &servers,
            &Written::default(),
        )
        .adds;
        let limit = |k: &str| {
            adds.iter()
                .find(|x| x.path == ["provider", "m", "models", "q", "limit", k])
                .map(|x| x.value.clone())
        };
        // OpenCode 1.x refuses a limit without both.
        assert_eq!(limit("context"), Some(Value::from(204800)));
        assert_eq!(limit("output"), Some(Value::from(32000)));
        assert_eq!(output_cap(8192), 2048);
        let codex = luoto_shared::profiles::agent("codex").unwrap();
        let servers = [("m".to_string(), s)].into();
        let adds = super::sets(
            codex.model_server.as_ref().unwrap(),
            &opts,
            &servers,
            &Written::default(),
        )
        .adds;
        let at = adds
            .iter()
            .find(|x| x.path == ["profiles", "m", "model_context_window"])
            .map(|x| x.value.clone());
        assert_eq!(at, Some(Value::from(204800)));
    }

    #[test]
    fn a_server_is_named_by_its_models_owner_when_that_names_it() {
        let one = r#"{"data":[{"id":"q","owned_by":"mtplx"},{"id":"r","owned_by":"mtplx"}]}"#;
        assert_eq!(owner(one).as_deref(), Some("mtplx"));
        assert_eq!(owner(r#"{"data":[{"id":"q","owned_by":"library"}]}"#), None);
        assert_eq!(
            owner(r#"{"data":[{"id":"q","owned_by":"a"},{"id":"r","owned_by":"b"}]}"#),
            None
        );
        let cfg: EnvConfig = toml::from_str(
            "[model_servers.mtplx]\nurl = \"http://localhost:9\"\napi = [\"openai\"]",
        )
        .unwrap();
        let ep = Endpoint::parse("http://localhost:8000").unwrap();
        assert_eq!(suggest_name(&ep, Some("mtplx"), &cfg), "mtplx-2");
        assert_eq!(suggest_name(&ep, None, &cfg), "local-8000");
        let lan = Endpoint::parse("https://gpu.lan:8443").unwrap();
        assert_eq!(suggest_name(&lan, None, &cfg), "gpu");
    }

    #[test]
    fn a_token_leaves_this_machine_only_over_https() {
        let mut s = server("http://192.168.1.50:8080", &["openai"], None);
        s.token = Some("keyring:luoto/gpu".into());
        assert!(check("gpu", &s).is_err());
        s.url = "https://gpu.lan:8443".into();
        assert!(check("gpu", &s).is_ok());
        s.url = "http://localhost:8000".into();
        assert!(check("gpu", &s).is_ok());
        assert!(check("Bad Name", &s).is_err());
        assert!(check("gpu", &server("http://localhost", &[], None)).is_err());
        assert!(check("gpu", &server("http://localhost", &["gemini"], None)).is_err());
    }

    #[test]
    fn only_the_model_endpoints_of_its_apis() {
        let anthropic = endpoints(&["anthropic".into()], "");
        assert!(anthropic.contains(&"/v1/messages".to_string()));
        assert!(!anthropic.iter().any(|p| p.contains("chat")));
        let both = endpoints(&["openai".into(), "anthropic".into()], "/proxy");
        assert!(both.contains(&"/proxy/v1/responses".to_string()));
        assert!(
            !both
                .iter()
                .any(|p| p.contains("/api/") || p.contains("pull"))
        );
    }

    #[test]
    fn an_agent_gets_each_server_and_loses_what_it_no_longer_has() {
        let codex = luoto_shared::profiles::agent("codex").unwrap();
        let m = codex.model_server.unwrap();
        let servers: BTreeMap<String, ModelServer> = [
            (
                "mtplx".to_string(),
                server(
                    "http://localhost:8000",
                    &["openai", "anthropic"],
                    Some("q3"),
                ),
            ),
            (
                "claude-only".to_string(),
                server("http://localhost:9000", &["anthropic"], None),
            ),
        ]
        .into();
        let opts = AgentOpts {
            model_server: Some("mtplx".into()),
            ..Default::default()
        };
        let s = super::sets(&m, &opts, &servers, &Written::default());
        let (got, now) = (s.adds, s.now);
        assert_eq!(now.default.as_deref(), Some("mtplx"));
        assert_eq!(now.each, ["mtplx".to_string()].into());
        let at = |path: &[&str]| got.iter().find(|s| s.path == path).map(|s| s.value.clone());
        assert_eq!(
            at(&["model_providers", "mtplx", "base_url"]),
            Some(Value::String("http://host.docker.internal:8000/v1".into()))
        );
        assert_eq!(
            at(&["profiles", "mtplx", "model"]),
            Some(Value::String("q3".into()))
        );
        assert_eq!(at(&["profile"]), Some(Value::String("mtplx".into())));
        // The server goes, and with it what was written for it.
        let s = super::sets(&m, &AgentOpts::default(), &BTreeMap::new(), &now);
        assert!(s.adds.is_empty());
        let (got, now) = (s.removes, s.now);
        assert!(now.is_empty());
        assert!(got.iter().all(|s| s.value.is_null()));
        let paths: Vec<_> = got.iter().map(|s| s.path.join(".")).collect();
        assert!(paths.contains(&"model_providers.mtplx".to_string()));
        assert!(paths.contains(&"profiles.mtplx".to_string()));
        assert!(paths.contains(&"profile".to_string()));
    }

    #[test]
    fn an_entry_that_needs_a_model_waits_for_one() {
        let opencode = luoto_shared::profiles::agent("opencode").unwrap();
        let m = opencode.model_server.unwrap();
        let servers: BTreeMap<String, ModelServer> = [(
            "box".to_string(),
            server("https://box.lan", &["openai"], None),
        )]
        .into();
        let got = super::sets(&m, &AgentOpts::default(), &servers, &Written::default()).adds;
        assert!(!got.is_empty());
        assert!(got.iter().all(|s| !s.path.join(".").contains("models")));
    }
}
