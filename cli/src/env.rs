//! Env lifecycle: create/start/stop/remove the networks, volumes and containers of an env,
//! keep the gate's policy and the vault's bindings in sync with the config, and verify
//! isolation from inside before declaring the env ready.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use luoto_shared::ctl::{GateCtl, VaultCtl};
use luoto_shared::policy::Rule;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::compile::{Compiled, compile};
use crate::config::{self, EnvConfig, EnvFile, GlobalConfig, Isolation};
use crate::paths::{Paths, write_private};
use crate::runtime::{Flavor, RunSpec, Runtime};
use crate::{ca, ctl, deps, machine, names, personal, project, secrets, ssh, workspace};

pub const UID: &str = "1000";

pub struct Ctx {
    pub paths: Paths,
    pub global: GlobalConfig,
    pub rt: Runtime,
}

impl Ctx {
    pub fn load() -> Result<Self> {
        let paths = Paths::get()?;
        let global = config::load_global(&paths)?;
        let rt = Runtime::from_config(&global)?;
        Ok(Ctx { paths, global, rt })
    }

    pub fn image(&self, component: &str) -> String {
        crate::release::image(self.global.images.as_deref(), component)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvState {
    pub octet: u8,
    pub home: Option<String>,
    pub vault_token: String,
    pub created: DateTime<Utc>,
    /// The folder has been copied into the workspace volume.
    #[serde(default)]
    pub seeded: bool,
    /// Login user in the dev container (uid 1000).
    #[serde(default)]
    pub user: Option<String>,
    /// Hash of a luoto.toml text the user declined, so it isn't offered again.
    #[serde(default)]
    pub project_declined: Option<String>,
}

impl EnvState {
    /// The dev user's login name for SSH: the recorded one if it is a plain user name.
    pub fn login(&self) -> &str {
        self.user
            .as_deref()
            .filter(|u| crate::ssh::valid_user(u))
            .unwrap_or("dev")
    }

    pub fn load(ctx: &Ctx, env: &str) -> Result<Option<Self>> {
        let p = ctx.paths.env_state(env).join("state.json");
        match std::fs::read(&p) {
            Ok(b) => Ok(Some(
                serde_json::from_slice(&b).with_context(|| format!("parse {}", p.display()))?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, ctx: &Ctx, env: &str) -> Result<()> {
        write_private(
            &ctx.paths.env_state(env).join("state.json"),
            &serde_json::to_vec_pretty(self)?,
        )
    }
}

fn labels(env: &str, role: &str) -> Vec<(String, String)> {
    vec![
        (names::LABEL_ENV.into(), env.into()),
        (names::LABEL_ROLE.into(), role.into()),
        ("luoto.version".into(), luoto_shared::VERSION.into()),
    ]
}

/// Hash of the run arguments plus the image ID, so a rebuilt image under the same tag also
/// counts as a changed spec.
fn spec_hash(rt: &Runtime, spec: &RunSpec) -> String {
    let args = [
        rt.run_args(spec, false),
        spec.oci_runtime.iter().cloned().collect(),
        spec.runtime_flags.clone(),
    ]
    .concat()
    .join("\u{1f}");
    let image = image_id(rt, &spec.image);
    hex::encode(&Sha256::digest(format!("{args}\u{1f}{image}").as_bytes())[..8])
}

fn image_id(rt: &Runtime, image: &str) -> String {
    rt.run(["image", "inspect", "--format", "{{.Id}}", image])
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Pick a free 10.213.x.0/24 for a new env.
fn allocate_octet(ctx: &Ctx) -> Result<u8> {
    let used = ctx.rt.used_subnets()?;
    let mut taken: BTreeSet<u8> = BTreeSet::new();
    for env in config::list_envs(&ctx.paths)? {
        if let Some(s) = EnvState::load(ctx, &env)? {
            taken.insert(s.octet);
        }
    }
    (1..=254u8)
        .find(|o| !taken.contains(o) && !used.iter().any(|s| s == &names::addrs(*o).subnet))
        .context("no free 10.213.x.0/24 subnet left for a new env")
}

pub fn state_or_init(ctx: &Ctx, env: &str, image: &str) -> Result<EnvState> {
    if let Some(s) = EnvState::load(ctx, env)? {
        return Ok(s);
    }
    let home = detect_home(ctx, image);
    let s = EnvState {
        octet: allocate_octet(ctx)?,
        home,
        vault_token: hex::encode(rand::random::<[u8; 32]>()),
        created: Utc::now(),
        seeded: false,
        user: None,
        project_declined: None,
    };
    s.save(ctx, env)?;
    Ok(s)
}

/// Home of uid 1000 in the image, or None (init.sh creates `/home/dev`).
fn detect_home(ctx: &Ctx, image: &str) -> Option<String> {
    ctx.rt
        .run([
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "sh",
            image,
            "-c",
            "awk -F: '$3==1000{print $6}' /etc/passwd 2>/dev/null",
        ])
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| s.starts_with('/'))
}

pub fn env_image(ctx: &Ctx, cfg: &EnvConfig) -> String {
    cfg.image.clone().unwrap_or_else(|| ctx.image("base"))
}

pub fn ensure_images(ctx: &Ctx, cfg: Option<&EnvConfig>) -> Result<()> {
    let mut all: Vec<String> = ["gate", "vault", "tools"]
        .iter()
        .map(|c| ctx.image(c))
        .collect();
    all.extend(cfg.map(|c| env_image(ctx, c)));
    // One call when everything is there, the common case.
    if ctx.rt.succeeds(
        ["image".to_string(), "inspect".into()]
            .into_iter()
            .chain(all),
    ) {
        return Ok(());
    }
    let mut missing = Vec::new();
    for c in ["gate", "vault", "tools"] {
        let img = ctx.image(c);
        if !ctx.rt.image_exists(&img) {
            missing.push(img);
        }
    }
    if let Some(cfg) = cfg {
        let img = env_image(ctx, cfg);
        if !ctx.rt.image_exists(&img) && ctx.rt.run(["pull", &img]).is_err() {
            missing.push(img);
        }
    }
    if !missing.is_empty() {
        bail!("missing images: {} — run `luoto setup`", missing.join(", "));
    }
    Ok(())
}

pub fn ensure_vault(ctx: &Ctx) -> Result<()> {
    let rt = &ctx.rt;
    rt.create_internal_network(
        names::VAULT_NET,
        names::VAULT_SUBNET,
        names::VAULT_GW,
        None,
        &labels("", "vault"),
    )?;
    rt.create_bridge_network(names::VAULT_OUT_NET, &labels("", "vault"))?;
    let spec = RunSpec {
        name: names::VAULT.into(),
        image: ctx.image("vault"),
        hostname: Some("luoto-vault".into()),
        networks: vec![
            (names::VAULT_NET.into(), Some(names::VAULT_IP)),
            (names::VAULT_OUT_NET.into(), None),
        ],
        env: vec![
            (
                "LUOTO_VAULT_ADDR".into(),
                format!("{}:{}", names::VAULT_IP, luoto_shared::VAULT_PORT),
            ),
            ("LUOTO_CTL_SOCKET".into(), "/run/luoto/ctl.sock".into()),
        ],
        cap_drop_all: true,
        read_only: true,
        tmpfs: vec!["/run/luoto:rw,mode=1777,size=1m".into()],
        ulimits: vec!["core=0".into()],
        restart: Some("on-failure".into()),
        labels: labels("", "vault"),
        ..Default::default()
    };
    start_or_create(ctx, &spec, true)?;
    wait_until(Duration::from_secs(20), || ctl::vault_status(rt).is_ok())
        .context("vault did not come up")?;
    Ok(())
}

/// What `start_or_create` did.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Launch {
    AlreadyRunning,
    Started,
    Created,
}

/// Start a stopped container, (re)create one whose spec changed when `recreate` allows.
fn start_or_create(ctx: &Ctx, spec: &RunSpec, recreate: bool) -> Result<Launch> {
    let rt = &ctx.rt;
    let hash = spec_hash(rt, spec);
    let mut spec = spec.clone();
    spec.labels.push((names::LABEL_SPEC.into(), hash.clone()));
    match rt.container_state_label(&spec.name, names::LABEL_SPEC) {
        None => {
            rt.create_and_start(&spec)?;
            Ok(Launch::Created)
        }
        Some((state, label)) => {
            let same = label == hash;
            if !same && recreate {
                rt.remove_container(&spec.name)?;
                rt.create_and_start(&spec)?;
                return Ok(Launch::Created);
            }
            if !same {
                eprintln!(
                    "note: {} was created from an older config or luoto version; `luoto up --recreate` applies it (volumes are kept)",
                    spec.name
                );
            }
            if state == "running" {
                return Ok(Launch::AlreadyRunning);
            }
            rt.run(["start", &spec.name])?;
            Ok(Launch::Started)
        }
    }
}

fn wait_until(timeout: Duration, mut ok: impl FnMut() -> bool) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(400));
    }
    bail!("timed out after {}s", timeout.as_secs())
}

pub fn static_dev_env(env: &str, gate_ip: Ipv4Addr) -> Vec<(String, String)> {
    let proxy = format!(
        "http://{}:{}",
        luoto_shared::GATE_HOST,
        luoto_shared::PROXY_PORT
    );
    let no_proxy = format!(
        "localhost,127.0.0.1,::1,{},{gate_ip}",
        luoto_shared::GATE_HOST
    );
    let bundle = "/etc/luoto/ca-bundle.pem".to_string();
    let mut v: Vec<(String, String)> = vec![
        ("LUOTO_ENV".into(), env.into()),
        ("LUOTO_GATE_IP".into(), gate_ip.to_string()),
        ("LUOTO_UID".into(), UID.into()),
    ];
    for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        v.push((k.into(), proxy.clone()));
    }
    for k in ["NO_PROXY", "no_proxy"] {
        v.push((k.into(), no_proxy.clone()));
    }
    for k in [
        "SSL_CERT_FILE",
        "NODE_EXTRA_CA_CERTS",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "PIP_CERT",
        "CARGO_HTTP_CAINFO",
        "GIT_SSL_CAINFO",
        "DENO_CERT",
    ] {
        v.push((k.into(), bundle.clone()));
    }
    v.push(("NODE_USE_ENV_PROXY".into(), "1".into()));
    v
}

pub struct Plan {
    pub file: EnvFile,
    pub state: EnvState,
    pub compiled: Compiled,
    pub image: String,
}

/// The env's config as `up` applies it: the user's file with the accepted luoto.toml layered in.
pub fn layered(ctx: &Ctx, env: &str) -> Result<EnvConfig> {
    let mut cfg = EnvFile::load(&ctx.paths, env)?.cfg;
    if let Some((_, p)) = project::accepted(ctx, env) {
        project::layer(&mut cfg, &p);
    }
    Ok(cfg)
}

pub fn plan(ctx: &Ctx, env: &str) -> Result<Plan> {
    let mut file = EnvFile::load(&ctx.paths, env)?;
    file.prune_expired()?;
    // In memory only: the env file on disk stays the user's own.
    if let Some((_, p)) = project::accepted(ctx, env) {
        project::layer(&mut file.cfg, &p);
    }
    let image = env_image(ctx, &file.cfg);
    let state = state_or_init(ctx, env, &image)?;
    let a = names::addrs(state.octet);
    let compiled = compile(env, &file.cfg, a.gate)?;
    for r in compiled
        .vault_refs
        .iter()
        .chain(compiled.sandbox_refs.values())
    {
        secrets::check_ref(r)?;
    }
    Ok(Plan {
        file,
        state,
        compiled,
        image,
    })
}

/// Register the env with the vault and load any secrets it is missing (prompting the user's
/// secret store only for those).
pub fn sync_vault(ctx: &Ctx, env: &str, p: &Plan) -> Result<()> {
    bind_vault(ctx, env, p)?;
    load_secrets(ctx, env, p)
}

/// Register the env's bindings with the vault. With a running gate this comes before
/// `apply_policy`: applying flushes the gate's credential cache, and whatever the gate fetches
/// after that must come from the new bindings, not refill the cache with the old value.
fn bind_vault(ctx: &Ctx, env: &str, p: &Plan) -> Result<()> {
    let token_sha = hex::encode(Sha256::digest(p.state.vault_token.as_bytes()));
    ctl::vault::<bool>(
        &ctx.rt,
        &VaultCtl::Bind {
            env: env.into(),
            token_sha256: token_sha,
            bindings: p.compiled.bindings.clone(),
        },
    )?;
    Ok(())
}

/// Load the env's secrets the vault is missing, prompting the user's secret store only for
/// those.
fn load_secrets(ctx: &Ctx, env: &str, p: &Plan) -> Result<()> {
    let status = ctl::vault_status(&ctx.rt)?;
    let loaded: BTreeSet<&String> = status.loaded_refs.iter().collect();
    let missing: BTreeSet<String> = p
        .compiled
        .vault_refs
        .iter()
        .filter(|r| !loaded.contains(r))
        .cloned()
        .collect();
    if !missing.is_empty() {
        eprintln!(
            "unlocking {} secret(s) for `{env}` from your secret store…",
            missing.len()
        );
        let values = secrets::resolve_all(&ctx.global, &missing)?;
        ctl::vault::<usize>(&ctx.rt, &VaultCtl::Load { secrets: values })?;
    }
    Ok(())
}

pub fn apply_policy(ctx: &Ctx, env: &str, compiled: &Compiled) -> Result<()> {
    ctl::gate::<usize>(
        &ctx.rt,
        env,
        &GateCtl::ApplyPolicy {
            policy: Box::new(compiled.policy.clone()),
        },
    )?;
    Ok(())
}

/// Bring a running env in line with its config without recreating anything: gate policy,
/// vault bindings, and the sandbox's runtime env when what it should hold has changed.
/// Image, port and workspace changes still need `up --recreate`. `None` when the env is down.
pub fn reapply(ctx: &Ctx, env: &str) -> Result<Option<Plan>> {
    let p = plan(ctx, env)?;
    let running = |c: String| ctx.rt.container_state(&c).as_deref() == Some("running");
    if !running(names::gate(env)) || !running(names::dev(env)) {
        return Ok(None);
    }
    // The policy lands even when the vault can't be reached.
    let bound = bind_vault(ctx, env, &p);
    apply_policy(ctx, env, &p.compiled)?;
    bound?;
    load_secrets(ctx, env, &p)?;
    let applied = ctx
        .rt
        .run(["exec", &names::dev(env), "cat", RUNTIME_ENV_SUM])
        .unwrap_or_default();
    if applied.trim() != runtime_env_sum(&p) {
        write_runtime_env(ctx, env, &p)?;
    }
    Ok(Some(p))
}

/// Wipe credentials from the vault and from every running gate's cache. Best effort: one
/// failure must not leave the others holding credentials. Returns what failed.
pub fn lock_all(ctx: &Ctx) -> Result<Vec<String>> {
    let mut failed = Vec::new();
    if let Err(e) = ctl::vault::<bool>(&ctx.rt, &VaultCtl::Lock) {
        failed.push(format!("vault: {e:#}"));
    }
    for e in config::list_envs(&ctx.paths)? {
        if ctx.rt.container_state(&names::gate(&e)).as_deref() == Some("running")
            && let Err(err) = ctl::gate::<bool>(&ctx.rt, &e, &GateCtl::FlushCredentials)
        {
            failed.push(format!(
                "gate of `{e}`: {err:#} (stop it: luoto down -e {e})"
            ));
        }
    }
    Ok(failed)
}

/// Run `f` with `rules` added to the env's policy as grants that expire after `ttl`. They
/// are removed when `f` returns, and expire on their own if luoto dies first.
pub fn with_grants<T>(
    ctx: &Ctx,
    env: &str,
    rules: &[Rule],
    ttl: chrono::TimeDelta,
    note: &str,
    f: impl FnOnce() -> T,
) -> Result<T> {
    if rules.is_empty() {
        return Ok(f());
    }
    let mut file = EnvFile::load(&ctx.paths, env)?;
    let mut ids = Vec::new();
    for r in rules {
        let id = config::new_rule_id();
        file.add_rule(&Rule {
            id: Some(id.clone()),
            expires: Some(Utc::now() + ttl),
            note: Some(note.to_string()),
            ..r.clone()
        })?;
        ids.push(id);
    }
    let push = || -> Result<()> {
        let p = plan(ctx, env)?;
        apply_policy(ctx, env, &p.compiled)
    };
    push()?;
    let out = f();
    let mut file = EnvFile::load(&ctx.paths, env)?;
    for id in &ids {
        file.remove_rules(id)?;
    }
    push()?;
    Ok(out)
}

fn populate_tools(ctx: &Ctx, env: &str, ca_pem: &str) -> Result<()> {
    let vol = names::volume(env, "tools");
    ctx.rt.create_volume(&vol, &labels(env, "tools"))?;
    ctx.rt.run_stdin(
        [
            "run",
            "--rm",
            "-i",
            "--network",
            "none",
            "-v",
            &format!("{vol}:/opt/luoto"),
            &ctx.image("tools"),
            "sh",
            "-c",
            "rm -rf /opt/luoto/* && cp -a /dist/. /opt/luoto/ && mkdir -p /opt/luoto/env && cat > /opt/luoto/env/ca.crt",
        ],
        ca_pem.as_bytes(),
    )?;
    Ok(())
}

pub struct UpOptions {
    pub selftest: bool,
    pub quiet: bool,
}

/// Remove the dev container so the next `up` makes a new one; workspace and home volumes stay.
pub fn remove_dev(ctx: &Ctx, env: &str) -> Result<()> {
    // The VM first: with it stopped there is no container to see, so none would go.
    ensure_vm(ctx)?;
    ctx.rt.remove_container(&names::dev(env))
}

/// On macOS and Windows, podman envs run only in luoto's own VM, started here if needed.
pub fn ensure_vm(ctx: &Ctx) -> Result<()> {
    if ctx.rt.flavor != Flavor::Podman || !machine::supported() {
        return Ok(());
    }
    if !machine::is_luoto(ctx.rt.connection.as_deref()) {
        bail!(
            "luoto runs envs in its own VM, which mounts none of your folders: run `luoto setup`"
        );
    }
    machine::start(&ctx.rt.bin, false)
}

pub fn up(ctx: &Ctx, env: &str, opts: &UpOptions) -> Result<()> {
    ensure_vm(ctx)?;
    let p = plan(ctx, env)?;
    for w in &p.compiled.warnings {
        eprintln!("warning: {w}");
    }
    ensure_images(ctx, Some(&p.file.cfg))?;
    let rt = &ctx.rt;
    let a = names::addrs(p.state.octet);
    let state_dir = ctx.paths.env_state(env);
    let env_ca = ca::ensure(&state_dir, env)?;

    ensure_vault(ctx)?;

    rt.create_internal_network(
        &names::internal_net(env),
        &a.subnet,
        &a.gateway.to_string(),
        Some(&a.gate.to_string()),
        &labels(env, "net"),
    )?;
    rt.create_bridge_network(&names::egress_net(env), &labels(env, "net"))?;
    // The workspace is filled once per volume: the host remembers that it did, but a volume
    // created now (a new VM, a removed volume) starts empty whatever the host remembers.
    let fresh_work = rt.create_volume(&names::volume(env, "work"), &labels(env, "work"))?;
    for v in ["home", "gate"] {
        rt.create_volume(&names::volume(env, v), &labels(env, v))?;
    }
    populate_tools(ctx, env, &env_ca.cert_pem)?;

    let cfg = &p.file.cfg;
    let transparent = cfg.transparent.unwrap_or(true);
    let gate_spec = RunSpec {
        name: names::gate(env),
        image: ctx.image("gate"),
        hostname: Some(format!("{env}-gate")),
        networks: vec![
            (names::internal_net(env), Some(a.gate)),
            (names::egress_net(env), None),
            (names::VAULT_NET.into(), None),
        ],
        env: vec![
            ("LUOTO_ENV".into(), env.into()),
            ("LUOTO_GATE_IP".into(), a.gate.to_string()),
            ("LUOTO_INTERNAL_SUBNET".into(), a.subnet.clone()),
            ("LUOTO_DEV_IP".into(), a.dev.to_string()),
            (
                "LUOTO_TRANSPARENT".into(),
                if transparent { "1" } else { "0" }.into(),
            ),
            ("LUOTO_DNS".into(), "1".into()),
            (
                "LUOTO_FORWARDS".into(),
                cfg.ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        ],
        mounts: vec![(
            names::volume(env, "gate"),
            "/var/lib/luoto-gate".into(),
            false,
        )],
        ports: cfg.ports.iter().map(|p| (*p, *p)).collect(),
        cap_drop_all: true,
        cap_add: ["NET_ADMIN", "NET_BIND_SERVICE", "SETUID", "SETGID", "CHOWN"]
            .into_iter()
            .map(str::to_string)
            .collect(),
        ulimits: vec!["core=0".into()],
        sysctls: vec!["net.ipv4.ip_forward=0".into()],
        restart: Some("on-failure".into()),
        labels: labels(env, "gate"),
        ..Default::default()
    };
    let gate_started = start_or_create(ctx, &gate_spec, true)?;
    wait_until(Duration::from_secs(20), || {
        ctl::gate_status(rt, env).is_ok()
    })
    .with_context(|| {
        format!(
            "gate for `{env}` did not come up (see `{} logs {}`)",
            rt.name(),
            names::gate(env)
        )
    })?;
    let gs = ctl::gate_status(rt, env)?;
    if !gs.ca_installed {
        ctl::gate::<bool>(
            rt,
            env,
            &GateCtl::InstallCa {
                cert_pem: env_ca.cert_pem.clone(),
                key_pem: env_ca.key_pem.clone(),
            },
        )?;
    }
    ctl::gate::<bool>(
        rt,
        env,
        &GateCtl::SetVault {
            url: format!("http://{}:{}", names::VAULT_IP, luoto_shared::VAULT_PORT),
            token: p.state.vault_token.clone(),
        },
    )?;
    let bound = bind_vault(ctx, env, &p);
    apply_policy(ctx, env, &p.compiled)?;
    // Credentials failing to unlock must not block the env: credentialed hosts fail closed
    // ("credentials locked") until `luoto vault unlock` succeeds.
    if let Err(e) = bound.and_then(|()| load_secrets(ctx, env, &p)) {
        eprintln!(
            "warning: credentials not unlocked ({e:#}); credentialed hosts return 403 until `luoto vault unlock`"
        );
    }

    let home = p.state.home.clone().unwrap_or_else(|| "/home/dev".into());
    let dir = workspace::canonical(cfg.workspace.dir.as_deref().with_context(|| {
        format!("env `{env}` has no folder: set `[workspace] dir` (`luoto edit -e {env}`)")
    })?)?;
    let gvisor = cfg.isolation(&ctx.global) == Isolation::Gvisor;
    let runsc = if gvisor {
        Some(ctx.global.gvisor.clone().context(
            "`isolation = \"gvisor\"` needs gVisor: run `luoto setup`, or set `isolation = \"container\"`",
        )?)
    } else {
        cfg.resources.oci_runtime.clone()
    };
    if gvisor && (cfg.resources.memory.is_some() || cfg.resources.cpus.is_some()) {
        eprintln!("warning: memory and CPU limits don't apply to gVisor envs (rootless podman)");
    }
    let dev_spec = RunSpec {
        name: names::dev(env),
        image: p.image.clone(),
        hostname: Some(env.into()),
        networks: vec![(names::internal_net(env), Some(a.dev))],
        dns: vec![a.gate.to_string()],
        add_hosts: vec![(luoto_shared::GATE_HOST.into(), a.gate.to_string())],
        env: static_dev_env(env, a.gate),
        mounts: vec![
            (names::volume(env, "work"), "/workspace".into(), false),
            (names::volume(env, "home"), home.clone(), false),
            (names::volume(env, "tools"), "/opt/luoto".into(), true),
        ],
        tmpfs: vec!["/run/luoto:rw,mode=755,size=4m".into()],
        entrypoint: Some("/opt/luoto/init.sh".into()),
        user: Some("0:0".into()),
        memory: cfg.resources.memory.clone().filter(|_| !gvisor),
        cpus: cfg.resources.cpus.filter(|_| !gvisor),
        oci_runtime: runsc,
        // gVisor rejects SELinux labels: its own sandbox is the confinement.
        security_opts: if gvisor {
            vec!["label=disable".into()]
        } else {
            Vec::new()
        },
        // In luoto's VM each env's dev container has its own ID range, and its root is not
        // the VM user that owns podman (so not the vault's or other envs' owner either).
        id_map: machine::is_luoto(rt.connection.as_deref())
            .then(|| machine::dev_id_start(p.state.octet)),
        // init.sh comes from the tools image and runs only at container start, so a new
        // tools image makes the container's spec stale.
        labels: [
            labels(env, "dev"),
            vec![("luoto.tools".into(), image_id(rt, &ctx.image("tools")))],
        ]
        .concat(),
        ..Default::default()
    };
    let dev_started = start_or_create(ctx, &dev_spec, false)?;
    let created = dev_started == Launch::Created;
    if rt.flavor == Flavor::Docker && transparent {
        rt.run([
            "run",
            "--rm",
            "--network",
            &format!("container:{}", names::dev(env)),
            "--cap-add",
            "NET_ADMIN",
            &ctx.image("tools"),
            "ip",
            "route",
            "replace",
            "default",
            "via",
            &a.gate.to_string(),
        ])?;
    }
    wait_until(Duration::from_secs(90), || {
        rt.succeeds(["exec", &names::dev(env), "test", "-f", "/run/luoto/ready"])
    })
    .with_context(|| {
        format!(
            "dev container did not finish init (see `{} logs {}`)",
            rt.name(),
            names::dev(env)
        )
    })?;
    // Isolation first: secrets, dotfiles and the SSH key enter only a container that passed.
    // Containers that were already running passed when they started.
    let restarted = gate_started != Launch::AlreadyRunning || dev_started != Launch::AlreadyRunning;
    if opts.selftest && restarted {
        let report = selftest(ctx, env, None)?;
        if !report.ok {
            rt.run(["stop", "-t", "2", &names::dev(env)]).ok();
            bail!(
                "isolation self-test FAILED — the dev container was stopped:\n{}\nrun `luoto doctor` for details",
                report.render()
            );
        }
    }
    write_runtime_env(ctx, env, &p)?;
    // The login name is read back from the sandbox and ends up in the ssh_config the user
    // includes, so only a plain POSIX user name is kept.
    let reported = rt
        .run(["exec", &names::dev(env), "cat", "/run/luoto/user"])
        .ok()
        .map(|u| u.trim().to_string());
    let user = reported
        .as_deref()
        .filter(|u| ssh::valid_user(u))
        .map(str::to_string);
    if user.is_none() && reported.is_some_and(|u| !u.is_empty()) {
        eprintln!("warning: the env reported an invalid login name; SSH uses `dev`");
    }
    let mut st = EnvState::load(ctx, env)?.unwrap_or_else(|| p.state.clone());
    if st.user != user {
        st.user = user;
        st.save(ctx, env)?;
    }
    if personal::apply(ctx, env, cfg) > 0 {
        // Home files may have replaced an agent's config, and with it luoto's entry there.
        for a in cfg
            .agents
            .iter()
            .filter_map(|n| luoto_shared::profiles::agent(n))
        {
            if let Err(e) = crate::agents::register(ctx, env, &a) {
                eprintln!("warning: {} not set up for luoto ({e:#})", a.description);
            }
        }
    }
    if let Err(e) = ssh::authorize(ctx, env) {
        eprintln!("warning: SSH access not set up ({e:#})");
    }
    ssh::write_config(ctx)?;

    if fresh_work || !p.state.seeded {
        println!("copying {} into the env…", dir.display());
        let n = workspace::push(ctx, env, &dir)?;
        println!("copied {n} file(s); bring changes back with `luoto pull -e {env}`");
        let mut st = EnvState::load(ctx, env)?.unwrap_or_else(|| p.state.clone());
        st.seeded = true;
        st.save(ctx, env)?;
    }
    if project::review(ctx, env)? == project::Review::Accepted {
        return up(
            ctx,
            env,
            &UpOptions {
                selftest: opts.selftest,
                quiet: opts.quiet,
            },
        );
    }
    if let Err(e) = deps::ensure(ctx, env, cfg) {
        eprintln!(
            "warning: deps not installed: {e:#}\n         \
             see `luoto egress -e {env} --denied --since 30m`; `luoto up -e {env}` retries"
        );
    }

    crate::watch::spawn(ctx);

    if !opts.quiet {
        println!(
            "env `{env}` is up{}",
            if created { " (new dev container)" } else { "" }
        );
        if !cfg.ports.is_empty() {
            let ports: Vec<String> = cfg
                .ports
                .iter()
                .map(|p| format!("http://127.0.0.1:{p}"))
                .collect();
            println!("  ports:  {}", ports.join("  "));
        }
        let editors: Vec<&str> = luoto_shared::profiles::editor_names().collect();
        println!("  shell:   luoto shell -e {env}");
        println!(
            "  editor:  luoto open -e {env}   (or --with {})",
            editors.join("|")
        );
        println!("  egress:  luoto egress -e {env}");
        println!("  web UI:  luoto ui");
    }
    Ok(())
}

/// Agent/placeholder env + sandbox secrets, written to a tmpfs inside the dev container
/// (memory only) and sourced by shells.
pub fn runtime_env(ctx: &Ctx, p: &Plan) -> Result<BTreeMap<String, String>> {
    let mut env = p.compiled.dev_env.clone();
    if !p.compiled.sandbox_refs.is_empty() {
        let refs: BTreeSet<String> = p.compiled.sandbox_refs.values().cloned().collect();
        let values = secrets::resolve_all(&ctx.global, &refs)?;
        for (k, r) in &p.compiled.sandbox_refs {
            if let Some(v) = values.get(r) {
                env.insert(k.clone(), v.clone());
            }
        }
    }
    Ok(env)
}

fn shell_quote(v: &str) -> String {
    format!("'{}'", v.replace('\'', "'\\''"))
}

const RUNTIME_ENV_SUM: &str = "/run/luoto/env.sum";

/// Fingerprint of what the runtime env should hold: variable names, placeholders and secret
/// refs, never resolved values. Kept beside env.sh so `reapply` resolves secrets only when it
/// has to rewrite, and a restarted container (empty tmpfs) never looks current.
fn runtime_env_sum(p: &Plan) -> String {
    let mut h = Sha256::new();
    h.update(format!(
        "{:?}{:?}{:?}{:?}",
        p.compiled.dev_env, p.compiled.sandbox_refs, p.compiled.git_config, p.compiled.known_hosts
    ));
    hex::encode(h.finalize())
}

/// fish's single quotes: only `\\` and `\'` are escapes, and newlines are kept.
fn fish_quote(v: &str) -> String {
    format!("'{}'", v.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn write_runtime_env(ctx: &Ctx, env: &str, p: &Plan) -> Result<()> {
    // Git's remote rewrites and SSH's pinned host keys, which the system configs init.sh
    // writes read from here.
    for (path, text) in [
        ("/run/luoto/gitconfig", &p.compiled.git_config),
        ("/run/luoto/ssh_known_hosts", &p.compiled.known_hosts),
    ] {
        ctx.rt.run_stdin(
            [
                "exec",
                "-i",
                "-u",
                "0",
                &names::dev(env),
                "sh",
                "-c",
                "umask 022; cat > \"$0\"",
                path,
            ],
            text.as_bytes(),
        )?;
    }
    let vars = runtime_env(ctx, p)?;
    let mut script = String::from("# written by luoto (memory only)\n");
    let mut fish = script.clone();
    for (k, v) in &vars {
        if k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            script.push_str(&format!("export {k}={}\n", shell_quote(v)));
            fish.push_str(&format!("set -gx {k} {}\n", fish_quote(v)));
        }
    }
    ctx.rt.run_stdin(
        [
            "exec",
            "-i",
            "-u",
            "0",
            &names::dev(env),
            "sh",
            "-c",
            "umask 022; cat > /run/luoto/env.fish",
        ],
        fish.as_bytes(),
    )?;
    ctx.rt.run_stdin(
        [
            "exec",
            "-i",
            "-u",
            "0",
            &names::dev(env),
            "sh",
            "-c",
            "umask 022; cat > /run/luoto/env.sh && printf %s \"$1\" > \"$2\"",
            "sh",
            &runtime_env_sum(p),
            RUNTIME_ENV_SUM,
        ],
        script.as_bytes(),
    )?;
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SelftestCheck {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SelftestReport {
    pub ok: bool,
    pub checks: Vec<SelftestCheck>,
}

impl SelftestReport {
    pub fn render(&self) -> String {
        self.checks
            .iter()
            .map(|c| {
                format!(
                    "  {} {:<14} {}",
                    if c.ok { "ok  " } else { "FAIL" },
                    c.name,
                    c.detail
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

pub fn selftest(ctx: &Ctx, env: &str, probe: Option<&str>) -> Result<SelftestReport> {
    let mut args: Vec<String> = vec![
        "exec".into(),
        "-u".into(),
        UID.into(),
        names::dev(env),
        "/opt/luoto/bin/sandbox".into(),
        "selftest".into(),
        "--json".into(),
    ];
    if let Some(p) = probe {
        args.push("--probe".into());
        args.push(p.into());
    }
    let out = ctx
        .rt
        .command()
        .args(&args)
        .output()
        .context("run selftest")?;
    let text = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(text.trim()).with_context(|| {
        format!(
            "selftest output: {}{}",
            text.trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        )
    })
}

/// Stop luoto's VM when no dev container runs in it. The VM holds only envs and the vault's
/// secrets in memory, so this gives its memory back; the next `up` starts it and unlocks the
/// vault again. Asked of the VM, not this config: other config dirs (LUOTO_HOME) may have envs
/// there.
pub fn stop_vm_if_unused(ctx: &Ctx) -> Result<bool> {
    if !machine::is_luoto(ctx.rt.connection.as_deref()) {
        return Ok(false);
    }
    let dev = ctx.rt.run([
        "ps",
        "-q",
        "--filter",
        &format!("label={}=dev", names::LABEL_ROLE),
    ])?;
    if !dev.trim().is_empty() {
        return Ok(false);
    }
    machine::stop(&ctx.rt.bin)?;
    Ok(true)
}

pub fn down(ctx: &Ctx, env: &str) -> Result<()> {
    for c in [names::dev(env), names::gate(env)] {
        if ctx.rt.container_state(&c).as_deref() == Some("running")
            && let Err(e) = ctx.rt.run(["stop", "-t", "5", &c])
            // gVisor: podman's network teardown can fail once the container has stopped.
            && ctx.rt.container_state(&c).as_deref() == Some("running")
        {
            return Err(e);
        }
    }
    Ok(())
}

/// Delete the env's containers, networks, volumes, vault binding and state (CA, vault token,
/// accepted luoto.toml), so a new env of the same name starts fresh.
pub fn remove(ctx: &Ctx, env: &str) -> Result<()> {
    for c in [names::dev(env), names::gate(env)] {
        ctx.rt.remove_container(&c)?;
    }
    for n in [names::internal_net(env), names::egress_net(env)] {
        if ctx.rt.network_exists(&n) {
            ctx.rt.run(["network", "rm", &n])?;
        }
    }
    for v in ["tools", "gate", "work", "home"] {
        let name = names::volume(env, v);
        if ctx.rt.volume_exists(&name) {
            ctx.rt.run(["volume", "rm", &name])?;
        }
    }
    if ctx.rt.container_state(names::VAULT).as_deref() == Some("running") {
        let _ = ctl::vault::<bool>(&ctx.rt, &VaultCtl::Unbind { env: env.into() });
    }
    let state = ctx.paths.env_state(env);
    if state.exists() {
        std::fs::remove_dir_all(&state)?;
    }
    Ok(())
}

/// Recompile every env, re-register bindings and load all secrets (after a VM reboot).
pub fn unlock_all(ctx: &Ctx) -> Result<usize> {
    ensure_vault(ctx)?;
    let mut n = 0;
    for env in config::list_envs(&ctx.paths)? {
        if EnvState::load(ctx, &env)?.is_none() {
            continue;
        }
        let p = plan(ctx, &env)?;
        sync_vault(ctx, &env, &p)?;
        n += 1;
    }
    Ok(n)
}

pub fn status_line(ctx: &Ctx, env: &str) -> (String, String) {
    let dev = ctx
        .rt
        .container_state(&names::dev(env))
        .unwrap_or_else(|| "absent".into());
    let gate = ctx
        .rt
        .container_state(&names::gate(env))
        .unwrap_or_else(|| "absent".into());
    (dev, gate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fish_quoting_keeps_multi_line_values_and_quotes() {
        assert_eq!(fish_quote("a'b\\c\nd"), "'a\\'b\\\\c\nd'");
    }
}
