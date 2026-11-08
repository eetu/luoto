//! Env lifecycle: create/start/stop/remove the networks, volumes and containers of an env,
//! and verify isolation from inside before declaring the env ready. `sync` keeps a running
//! env's gate and vault in line with its config; `state` is what the host keeps of it.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use luoto_shared::ctl::GateCtl;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ca::EnvCa;
use crate::compile::{Compiled, compile};
use crate::config::{self, EnvConfig, EnvFile, GlobalConfig, Isolation};
use crate::events::Mutes;
use crate::paths::Paths;
use crate::runtime::{Flavor, RunSpec, Runtime};
use crate::state::{self, EnvState};
use crate::{
    azure, ca, ctl, deps, machine, names, personal, project, repos, secrets, ssh, sync, workspace,
};

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

fn labels(env: &str, role: &str) -> Vec<(String, String)> {
    vec![
        (names::LABEL_ENV.into(), env.into()),
        (names::LABEL_ROLE.into(), role.into()),
        ("luoto.version".into(), luoto_shared::VERSION.into()),
    ]
}

/// Hash of the run arguments plus the image ID, so a rebuilt image under the same tag also
/// counts as a changed spec.
fn spec_hash(rt: &Runtime, spec: &RunSpec, image_id: &str) -> String {
    let args = [
        rt.run_args(spec, false),
        spec.oci_runtime.iter().cloned().collect(),
    ]
    .concat()
    .join("\u{1f}");
    hex::encode(&Sha256::digest(format!("{args}\u{1f}{image_id}").as_bytes())[..8])
}

/// The IDs of `images` from one `image inspect`; `None` unless every one is there.
fn image_ids<const N: usize>(rt: &Runtime, images: &[String; N]) -> Option<[String; N]> {
    let out = rt
        .run(
            ["image", "inspect", "--format", "{{.Id}}"]
                .into_iter()
                .map(String::from)
                .chain(images.iter().cloned()),
        )
        .ok()?;
    let ids: Vec<String> = out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect();
    ids.try_into().ok()
}

pub fn env_image(ctx: &Ctx, cfg: &EnvConfig) -> String {
    cfg.image.clone().unwrap_or_else(|| ctx.image("base"))
}

/// IDs of the images `up` runs, and whether it pulled any.
struct ImageIds {
    gate: String,
    vault: String,
    tools: String,
    dev: String,
    pulled: bool,
}

/// luoto's images and the env's own `dev` image, each pulled (with progress) when missing, as
/// after an upgrade. A local image (`localhost/…`, a source build's) can't be pulled.
fn ensure_images(ctx: &Ctx, dev: &str) -> Result<ImageIds> {
    let all = [
        ctx.image("gate"),
        ctx.image("vault"),
        ctx.image("tools"),
        dev.to_string(),
    ];
    // One call when everything is there, the common case.
    let (ids, pulled) = match image_ids(&ctx.rt, &all) {
        Some(ids) => (ids, false),
        None => {
            for img in all.iter().filter(|img| !ctx.rt.image_exists(img)) {
                if img.starts_with("localhost/") {
                    bail!("missing image {img}: a local image (`luoto setup` builds luoto's own)");
                }
                ctx.rt.pull(img)?;
            }
            let ids = image_ids(&ctx.rt, &all).context("inspect the env's images")?;
            (ids, true)
        }
    };
    let [gate, vault, tools, dev] = ids;
    Ok(ImageIds {
        gate,
        vault,
        tools,
        dev,
        pulled,
    })
}

pub fn ensure_vault(ctx: &Ctx) -> Result<()> {
    let id = image_ids(&ctx.rt, &[ctx.image("vault")]).map_or_else(String::new, |[id]| id);
    start_vault(ctx, &id)
}

/// The vault from its image `image_id`, and its networks.
fn start_vault(ctx: &Ctx, image_id: &str) -> Result<()> {
    let rt = &ctx.rt;
    rt.create_internal_network(
        &names::vault_net(),
        &names::vault_subnet(),
        &names::vault_gw(),
        None,
        &labels("", "vault"),
    )?;
    rt.create_bridge_network(&names::vault_out_net(), &labels("", "vault"))?;
    let spec = RunSpec {
        name: names::vault(),
        image: ctx.image("vault"),
        hostname: Some(names::vault()),
        networks: vec![
            (names::vault_net(), Some(names::vault_ip())),
            (names::vault_out_net(), None),
        ],
        env: vec![
            (
                "LUOTO_VAULT_ADDR".into(),
                format!("{}:{}", names::vault_ip(), luoto_shared::VAULT_PORT),
            ),
            ("LUOTO_CTL_SOCKET".into(), "/run/luoto/ctl.sock".into()),
        ],
        cap_drop_all: true,
        read_only: true,
        tmpfs: vec!["/run/luoto:rw,mode=1777,size=1m".into()],
        ulimits: vec!["core=0".into()],
        restart: Some("on-failure".into()),
        labels: labels("", "vault"),
        log_mb: Some(VAULT_LOG_MB),
        ..Default::default()
    };
    start_or_create(ctx, &spec, image_id, true)?;
    wait_until(Duration::from_secs(20), || ctl::vault_status(rt).ok())
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

/// Start a stopped container, (re)create one whose spec (or image, `image_id`) changed when
/// `recreate` allows.
fn start_or_create(ctx: &Ctx, spec: &RunSpec, image_id: &str, recreate: bool) -> Result<Launch> {
    let rt = &ctx.rt;
    let hash = spec_hash(rt, spec, image_id);
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

/// Poll until `ready` gives a value, and return it.
fn wait_until<T>(timeout: Duration, mut ready: impl FnMut() -> Option<T>) -> Result<T> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Some(v) = ready() {
            return Ok(v);
        }
        std::thread::sleep(Duration::from_millis(400));
    }
    bail!("timed out after {}s", timeout.as_secs())
}

fn static_dev_env(env: &str, gate_ip: Ipv4Addr) -> Vec<(String, String)> {
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
    /// The env's file.
    pub path: PathBuf,
    /// Its config with the accepted luoto.toml layered in.
    pub cfg: EnvConfig,
    /// `None` until the env's first `up`.
    pub state: Option<EnvState>,
    pub compiled: Compiled,
    pub image: String,
}

/// The env's config as `up` applies it: the user's file with the accepted luoto.toml layered
/// in, and config.toml's options for its agents, denies and mutes.
pub fn layered(ctx: &Ctx, env: &str) -> Result<EnvConfig> {
    let mut cfg = EnvFile::load(&ctx.paths, env)?.cfg;
    if let Some((_, p)) = project::accepted(ctx, env) {
        project::layer(&mut cfg, &p);
    }
    cfg.agents.fill_options(&ctx.global.agents);
    ctx.global.layer_under(&mut cfg);
    Ok(cfg)
}

/// What the env's egress views leave out.
pub fn mutes(ctx: &Ctx, env: &str) -> Result<Mutes> {
    let cfg = EnvFile::load(&ctx.paths, env)?.cfg;
    Ok(Mutes::new(&ctx.global.mutes_for(&cfg)))
}

/// What the env's config compiles to, changing nothing: expired grants are left out here (`up`
/// drops them from the file), and an env that was never up has no gate address in its policy.
pub fn plan(ctx: &Ctx, env: &str) -> Result<Plan> {
    let cfg = layered(ctx, env)?;
    let state = EnvState::load(&ctx.paths, env)?;
    let gate = state.as_ref().map(|s| names::addrs(s.octet).gate);
    let compiled = compile(env, &cfg, gate, &azure::aliases(&cfg.workspace))?;
    for r in compiled.vault_refs() {
        secrets::check_vault_ref(&r)?;
    }
    for r in compiled.sandbox_refs.values() {
        secrets::check_ref(r)?;
    }
    Ok(Plan {
        path: ctx.paths.env_config(env),
        image: env_image(ctx, &cfg),
        cfg,
        state,
        compiled,
    })
}

/// Fill the tools volume from the tools image (`tools_id`), with the env's CA, unless it holds
/// them already.
fn populate_tools(
    ctx: &Ctx,
    env: &str,
    state: &EnvState,
    tools_id: &str,
    ca_pem: &str,
) -> Result<()> {
    let vol = names::volume(env, "tools");
    let created = ctx.rt.create_volume(&vol, &labels(env, "tools"))?;
    let stamp = hex::encode(Sha256::digest(format!("{tools_id}\u{1f}{ca_pem}")));
    if !created && state.tools.as_deref() == Some(stamp.as_str()) {
        return Ok(());
    }
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
    EnvState::update(&ctx.paths, env, |s| s.tools = Some(stamp))
}

#[derive(Default)]
pub struct UpOptions {
    /// Skip the isolation self-test after a start.
    pub no_selftest: bool,
    pub quiet: bool,
    /// Install what a remote cloned into the workspace pins without asking (`init --yes`).
    pub accept_installs: bool,
}

/// Remove the dev container so the next `up` makes a new one; workspace and home volumes stay.
pub fn remove_dev(ctx: &Ctx, env: &str) -> Result<()> {
    // The VM first: with it stopped there is no container to see, so none would go.
    ensure_vm(ctx)?;
    ctx.rt.remove_container(&names::dev(env))
}

/// Discard the env's home volume, and the dev container that mounts it (a volume in use can't
/// go); the next `up` makes both anew. Whether there was a home to discard.
pub fn reset_home(ctx: &Ctx, env: &str) -> Result<bool> {
    ensure_vm(ctx)?;
    let vol = names::volume(env, "home");
    if !ctx.rt.volume_exists(&vol) {
        return Ok(false);
    }
    ctx.rt.remove_container(&names::dev(env))?;
    ctx.rt.run(["volume", "rm", &vol])?;
    Ok(true)
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

/// What the env's agents and repos need and its config doesn't say: asked on a terminal,
/// before the gate starts, so it has the answers (`agents::ask_missing`,
/// `repos::ask_missing`).
fn ask_credentials(ctx: &Ctx, env: &str) -> Result<()> {
    let cfg = layered(ctx, env)?;
    crate::agents::ask_missing(ctx, env, &cfg)?;
    repos::ask_missing(ctx, env, &cfg)?;
    Ok(())
}

pub fn up(ctx: &Ctx, env: &str, opts: &UpOptions) -> Result<()> {
    ensure_vm(ctx)?;
    if !opts.quiet {
        crate::disk::warn_if_low(ctx);
    }
    EnvFile::load(&ctx.paths, env)?.prune_expired()?;
    ask_credentials(ctx, env)?;
    let image = env_image(ctx, &layered(ctx, env)?);
    let ids = ensure_images(ctx, &image)?;
    let state = state::ensure(ctx, env, &image)?;
    let mut p = plan(ctx, env)?;
    for w in &p.compiled.warnings {
        eprintln!("warning: {w}");
    }
    let rt = &ctx.rt;
    let a = names::addrs(state.octet);
    let (env_ca, made) = ca::ensure(&ctx.paths.env_state(env), env)?;
    if let ca::Made::Renewed(old) = made {
        eprintln!("{}", ca::renewal_note(old, &env_ca));
    }
    let ca_sha = env_ca.pem_sha256();
    // A renewal counts on its own: `dev_ca` is unset until a start records it.
    let stale_ca = matches!(made, ca::Made::Renewed(_))
        || state.dev_ca.as_deref().is_some_and(|h| h != ca_sha);

    start_vault(ctx, &ids.vault)?;

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
    populate_tools(ctx, env, &state, &ids.tools, &env_ca.cert_pem)?;

    let gate = start_gate(ctx, env, &p, &state, &env_ca, &ids.gate)?;
    let restart = if gate != Launch::AlreadyRunning {
        Restart::Gate
    } else if stale_ca {
        Restart::Ca
    } else {
        Restart::No
    };
    let dev = start_dev(ctx, env, &p, &state, &ids, restart)?;
    if state.dev_ca.as_deref() != Some(ca_sha.as_str()) {
        EnvState::update(&ctx.paths, env, |s| s.dev_ca = Some(ca_sha))?;
    }
    // Containers that were already running passed the self-test when they started.
    let restarted = gate != Launch::AlreadyRunning || dev != Launch::AlreadyRunning;
    after_start(
        ctx,
        env,
        &p,
        &state,
        restarted && !opts.no_selftest,
        opts.quiet,
    )?;

    // Nothing the clone of the env's own remote brings runs, installs or is granted until the
    // user has seen its luoto.toml (`project::review`) and what it would install (below).
    let mut cloned_workspace = false;
    if fresh_work || !state.seeded {
        let ws = &p.cfg.workspace;
        match (&ws.dir, &ws.url) {
            (Some(dir), _) => {
                let dir = workspace::canonical(dir)?;
                println!("copying {} into the env…", dir.display());
                let n = workspace::push(ctx, env, &dir, None)?;
                println!("copied {n} file(s); bring changes back with `luoto pull -e {env}`");
            }
            (None, Some(url)) => {
                let locked = repos::creds_locked(ctx, env);
                if let Err(e) = repos::clone_workspace(ctx, env, url, ws.branch.as_deref(), locked)
                {
                    if repos::undecline(ctx, env, url)? {
                        eprintln!(
                            "note: it was answered as public; `luoto up` asks for its access again"
                        );
                    }
                    return Err(e);
                }
                cloned_workspace = true;
            }
            (None, None) => bail!(
                "env `{env}` has no folder or remote: set `[workspace] dir` or `url` \
                 (`luoto edit -e {env}`)"
            ),
        }
        EnvState::update(&ctx.paths, env, |s| s.seeded = true)?;
    }
    // A new volume holds none of the repos, whatever the host remembers.
    let seeded_repos = if fresh_work {
        Default::default()
    } else {
        state.repos.clone()
    };
    if project::review(ctx, env)? {
        // Its agents and repos may need credentials too.
        ask_credentials(ctx, env)?;
        // The accepted settings reach the gate (policy, credentials, ports) and the runtime env.
        let image = p.image.clone();
        p = plan(ctx, env)?;
        if start_gate(ctx, env, &p, &state, &env_ca, &ids.gate)? != Launch::AlreadyRunning {
            start_dev(ctx, env, &p, &state, &ids, Restart::Gate)?;
            after_start(ctx, env, &p, &state, !opts.no_selftest, opts.quiet)?;
        } else {
            sync::write_runtime_env(ctx, env, &p.compiled)?;
        }
        if p.image != image {
            eprintln!(
                "note: luoto.toml names another image; `luoto up --recreate` applies it (volumes are kept)"
            );
        }
    }
    let repos = repos::seed(ctx, env, &p.cfg.workspace, &seeded_repos);
    let cloned = repos.iter().any(|n| {
        !seeded_repos.contains(n)
            && p.cfg
                .workspace
                .repos
                .get(n)
                .is_some_and(|r| r.url.is_some())
    });
    if repos != state.repos {
        EnvState::update(&ctx.paths, env, |s| s.repos = repos)?;
    }
    // New clones bring files of their own: the presets and toolchains they suggest, offered
    // as `luoto init` offers a folder's.
    let mut install = true;
    if cloned || cloned_workspace {
        match deps::detect_in_env(ctx, env) {
            Ok(found) => {
                let heading = if cloned_workspace {
                    format!("the repository cloned into `{env}` suggests:")
                } else {
                    format!("the repos cloned into `{env}` suggest:")
                };
                if crate::init::offer(ctx, env, &found, &heading, false, true)? {
                    sync::reapply(ctx, env)?;
                    p = plan(ctx, env)?;
                }
                if cloned_workspace {
                    install = ask_installs(ctx, env, &p.cfg, &found, opts.accept_installs);
                }
            }
            Err(e) => {
                eprintln!("warning: the cloned repos weren't read ({e:#})");
                // What the clone pins is unknown: nothing installs without a look at it.
                if cloned_workspace {
                    install = false;
                    println!("nothing installed yet: `luoto up -e {env}` installs it");
                }
            }
        }
    }
    if install {
        if let Err(e) = deps::ensure(ctx, env, &p.cfg, state.home()) {
            eprintln!(
                "warning: deps not installed: {e:#}\n         \
                 see `luoto egress -e {env} --denied --since 30m`; `luoto up -e {env}` retries"
            );
        }
        let agents: Vec<String> = p.cfg.agents.names().cloned().collect();
        if let Err(e) = crate::agents::ensure(ctx, env, &agents, opts.quiet) {
            eprintln!("warning: agents not installed: {e:#}\n         `luoto up -e {env}` retries");
        }
    }
    // After deps: the image or [deps] may be what brings `az`, which then runs in the
    // workspace (a mise shim reads its files), so not before the installs were wanted.
    if install && let Some(c) = &p.cfg.credentials.azure {
        crate::azure_identity::login_in_env(ctx, env, c);
    }

    crate::watch::spawn(ctx);

    if !opts.quiet {
        println!(
            "env `{env}` is up{}",
            if dev == Launch::Created {
                " (new dev container)"
            } else {
                ""
            }
        );
        if !p.cfg.ports.is_empty() {
            let ports: Vec<String> = p
                .cfg
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
        // Now that the gate and vault run on the new images, the old ones are unused.
        if ids.pulled {
            crate::disk::note_superseded(ctx);
        }
    }
    Ok(())
}

/// After the env's own remote is cloned in: what installing would act on (the toolchains the
/// clone pins, which mise installs reading its files, the presets those installs open for a
/// while, the env's agents and `[deps]`), then one question. `accept` is `init --yes`'s answer.
/// Whether to install on this `up`; without one, the next `up` installs.
fn ask_installs(
    ctx: &Ctx,
    env: &str,
    cfg: &EnvConfig,
    found: &crate::detect::Detected,
    accept: bool,
) -> bool {
    let defaults = deps::tools_for(ctx, cfg);
    let pins: Vec<String> = found
        .tools
        .iter()
        .map(|t| crate::text::display(&format!("{} {} ({})", t.tool, t.version, t.source)))
        .chain(
            defaults
                .iter()
                .filter(|(k, _)| !found.tools.iter().any(|t| &t.tool == *k))
                .map(|(k, v)| format!("{k} {} (default)", v.as_str().unwrap_or("?"))),
        )
        .collect();
    let tools = found
        .tools
        .iter()
        .map(|t| t.tool.as_str())
        .chain(defaults.keys().map(String::as_str));
    let presets = deps::install_presets(tools, &cfg.presets);
    println!(
        "\nInstalling reads the clone: mise installs what its files pin, and a mise.toml can run \
         commands in the env."
    );
    println!(
        "  toolchains {}",
        if pins.is_empty() {
            "none pinned".to_string()
        } else {
            pins.join(", ")
        }
    );
    if !presets.is_empty() {
        println!(
            "  presets    {}, opened only while they install",
            presets.join(", ")
        );
    }
    let agents: Vec<&str> = cfg.agents.names().map(String::as_str).collect();
    if !agents.is_empty() {
        println!("  agents     {}", agents.join(", "));
    }
    let d = deps::merged(&ctx.global.deps, &cfg.deps);
    if !d.system.is_empty() || !d.run.is_empty() {
        println!("  [deps]     system packages and setup commands, as the env's config says");
    }
    if accept {
        return true;
    }
    let later = format!("nothing installed yet: `luoto up -e {env}` installs them");
    if !crate::prompt::interactive() {
        println!("{later}");
        return false;
    }
    if crate::prompt::ask("Install them now? [Y/n]", 'y') == 'n' {
        println!("{later}");
        return false;
    }
    true
}

/// The gate's log is the env's event history: over 100 000 events, and a flood of them can't
/// fill the disk.
const GATE_LOG_MB: u32 = 50;
/// The vault logs only an error that stops it: 1 MB holds thousands, and bounds a crash loop.
const VAULT_LOG_MB: u32 = 1;
/// The dev container logs init.sh's few lines a start, and whatever the sandbox (root in its
/// container) writes to the main process's output, which this bounds.
const DEV_LOG_MB: u32 = 10;

fn gate_spec(ctx: &Ctx, env: &str, p: &Plan, a: &names::Addrs) -> RunSpec {
    let cfg = &p.cfg;
    let mut spec = RunSpec {
        name: names::gate(env),
        image: ctx.image("gate"),
        hostname: Some(format!("{env}-gate")),
        networks: vec![
            (names::internal_net(env), Some(a.gate)),
            (names::egress_net(env), None),
            (names::vault_net(), None),
        ],
        env: vec![
            ("LUOTO_ENV".into(), env.into()),
            ("LUOTO_GATE_IP".into(), a.gate.to_string()),
            ("LUOTO_INTERNAL_SUBNET".into(), a.subnet.clone()),
            ("LUOTO_DEV_IP".into(), a.dev.to_string()),
            (
                "LUOTO_TRANSPARENT".into(),
                if cfg.transparent.unwrap_or(true) {
                    "1"
                } else {
                    "0"
                }
                .into(),
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
        log_mb: Some(GATE_LOG_MB),
        ..Default::default()
    };
    // Read at start: a changed CA changes the spec, which recreates the gate.
    if !p.compiled.upstream_cas.is_empty() {
        spec.env.push((
            "LUOTO_UPSTREAM_CAS".into(),
            serde_json::to_string(&p.compiled.upstream_cas).unwrap_or_default(),
        ));
    }
    spec
}

/// Start the gate from its image `image_id` (recreated when its spec changed), give it the
/// env's CA and the vault, then the env's bindings, policy and secrets.
fn start_gate(
    ctx: &Ctx,
    env: &str,
    p: &Plan,
    state: &EnvState,
    env_ca: &EnvCa,
    image_id: &str,
) -> Result<Launch> {
    let rt = &ctx.rt;
    let a = names::addrs(state.octet);
    let launch = start_or_create(ctx, &gate_spec(ctx, env, p, &a), image_id, true)?;
    let gs = wait_until(Duration::from_secs(20), || ctl::gate_status(rt, env).ok())
        .with_context(|| format!("gate for `{env}` did not come up (see `luoto logs -e {env}`)"))?;
    if gs.ca_pem_sha256 != Some(env_ca.pem_sha256()) {
        ctl::gate::<bool>(
            rt,
            env,
            &GateCtl::InstallCa {
                cert_pem: env_ca.cert_pem.clone(),
                key_pem: env_ca.key_pem.clone(),
            },
        )?;
    }
    if !gs.vault_configured {
        ctl::gate::<bool>(
            rt,
            env,
            &GateCtl::SetVault {
                url: format!("http://{}:{}", names::vault_ip(), luoto_shared::VAULT_PORT),
                token: state.vault_token.clone(),
            },
        )?;
    }
    let bound = sync::bind_vault(ctx, env, state, &p.compiled);
    sync::apply_policy(ctx, env, &p.compiled)?;
    // Credentials failing to unlock must not block the env: credentialed hosts fail closed
    // ("credentials locked") until `luoto vault unlock` succeeds.
    if let Err(e) = bound
        .and_then(|()| sync::load_secrets(ctx, &p.compiled.vault_refs(), &format!("`{env}`"), true))
    {
        eprintln!(
            "warning: {e:#}\n         their hosts return 403 until the reference is fixed \
             (`luoto edit -e {env}`) and `luoto vault unlock` loads it"
        );
    }
    Ok(launch)
}

fn dev_spec(ctx: &Ctx, env: &str, p: &Plan, state: &EnvState, tools_id: &str) -> Result<RunSpec> {
    let rt = &ctx.rt;
    let cfg = &p.cfg;
    let a = names::addrs(state.octet);
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
    Ok(RunSpec {
        name: names::dev(env),
        image: p.image.clone(),
        hostname: Some(env.into()),
        networks: vec![(names::internal_net(env), Some(a.dev))],
        dns: vec![a.gate.to_string()],
        add_hosts: vec![(luoto_shared::GATE_HOST.into(), a.gate.to_string())],
        env: static_dev_env(env, a.gate),
        mounts: vec![
            (names::volume(env, "work"), "/workspace".into(), false),
            (names::volume(env, "home"), state.home().into(), false),
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
            .then(|| machine::dev_id_start(state.octet)),
        // init.sh comes from the tools image and runs only at container start, so a new
        // tools image makes the container's spec stale.
        labels: [
            labels(env, "dev"),
            vec![("luoto.tools".into(), tools_id.into())],
        ]
        .concat(),
        log_mb: Some(DEV_LOG_MB),
        ..Default::default()
    })
}

/// Why `start_dev` restarts a dev container that is running.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Restart {
    No,
    /// The gate (re)started: until the dev container restarts, its network stack keeps
    /// reaching for the gate it started with, at the same address, and gets nothing.
    Gate,
    /// It started with an older env CA: init.sh puts the tools volume's in its trust stores
    /// at start.
    Ca,
}

/// Start the dev container and wait for its init.sh.
fn start_dev(
    ctx: &Ctx,
    env: &str,
    p: &Plan,
    state: &EnvState,
    ids: &ImageIds,
    restart: Restart,
) -> Result<Launch> {
    let rt = &ctx.rt;
    let spec = dev_spec(ctx, env, p, state, &ids.tools)?;
    let mut launch = start_or_create(ctx, &spec, &ids.dev, false)?;
    if launch == Launch::AlreadyRunning && restart != Restart::No {
        eprintln!(
            "{} (what runs in it stops)",
            if restart == Restart::Gate {
                "the gate restarted, so the dev container restarts too"
            } else {
                "the dev container restarts to trust the new CA"
            }
        );
        // Not `restart`: podman gives up on it when the network teardown errs, as it does for
        // a gVisor container whose addresses runsc already took over.
        rt.stop(&names::dev(env))?;
        rt.run(["start", &names::dev(env)])?;
        launch = Launch::Started;
    }
    if rt.flavor == Flavor::Docker && p.cfg.transparent.unwrap_or(true) {
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
            &names::addrs(state.octet).gate.to_string(),
        ])?;
    }
    wait_until(Duration::from_secs(90), || {
        rt.succeeds(["exec", &names::dev(env), "test", "-f", "/run/luoto/ready"])
            .then_some(())
    })
    .with_context(|| {
        format!(
            "dev container did not finish init (see `{} logs {}`)",
            rt.name(),
            names::dev(env)
        )
    })?;
    Ok(launch)
}

/// Once both containers run: the self-test when `selftest`, then the runtime env, the login
/// name, home files and SSH access.
fn after_start(
    ctx: &Ctx,
    env: &str,
    p: &Plan,
    state: &EnvState,
    selftest: bool,
    quiet: bool,
) -> Result<()> {
    // Isolation first: secrets, dotfiles and the SSH key enter only a container that passed.
    if selftest {
        check_isolation(ctx, env)?;
    }
    sync::write_runtime_env(ctx, env, &p.compiled)?;
    // The login name is read back from the sandbox and ends up in the ssh_config the user
    // includes, so only a plain POSIX user name is kept.
    let reported = ctx
        .rt
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
    if state.user != user {
        EnvState::update(&ctx.paths, env, |s| s.user = user)?;
    }
    // Home files may have replaced an agent's config, and with it luoto's entries there; an
    // agent with options gets them on every start.
    let copied = personal::apply(ctx, env, &p.cfg, state.home(), quiet) > 0;
    for (name, opts) in &p.cfg.agents.0 {
        let Some(a) = luoto_shared::profiles::agent(name) else {
            continue;
        };
        if (copied || !opts.is_empty())
            && let Err(e) = crate::agents::register(ctx, env, &a, opts)
        {
            eprintln!("warning: {} not set up for luoto ({e:#})", a.description);
        }
    }
    if let Err(e) = ssh::authorize(ctx, env) {
        eprintln!("warning: SSH access not set up ({e:#})");
    }
    ssh::write_config(ctx)?;
    Ok(())
}

/// The isolation self-test; a dev container that fails it is stopped.
fn check_isolation(ctx: &Ctx, env: &str) -> Result<()> {
    let report = selftest(ctx, env, None)?;
    if !report.ok {
        ctx.rt.run(["stop", "-t", "2", &names::dev(env)]).ok();
        bail!(
            "isolation self-test FAILED — the dev container was stopped:\n{}\nrun `luoto doctor` for details",
            report.render()
        );
    }
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
/// vault again. Asked of the VM, not this config: other config dirs (LUOTO_HOME) and the other
/// instance (`names::instance`) may have envs there.
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
        ctx.rt.stop(&c)?;
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
    if ctx.rt.is_running(&names::vault()) {
        let _ = ctl::vault::<bool>(
            &ctx.rt,
            &luoto_shared::ctl::VaultCtl::Unbind { env: env.into() },
        );
    }
    let state = ctx.paths.env_state(env);
    if state.exists() {
        std::fs::remove_dir_all(&state)?;
    }
    Ok(())
}
