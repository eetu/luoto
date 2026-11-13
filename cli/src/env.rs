//! Env lifecycle: create/start/stop/remove the networks, volumes and containers of an env,
//! and verify isolation from inside before declaring the env ready. `sync` keeps a running
//! env's gate and vault in line with its config; `state` is what the host keeps of it.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
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
use crate::runtime::{Flavor, RunSpec, Runtime, exec};
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
    rt.image_ids(images)?.try_into().ok()
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
            for img in &all {
                ensure_image(ctx, img)?;
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

/// `image`, pulled (with progress) when missing. A local image (`localhost/…`, a source
/// build's) can't be pulled.
pub fn ensure_image(ctx: &Ctx, image: &str) -> Result<()> {
    if ctx.rt.image_exists(image) {
        return Ok(());
    }
    if image.starts_with("localhost/") {
        bail!("missing image {image}: a local image (`luoto setup` builds luoto's own)");
    }
    ctx.rt.pull(image)
}

/// Create the env's volume `what` (`work`, `home`, …) unless it exists; true when it was
/// created.
pub fn create_volume(ctx: &Ctx, env: &str, what: &str) -> Result<bool> {
    ctx.rt
        .create_volume(&names::volume(env, what), &labels(env, what))
}

/// Where the user namespace of env `octet`'s dev container starts. In luoto's VM each env's
/// dev container has its own ID range, and its root is not the VM user that owns podman (so
/// not the vault's or other envs' owner either).
pub fn dev_id_map(rt: &Runtime, octet: u8) -> Option<u32> {
    machine::is_luoto(rt.connection.as_deref()).then(|| machine::dev_id_start(octet))
}

pub fn ensure_vault(ctx: &Ctx) -> Result<()> {
    crate::progress::wait("starting the vault", || {
        let id = image_ids(&ctx.rt, &[ctx.image("vault")]).map_or_else(String::new, |[id]| id);
        start_vault(ctx, &id)
    })
}

/// Where the vault serves gates: its socket volume on podman and Docker, a folder of its
/// image (owned by its user) on Apple, where it publishes one socket from there.
const VAULT_SOCKETS: &str = "/run/luoto-vault";
const APPLE_VAULT_SOCKET: &str = "/run/luoto-vault/vault.sock";

/// The vault from its image `image_id`, its egress network and its socket volume.
fn start_vault(ctx: &Ctx, image_id: &str) -> Result<()> {
    let rt = &ctx.rt;
    rt.create_bridge_network(&names::vault_out_net(), &labels("", "vault"))?;
    let apple = rt.flavor == Flavor::Apple;
    let mut spec = RunSpec {
        name: names::vault(),
        image: ctx.image("vault"),
        hostname: Some(names::vault()),
        networks: vec![(names::vault_out_net(), None)],
        env: vec![
            ("LUOTO_CTL_SOCKET".into(), "/run/luoto/ctl.sock".into()),
            ("LUOTO_VAULT_SOCKETS".into(), VAULT_SOCKETS.into()),
        ],
        mounts: vec![(names::vault_sockets(), VAULT_SOCKETS.into(), false)],
        cap_drop_all: true,
        read_only: true,
        tmpfs: vec!["/run/luoto:rw,mode=1777,size=1m".into()],
        ulimits: vec!["core=0".into()],
        restart: Some("on-failure".into()),
        labels: labels("", "vault"),
        log_mb: Some(VAULT_LOG_MB),
        ..Default::default()
    };
    if apple {
        // A volume there is attached to one running container, and a socket on a tmpfs or a
        // read-only root is not published: the vault's own folder holds the one socket.
        let host = vault_socket(ctx);
        #[cfg(unix)]
        if let Some(dir) = host.parent() {
            own_dir(dir)?;
        }
        spec.env = vec![
            ("LUOTO_CTL_SOCKET".into(), "/run/luoto/ctl.sock".into()),
            ("LUOTO_VAULT_SOCKET".into(), APPLE_VAULT_SOCKET.into()),
        ];
        spec.mounts.clear();
        spec.read_only = false;
        spec.published_sockets = vec![(host.display().to_string(), APPLE_VAULT_SOCKET.into())];
        spec.memory = Some(APPLE_SMALL_MEMORY.into());
    } else {
        rt.create_volume(&names::vault_sockets(), &labels("", "vault"))?;
    }
    if start_or_create(ctx, &spec, image_id, None)? == Launch::Created {
        remove_old_vault_net(ctx);
    }
    wait_until(Duration::from_secs(20), || ctl::vault_status(rt).ok())
        .context("vault did not come up")?;
    Ok(())
}

/// The network every gate shared with the vault before luoto 0.4.4, once the vault and the
/// gates were made anew without it. Until the last of them is, removing it fails.
fn remove_old_vault_net(ctx: &Ctx) {
    let net = names::old_vault_net();
    if ctx.rt.network_exists(&net) {
        let _ = ctx.rt.run(["network", "rm", &net]);
    }
}

/// Memory of the gate and vault VMs on Apple (its default is 1 GB a container).
const APPLE_SMALL_MEMORY: &str = "512M";
/// The dev VM's memory on Apple when the env sets none.
const APPLE_DEV_MEMORY: &str = "8G";

/// What `start_or_create` did.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Launch {
    AlreadyRunning,
    Started,
    Created,
}

/// Start a stopped container, (re)create one whose spec (or image, `image_id`) changed, unless
/// it is env `keep`'s dev container, which `luoto up --recreate` recreates.
fn start_or_create(
    ctx: &Ctx,
    spec: &RunSpec,
    image_id: &str,
    keep: Option<&str>,
) -> Result<Launch> {
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
            if !same && keep.is_none() {
                rt.remove_container(&spec.name)?;
                rt.create_and_start(&spec)?;
                return Ok(Launch::Created);
            }
            if let Some(env) = keep.filter(|_| !same) {
                crate::progress::note(&format!(
                    "{} was created from an older config or luoto version; \
                     `luoto up -e {env} --recreate` applies it (volumes are kept)",
                    spec.name
                ));
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
    for k in luoto_shared::PROXY_VARS {
        v.push((k.into(), proxy.clone()));
    }
    for k in luoto_shared::NO_PROXY_VARS {
        v.push((k.into(), no_proxy.clone()));
    }
    for k in luoto_shared::CA_VARS {
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
    let mount = if ctx.rt.flavor == Flavor::Apple {
        // A volume is attached to one running container at a time there: the dev container
        // stops while the volume fills, and `up` starts it again.
        ctx.rt.stop(&names::dev(env))?;
        [
            "--mount".to_string(),
            format!("type=volume,source={vol},target=/opt/luoto"),
        ]
    } else {
        ["-v".to_string(), format!("{vol}:/opt/luoto")]
    };
    ctx.rt.run_stdin(
        [
            "run",
            "--rm",
            "-i",
            "--network",
            "none",
            &mount[0],
            &mount[1],
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
    /// Leave out the closing block (`env … is up` and the commands for it): the env was
    /// running, and the command is about something in it.
    pub brief: bool,
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
    let _waiting = crate::progress::waiting("discarding the home");
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
    if ctx.rt.flavor == Flavor::Apple {
        return machine::ensure_apple_service(&ctx.rt);
    }
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

/// What the env's agents, repos and project need and its config doesn't say: asked on a
/// terminal, before the gate starts, so it has the answers (`agents::ask_missing`,
/// `repos::ask_missing`, `needs::ask`).
fn ask_credentials(ctx: &Ctx, env: &str) -> Result<()> {
    let cfg = layered(ctx, env)?;
    crate::agents::ask_missing(ctx, env, &cfg)?;
    repos::ask_missing(ctx, env, &cfg)?;
    crate::needs::ask(ctx, env, crate::wizard::Mode::Missing)?;
    Ok(())
}

pub fn up(ctx: &Ctx, env: &str, opts: &UpOptions) -> Result<()> {
    crate::azure_identity::forget_login_needed();
    ensure_vm(ctx)?;
    if !opts.quiet {
        crate::disk::warn_if_low(ctx);
    }
    EnvFile::load(&ctx.paths, env)?.prune_expired()?;
    ask_credentials(ctx, env)?;
    let image = env_image(ctx, &layered(ctx, env)?);
    let ids = ensure_images(ctx, &image)?;
    let state = state::ensure(ctx, env, &image)?;
    // Its warnings are about choices the user made: `edit` and `status` show them.
    let mut p = plan(ctx, env)?;
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

    // Quick when the env runs, so it says nothing then.
    let starting = crate::progress::waiting(&format!("starting `{env}`"));
    crate::progress::wait("starting the vault", || start_vault(ctx, &ids.vault))?;

    // On Apple the dev container's only link is the tun device to its gate: no env network.
    let apple = rt.flavor == Flavor::Apple;
    if !apple
        && !rt.network_exists(&names::internal_net(env))
        && let Some((holder, _)) = rt
            .subnets()
            .unwrap_or_default()
            .into_iter()
            .find(|(_, s)| *s == a.subnet)
    {
        let me = names::instance();
        bail!(
            "network `{holder}` already uses this env's subnet {}: `{me} export -e {env}`, \
             `{me} rm -e {env}` and `{me} import {env}.luoto.tar` move the env to a free one",
            a.subnet
        );
    }
    if !apple {
        rt.create_internal_network(
            &names::internal_net(env),
            &a.subnet,
            &a.gateway.to_string(),
            Some(&a.gate.to_string()),
            &labels(env, "net"),
        )?;
    }
    rt.create_bridge_network(&names::egress_net(env), &labels(env, "net"))?;
    // The workspace is filled once per volume: the host remembers that it did, but a volume
    // created now (a new VM, a removed volume) starts empty whatever the host remembers.
    let fresh_work = create_volume(ctx, env, "work")?;
    for v in ["home", "gate"] {
        create_volume(ctx, env, v)?;
    }
    crate::progress::wait("copying luoto's tools into the env", || {
        populate_tools(ctx, env, &state, &ids.tools, &env_ca.cert_pem)
    })?;

    let gate = start_gate(ctx, env, &p, &state, &env_ca, &ids.gate)?;
    // On Apple the dev container keeps its tun device when the gate restarts: the host link
    // joins it to the new gate.
    let restart = if gate != Launch::AlreadyRunning && !apple {
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
    drop(starting);

    // Nothing the clone of the env's own remote brings runs, installs or is granted until the
    // user has seen its luoto.toml (`project::review`) and what it would install (below).
    let mut cloned_workspace = false;
    let ws = &p.cfg.workspace;
    // A remote whose access was left for later: its clone would only fail.
    let waits = |ws: &crate::config::Workspace| {
        ws.dir.is_none() && ws.url.as_deref().is_some_and(|u| repos::waits(env, u))
    };
    if (fresh_work || !state.seeded) && !waits(ws) {
        match (&ws.dir, &ws.url) {
            (Some(dir), _) => {
                let dir = workspace::canonical(dir)?;
                let n = crate::progress::step(
                    &format!("copying {} into the env", dir.display()),
                    || workspace::push(ctx, env, &dir, None),
                )?;
                println!("copied {n} file(s); bring changes back with `luoto pull -e {env}`");
            }
            (None, Some(url)) => {
                let locked = repos::creds_locked(ctx, env);
                if let Err(e) =
                    repos::clone_workspace(ctx, env, url, ws.branch.as_deref(), locked, &p.cfg)
                {
                    if repos::undecline(ctx, env, url)? {
                        crate::progress::note(&format!(
                            "it was answered as public; `luoto up -e {env}` asks for its access \
                             again"
                        ));
                    }
                    return Err(e);
                }
                cloned_workspace = true;
            }
            (None, None) => {
                bail!("env `{env}` has no folder or remote (`[workspace] dir` or `url`)")
            }
        }
        // The install question outlives this `up`: one cut short, or unable to ask, leaves it
        // for the next.
        EnvState::update(&ctx.paths, env, |s| filled(s, cloned_workspace))?;
    }
    let installs_pending = cloned_workspace || state.installs_pending;
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
        let _restarting = crate::progress::waiting(&format!("starting `{env}` with them"));
        if start_gate(ctx, env, &p, &state, &env_ca, &ids.gate)? != Launch::AlreadyRunning {
            let restart = if apple { Restart::No } else { Restart::Gate };
            start_dev(ctx, env, &p, &state, &ids, restart)?;
            after_start(ctx, env, &p, &state, !opts.no_selftest, opts.quiet)?;
        } else {
            sync::write_runtime_env(ctx, env, &p.compiled)?;
        }
        drop(_restarting);
        if p.image != image {
            crate::progress::note(&format!(
                "luoto.toml names another image; `luoto up -e {env} --recreate` applies it \
                 (volumes are kept)"
            ));
        }
    }
    let seeded = repos::seed(ctx, env, &p.cfg, &seeded_repos);
    let repos = seeded.done.clone();
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
    // Shared folders: what changed in them since the last sync is cloned in again.
    for s in crate::shares::sync(ctx, env, &p.cfg, None) {
        if s.worth_saying() {
            crate::progress::say(|| println!("{}", s.said()));
        }
    }
    if let Some(cmd) = crate::shares::needs(ctx, env, &p.cfg) {
        crate::progress::say(|| println!("the env can't read its shares yet: `{cmd}`"));
    }
    // New clones bring files of their own: the presets and toolchains they suggest, offered
    // as `luoto init` offers a folder's.
    let mut install = true;
    if cloned || installs_pending {
        match deps::detect_in_env(ctx, env) {
            Ok(found) => {
                let heading = if installs_pending {
                    format!("the repository cloned into `{env}` suggests:")
                } else {
                    format!("the repos cloned into `{env}` suggest:")
                };
                if crate::init::offer(ctx, env, &found, &heading, false, true)? {
                    sync::reapply(ctx, env)?;
                    p = plan(ctx, env)?;
                }
                if installs_pending {
                    install = ask_installs(ctx, env, &p.cfg, &found, opts.accept_installs);
                    if install {
                        EnvState::update(&ctx.paths, env, |s| s.installs_pending = false)?;
                    }
                }
            }
            Err(e) => {
                crate::progress::warn(&format!("the cloned repos weren't read ({e:#})"));
                // What the clone pins is unknown: nothing installs without a look at it.
                if installs_pending {
                    install = false;
                    println!("nothing installed yet: `luoto up -e {env}` asks again");
                }
            }
        }
    }
    if install {
        if let Err(e) = deps::ensure(ctx, env, &p.cfg, state.home()) {
            crate::progress::warn(&format!(
                "deps not installed ({e:#}); {}; `luoto up -e {env}` retries",
                crate::logs::InstallLog::hint(env)
            ));
        }
        let agents: Vec<String> = p.cfg.agents.names().cloned().collect();
        if let Err(e) = crate::agents::ensure(ctx, env, &agents, opts.quiet) {
            crate::progress::warn(&format!(
                "agents not installed ({e:#}); `luoto up -e {env}` retries"
            ));
        }
    }
    // After deps: the image or [deps] may be what brings `az`, which then runs in the
    // workspace (a mise shim reads its files), so not before the installs were wanted.
    if install && let Some(c) = &p.cfg.credentials.azure {
        crate::azure_identity::login_in_env(ctx, env, c);
    }

    crate::watch::spawn(ctx);

    let open = p
        .compiled
        .policy
        .open_at(chrono::Utc::now())
        .map(|o| o.until);
    if let Some(until) = open
        && (opts.quiet || opts.brief)
    {
        let width = crate::text::columns().saturating_sub(10);
        eprintln!(
            "egress of `{env}` is {}",
            crate::egress::state_line(env, until, width)
        );
    }
    if opts.quiet || opts.brief {
        seeded.warn();
    } else {
        println!(
            "env `{env}` is up{}{}",
            if dev == Launch::Created {
                " (new dev container)"
            } else {
                ""
            },
            match seeded.failed.len() {
                0 => String::new(),
                1 => ", but a repo isn't there:".to_string(),
                n => format!(", but {n} repos aren't there:"),
            }
        );
        // Last, where they are read: a repo that failed mid-output is easy to miss.
        let width = crate::text::columns();
        for f in &seeded.failed {
            for (i, l) in f.lines().enumerate() {
                // Under its first line, hanging: the repo's name stands out.
                let text = crate::text::wrap(l.trim_start(), "    ", width);
                println!("{}", if i == 0 { &text[2..] } else { &text });
            }
        }
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
        if let Some(until) = open {
            let width = crate::text::columns().saturating_sub(11);
            println!(
                "           {}",
                crate::egress::state_line(env, until, width)
            );
        }
        println!("  web UI:  luoto ui");
        // Now that the gate and vault run on the new images, the old ones are unused.
        if ids.pulled {
            crate::disk::note_superseded(ctx);
        }
        crate::disk::hint_growth(ctx, env);
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
    if !crate::prompt::interactive() {
        println!(
            "nothing installed: installing waits for a yes, which `luoto up -e {env}` asks for \
             on a terminal"
        );
        return false;
    }
    if crate::prompt::ask("Install them now? [Y/n]", 'y') == 'n' {
        println!("nothing installed yet: `luoto up -e {env}` asks again");
        return false;
    }
    true
}

/// The state once the workspace is filled: a clone of the env's own remote also opens the
/// install question, which only a yes closes.
fn filled(s: &mut EnvState, cloned: bool) {
    s.seeded = true;
    s.installs_pending |= cloned;
}

/// The gate's log is the env's event history: over 100 000 events, and a flood of them can't
/// fill the disk. On Apple it caps the event file and the one before it.
const GATE_LOG_MB: u32 = 50;
/// The vault logs only an error that stops it: 1 MB holds thousands, and bounds a crash loop.
const VAULT_LOG_MB: u32 = 1;
/// The dev container logs init.sh's few lines a start, and whatever the sandbox (root in its
/// container) writes to the main process's output, which this bounds.
const DEV_LOG_MB: u32 = 10;

/// On Apple every env's link has the same two ends: the gate and the dev container meet only
/// over their tun device.
pub const APPLE_GATE_IP: &str = "169.254.1.1";
pub const APPLE_DEV_IP: &str = "169.254.1.2";
/// Where the gate listens for its end of the tun link, published to the host.
const APPLE_GATE_SOCKET: &str = "/run/luoto-gate-net/net.sock";
/// Where the gate takes the links to the vault the watcher opens, published to the host.
const APPLE_GATE_UPLINK: &str = "/run/luoto-gate-net/vault.sock";
/// The gate's event file on Apple, in its state volume.
const APPLE_GATE_EVENTS: &str = "/var/lib/luoto-gate/events.jsonl";
/// Where the dev container's `sandbox` listens for its end.
const APPLE_DEV_SOCKET: &str = "/run/luoto-net/net.sock";
/// The longest path a unix socket address holds on macOS.
const SUN_PATH_MAX: usize = 104;

/// `dir`, or when a socket in it is too long an address, a short folder of its own in the temp
/// dir.
fn socket_dir(dir: PathBuf) -> PathBuf {
    if dir.join("vault.sock").as_os_str().len() < SUN_PATH_MAX {
        return dir;
    }
    let tag = hex::encode(&Sha256::digest(dir.as_os_str().as_encoded_bytes())[..6]);
    std::env::temp_dir().join(format!("luoto-{tag}"))
}

/// The host ends of an env's links on Apple, in its state folder (`socket_dir`).
pub struct LinkSockets {
    /// The dev container's end of the tun link.
    pub dev: PathBuf,
    /// The gate's end of the tun link.
    pub gate: PathBuf,
    /// Where the watcher opens the gate's links to the vault (`gate/src/uplink.rs`).
    pub uplink: PathBuf,
}

pub fn link_sockets(ctx: &Ctx, env: &str) -> LinkSockets {
    let dir = socket_dir(ctx.paths.env_state(env));
    LinkSockets {
        dev: dir.join("dev.sock"),
        gate: dir.join("gate.sock"),
        uplink: dir.join("vault.sock"),
    }
}

/// The vault's socket on Apple, published to the host: a connection names its env in its
/// first line, then speaks for that env. The instance's, as the vault is, whichever config dir
/// (`LUOTO_HOME`) started it.
pub fn vault_socket(ctx: &Ctx) -> PathBuf {
    let data = Paths::of(names::instance()).map_or_else(|_| ctx.paths.data.clone(), |p| p.data);
    socket_dir(data.join("vault")).join("vault.sock")
}

/// Create `dir` for an env's link sockets, only this user's: a folder someone else made or can
/// enter (a shared temp dir) is refused, so nobody else's socket stands in for the gate.
#[cfg(unix)]
fn own_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let made = std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir);
    made.with_context(|| format!("create {}", dir.display()))?;
    let m = std::fs::symlink_metadata(dir).with_context(|| format!("read {}", dir.display()))?;
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    if !m.is_dir() || m.uid() != uid {
        bail!(
            "{} isn't a folder of yours; remove it and run `luoto up` again",
            dir.display()
        );
    }
    if m.permissions().mode() & 0o077 != 0 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restrict {}", dir.display()))?;
    }
    Ok(())
}

fn set_env(env: &mut Vec<(String, String)>, key: &str, value: &str) {
    env.retain(|(k, _)| k != key);
    env.push((key.into(), value.into()));
}

fn gate_spec(ctx: &Ctx, env: &str, p: &Plan, a: &names::Addrs) -> RunSpec {
    let cfg = &p.cfg;
    let mut spec = RunSpec {
        name: names::gate(env),
        image: ctx.image("gate"),
        hostname: Some(format!("{env}-gate")),
        networks: vec![
            (names::internal_net(env), Some(a.gate)),
            (names::egress_net(env), None),
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
    let vault_dir = Path::new(luoto_shared::VAULT_SOCKET)
        .parent()
        .map_or_else(String::new, |d| d.display().to_string());
    if ctx.rt.flavor == Flavor::Apple {
        let socks = link_sockets(ctx, env);
        spec.networks = vec![(names::egress_net(env), None)];
        set_env(&mut spec.env, "LUOTO_GATE_IP", APPLE_GATE_IP);
        set_env(
            &mut spec.env,
            "LUOTO_INTERNAL_SUBNET",
            &format!("{APPLE_DEV_IP}/32"),
        );
        set_env(&mut spec.env, "LUOTO_DEV_IP", APPLE_DEV_IP);
        set_env(&mut spec.env, "LUOTO_TUN_SOCKET", APPLE_GATE_SOCKET);
        // Apple keeps a container's output uncapped and only until it starts again: events go
        // to a capped file in the gate's volume, read by `luoto-gate events`.
        set_env(&mut spec.env, "LUOTO_EVENTS_FILE", APPLE_GATE_EVENTS);
        set_env(&mut spec.env, "LUOTO_EVENTS_MB", &GATE_LOG_MB.to_string());
        set_env(&mut spec.env, "LUOTO_VAULT_UPLINK", APPLE_GATE_UPLINK);
        spec.published_sockets = vec![
            (socks.gate.display().to_string(), APPLE_GATE_SOCKET.into()),
            (socks.uplink.display().to_string(), APPLE_GATE_UPLINK.into()),
        ];
        spec.memory = Some(APPLE_SMALL_MEMORY.into());
    } else if ctx.rt.mounts_folders() {
        // Only the env's own folder of the vault's sockets.
        spec.folder_mounts = vec![(names::vault_sockets(), env.into(), vault_dir)];
    } else {
        // Docker before 26 mounts whole volumes: the gate sees every env's socket, and the
        // vault's check that a token is its socket's env is all that keeps them apart.
        spec.mounts
            .push((names::vault_sockets(), "/run/luoto/vaults".into(), true));
        spec.env.push((
            "LUOTO_VAULT_SOCKET".into(),
            format!("/run/luoto/vaults/{env}/vault.sock"),
        ));
    }
    // A model server on this machine is `host.docker.internal`, which Docker Engine on Linux
    // knows only when told (podman's hosts file and Docker Desktop have it).
    if ctx.rt.flavor == Flavor::Docker {
        spec.add_hosts
            .push((crate::model_servers::HOST.into(), "host-gateway".into()));
    }
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
    let _waiting = crate::progress::waiting("starting the gate");
    let rt = &ctx.rt;
    let a = names::addrs(state.octet);
    #[cfg(unix)]
    if rt.flavor == Flavor::Apple
        && let Some(dir) = link_sockets(ctx, env).gate.parent()
    {
        own_dir(dir)?;
    }
    // The vault makes the env's folder of sockets, which the gate mounts, as it binds the env.
    // With a running gate this comes before `apply_policy` (`sync::bind_vault`).
    sync::bind_vault(ctx, env, state, &p.compiled)?;
    let launch = start_or_create(ctx, &gate_spec(ctx, env, p, &a), image_id, None)?;
    if launch == Launch::Created {
        remove_old_vault_net(ctx);
    }
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
                token: state.vault_token.clone(),
            },
        )?;
    }
    sync::apply_policy(ctx, env, &p.compiled)?;
    // Credentials failing to unlock must not block the env: credentialed hosts fail closed
    // ("credentials locked") until `luoto vault unlock` succeeds.
    if let Err(e) = sync::load_secrets(ctx, &p.compiled.vault_refs(), &format!("`{env}`"), true) {
        crate::progress::warn(&format!(
            "{e:#}; their hosts return 403 until then, and once it is fixed `luoto up -e {env}` \
             loads them"
        ));
    }
    Ok(launch)
}

fn dev_spec(ctx: &Ctx, env: &str, p: &Plan, state: &EnvState, tools_id: &str) -> Result<RunSpec> {
    let rt = &ctx.rt;
    let cfg = &p.cfg;
    // What every runtime's dev container has: its volumes, its shares (read-only at /shares;
    // shares added later appear without a restart) and init.sh as root.
    let base = RunSpec {
        name: names::dev(env),
        image: p.image.clone(),
        mounts: vec![
            (names::volume(env, "work"), "/workspace".into(), false),
            (names::volume(env, "home"), state.home().into(), false),
            (names::volume(env, "tools"), "/opt/luoto".into(), true),
        ],
        binds: crate::shares::mount_source(ctx, env, cfg)?
            .into_iter()
            .map(|src| (src, crate::shares::IN_ENV.to_string()))
            .collect(),
        tmpfs: vec!["/run/luoto:rw,mode=755,size=4m".into()],
        entrypoint: Some("/opt/luoto/init.sh".into()),
        user: Some("0:0".into()),
        // init.sh comes from the tools image and runs only at container start, so a new
        // tools image makes the container's spec stale.
        labels: [
            labels(env, "dev"),
            vec![("luoto.tools".into(), tools_id.into())],
        ]
        .concat(),
        ..Default::default()
    };
    if rt.flavor == Flavor::Apple {
        return Ok(apple_dev_spec(ctx, env, cfg, base));
    }
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
        crate::progress::warn("memory and CPU limits don't apply to gVisor envs (rootless podman)");
    }
    Ok(RunSpec {
        hostname: Some(env.into()),
        networks: vec![(names::internal_net(env), Some(a.dev))],
        dns: vec![a.gate.to_string()],
        add_hosts: vec![(luoto_shared::GATE_HOST.into(), a.gate.to_string())],
        env: static_dev_env(env, a.gate),
        memory: cfg.resources.memory.clone().filter(|_| !gvisor),
        cpus: cfg.resources.cpus.filter(|_| !gvisor),
        oci_runtime: runsc,
        // gVisor rejects SELinux labels: its own sandbox is the confinement.
        security_opts: if gvisor {
            vec!["label=disable".into()]
        } else {
            Vec::new()
        },
        id_map: dev_id_map(rt, state.octet),
        log_mb: Some(DEV_LOG_MB),
        ..base
    })
}

/// The dev container on Apple: a VM of its own, which is the isolation `isolation = "gvisor"`
/// asks for, so the setting (and an OCI runtime) has nothing to choose there. No network: its
/// only link is the tun device `sandbox` makes on the published socket.
fn apple_dev_spec(ctx: &Ctx, env: &str, cfg: &EnvConfig, base: RunSpec) -> RunSpec {
    let dev_sock = link_sockets(ctx, env).dev;
    let gate_ip: Ipv4Addr = APPLE_GATE_IP.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
    let mut env_vars = static_dev_env(env, gate_ip);
    env_vars.push(("LUOTO_NET".into(), "tun".into()));
    env_vars.push(("LUOTO_DEV_IP".into(), APPLE_DEV_IP.into()));
    // Apple keeps the container's output uncapped: init.sh closes it once ready.
    env_vars.push(("LUOTO_OUTPUT".into(), "startup".into()));
    RunSpec {
        networks: vec![("none".into(), None)],
        dns: vec![APPLE_GATE_IP.into()],
        env: env_vars,
        published_sockets: vec![(dev_sock.display().to_string(), APPLE_DEV_SOCKET.into())],
        // The VM's console is logged uncapped on the host: the kernel writes to it only what
        // stops it, and keeps no audit trail (with none, sudo stays quiet without AUDIT_WRITE).
        kernel_args: vec!["loglevel=1".into(), "audit=0".into()],
        // Podman's default set, without MKNOD (init.sh removes the VM's console nodes) and with
        // NET_ADMIN for the tun device.
        cap_drop_all: true,
        cap_add: [
            "CHOWN",
            "DAC_OVERRIDE",
            "FOWNER",
            "FSETID",
            "KILL",
            "NET_BIND_SERVICE",
            "SETFCAP",
            "SETGID",
            "SETPCAP",
            "SETUID",
            "SYS_CHROOT",
            "NET_ADMIN",
        ]
        .map(String::from)
        .to_vec(),
        memory: Some(
            cfg.resources
                .memory
                .clone()
                .unwrap_or_else(|| APPLE_DEV_MEMORY.into()),
        ),
        cpus: cfg.resources.cpus,
        ..base
    }
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
    let _waiting = crate::progress::waiting("starting the dev container");
    let rt = &ctx.rt;
    let spec = dev_spec(ctx, env, p, state, &ids.tools)?;
    let mut launch = start_or_create(ctx, &spec, &ids.dev, Some(env))?;
    // On Apple the watcher joins the dev container's tun link to the gate: init.sh needs it
    // before it can finish.
    if rt.flavor == Flavor::Apple {
        crate::watch::spawn(ctx);
    }
    if launch == Launch::AlreadyRunning && restart != Restart::No {
        crate::progress::say(|| {
            eprintln!(
                "{} (what runs in it stops)",
                if restart == Restart::Gate {
                    "the gate restarted, so the dev container restarts too"
                } else {
                    "the dev container restarts to trust the new CA"
                }
            )
        });
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
        rt.succeeds(exec(&names::dev(env)).argv(["test", "-f", "/run/luoto/ready"]))
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
        crate::progress::wait("checking the env's isolation", || check_isolation(ctx, env))?;
    }
    let _waiting = crate::progress::waiting("setting up the env");
    sync::write_runtime_env(ctx, env, &p.compiled)?;
    // The login name is read back from the sandbox and ends up in the ssh_config the user
    // includes, so only a plain POSIX user name is kept.
    let reported = ctx
        .rt
        .run(exec(&names::dev(env)).argv(["cat", "/run/luoto/user"]))
        .ok()
        .map(|u| u.trim().to_string());
    let user = reported
        .as_deref()
        .filter(|u| ssh::valid_user(u))
        .map(str::to_string);
    if user.is_none() && reported.is_some_and(|u| !u.is_empty()) {
        crate::progress::warn("the env reported an invalid login name; SSH uses `dev`");
    }
    if state.user != user {
        EnvState::update(&ctx.paths, env, |s| s.user = user)?;
    }
    // Home files may have replaced an agent's config, and with it luoto's entries there; an
    // agent with options gets them on every start.
    let copied = personal::apply(ctx, env, &p.cfg, state.home(), quiet) > 0;
    let write = if copied {
        crate::agents::Write::All
    } else {
        crate::agents::Write::Set
    };
    crate::agents::configure(ctx, env, &p.cfg, None, write)?;
    if let Err(e) = ssh::authorize(ctx, env) {
        crate::progress::warn(&format!("SSH access not set up ({e:#})"));
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
    let mut args =
        exec(&names::dev(env))
            .user(UID)
            .argv(["/opt/luoto/bin/sandbox", "selftest", "--json"]);
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
    let _waiting = crate::progress::waiting(&format!("stopping `{env}`"));
    for c in [names::dev(env), names::gate(env)] {
        ctx.rt.stop(&c)?;
    }
    Ok(())
}

/// Delete the env's containers, networks, volumes, vault binding and state (CA, vault token,
/// accepted luoto.toml), so a new env of the same name starts fresh.
pub fn remove(ctx: &Ctx, env: &str) -> Result<()> {
    let _waiting = crate::progress::waiting(&format!("removing `{env}`"));
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
    forget(ctx, env)
}

/// Delete what this machine keeps of the env: its state and its shares' clones.
pub fn forget(ctx: &Ctx, env: &str) -> Result<()> {
    let state = ctx.paths.env_state(env);
    if state.exists() {
        std::fs::remove_dir_all(&state)?;
    }
    crate::shares::forget(env);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_install_question_outlives_an_up_that_didnt_answer_it() {
        let mut s = EnvState::fresh(1, None);
        filled(&mut s, true);
        assert!(s.seeded && s.installs_pending);
        // An `up` cut short after the clone: the next one finds the state saved so.
        let saved = serde_json::to_vec(&s).unwrap();
        let mut next: EnvState = serde_json::from_slice(&saved).unwrap();
        assert!(next.installs_pending);
        // A workspace volume filled again doesn't answer it.
        filled(&mut next, false);
        assert!(next.installs_pending);
        let mut copied = EnvState::fresh(2, None);
        filled(&mut copied, false);
        assert!(!copied.installs_pending);
        let old: EnvState =
            serde_json::from_str(r#"{"octet":3,"home":null,"vault_token":"t","seeded":true}"#)
                .unwrap();
        assert!(!old.installs_pending);
    }
}
