//! `luoto setup` / `luoto doctor`: detect the host and the container runtimes it has, set luoto
//! up on the one chosen, prepare luoto's images, and verify isolation of every env. Installing
//! a runtime is the user's: setup names what luoto runs on and runs no package manager.

use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::config;
use crate::env::{self, Ctx};
use crate::machine;
use crate::names;
use crate::paths::Paths;
use crate::release;
use crate::runtime::{Flavor, Runtime};

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeInfo {
    pub name: String,
    pub version: Option<(u32, u32, u32)>,
    pub version_ok: bool,
    pub reachable: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    pub os: String,
    pub arch: String,
    pub distro: Option<String>,
    pub cpus: usize,
    pub runtimes: Vec<RuntimeInfo>,
    pub wsl: Option<String>,
}

/// The oldest podman and Docker luoto runs on; Apple's is [`machine::APPLE_MIN`].
const PODMAN_MIN: (u32, u32, u32) = (5, 2, 0);
const DOCKER_MIN: (u32, u32, u32) = (28, 0, 0);

fn output(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn parse_version(text: &str) -> Option<(u32, u32, u32)> {
    text.split(|c: char| c.is_whitespace() || c == ',')
        .find_map(|w| {
            let w = w.trim_start_matches('v');
            let mut it = w.split('.');
            let a = it.next()?.parse().ok()?;
            let b = it.next()?.parse().ok()?;
            let c = it
                .next()
                .and_then(|c| {
                    c.split(|ch: char| !ch.is_ascii_digit())
                        .next()?
                        .parse()
                        .ok()
                })
                .unwrap_or(0);
            Some((a, b, c))
        })
}

fn probe_runtime(flavor: Flavor, min: (u32, u32, u32)) -> Option<RuntimeInfo> {
    let rt = Runtime {
        bin: match flavor {
            Flavor::Podman => "podman",
            Flavor::Docker => "docker",
            Flavor::Apple => "container",
        }
        .into(),
        flavor,
        connection: None,
        api: None,
    };
    let version = parse_version(&rt.version().ok()?);
    let version_ok = version.is_some_and(|v| v >= min);
    let (reachable, detail) = match flavor {
        // luoto starts its own machine there; podman's default one doesn't matter.
        Flavor::Podman if crate::machine::supported() => {
            (true, "podman (luoto runs envs in its own VM)".to_string())
        }
        Flavor::Podman => match rt.run(["info", "--format", "{{.Host.RemoteSocket.Exists}}"]) {
            Ok(_) => (true, "podman reachable".to_string()),
            Err(_) => (false, "podman installed but `podman info` fails".into()),
        },
        Flavor::Docker => match rt.run(["info", "--format", "{{.ServerVersion}}"]) {
            Ok(v) => (true, format!("docker engine {}", v.trim())),
            Err(_) => (
                false,
                "docker CLI installed but the engine is not running".into(),
            ),
        },
        Flavor::Apple if machine::apple_running(&rt) => {
            (true, "Apple's container, service running".to_string())
        }
        Flavor::Apple => (false, "Apple's container, service stopped".to_string()),
    };
    Some(RuntimeInfo {
        name: rt.bin,
        version,
        version_ok,
        reachable,
        detail,
    })
}

/// The distribution's `ID` in /etc/os-release.
pub fn os_release(text: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.strip_prefix("ID="))
        .map(|v| v.trim_matches('"').to_string())
}

pub fn detect() -> Detection {
    let os = std::env::consts::OS.to_string();
    let distro = std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|t| os_release(&t));
    let runtimes = [(Flavor::Podman, PODMAN_MIN), (Flavor::Docker, DOCKER_MIN)]
        .into_iter()
        .filter_map(|(f, min)| probe_runtime(f, min))
        .collect();
    let wsl = (os == "windows")
        .then(|| output("wsl", &["--status"]).unwrap_or_else(|| "not installed".into()));
    Detection {
        os,
        arch: std::env::consts::ARCH.into(),
        distro,
        cpus: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2),
        runtimes,
        wsl,
    }
}

#[derive(clap::Args)]
pub struct SetupOpts {
    /// Build luoto's images from the checkout this binary was built from, instead of pulling
    /// them (source builds only).
    #[arg(long)]
    pub build: bool,
    /// Run envs on this runtime, which has to be installed: `container` (Apple's, on macOS 26
    /// or later on Apple silicon), `podman` or `docker`.
    #[arg(long, value_enum)]
    pub runtime: Option<RuntimeChoice>,
    /// Don't ask first.
    #[arg(long, short)]
    pub yes: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeChoice {
    Container,
    Podman,
    Docker,
}

impl RuntimeChoice {
    fn of(flavor: Flavor) -> Self {
        match flavor {
            Flavor::Apple => RuntimeChoice::Container,
            Flavor::Podman => RuntimeChoice::Podman,
            Flavor::Docker => RuntimeChoice::Docker,
        }
    }

    pub fn flavor(self) -> Flavor {
        match self {
            RuntimeChoice::Container => Flavor::Apple,
            RuntimeChoice::Podman => Flavor::Podman,
            RuntimeChoice::Docker => Flavor::Docker,
        }
    }

    /// As `--runtime` and config.toml's `runtime` take it.
    pub fn name(self) -> &'static str {
        match self {
            RuntimeChoice::Container => "container",
            RuntimeChoice::Podman => "podman",
            RuntimeChoice::Docker => "docker",
        }
    }
}

/// Where Apple's `container` is installed from.
const APPLE_URL: &str = "https://github.com/apple/container/releases";
const APPLE_HOST_ONLY: &str = "Apple's container needs macOS 26 or later on Apple silicon";

/// Apple's `container` as found: `None` where it can't run, `Some(None)` where it isn't
/// installed.
pub fn probe_apple() -> Option<Option<RuntimeInfo>> {
    machine::apple_host().then(|| probe_runtime(Flavor::Apple, machine::APPLE_MIN))
}

/// A runtime luoto runs on, as this machine has it: a row of setup's listing, of its menu
/// where it is ready, and of the UI's choice.
#[derive(Debug, Clone, Serialize)]
pub struct RuntimeOption {
    pub runtime: RuntimeChoice,
    pub label: String,
    /// How it isolates an env.
    pub description: String,
    /// The oldest version luoto runs on.
    pub min: String,
    /// Its own install page.
    pub url: String,
    /// What was found of it: its version, and what keeps luoto from using it.
    pub status: String,
    /// Setup can use it: installed, new enough, and running unless setup starts it.
    pub ready: bool,
    /// config.toml names it.
    pub current: bool,
    /// Where the choice starts: the current runtime when it is ready, else the first ready.
    pub selected: bool,
    /// The command that sets it up.
    pub setup: String,
}

fn dotted((a, b, c): (u32, u32, u32)) -> String {
    format!("{a}.{b}.{c}")
}

/// `runtime` as its probe `found` it, on `os`: podman and Docker have a VM around them on
/// macOS and Windows only.
fn option(runtime: RuntimeChoice, found: Option<&RuntimeInfo>, os: &str) -> RuntimeOption {
    let vm = matches!(os, "macos" | "windows");
    let (label, min, description, url) = match runtime {
        RuntimeChoice::Container => (
            "Apple's container",
            machine::APPLE_MIN,
            "every container is a VM of its own",
            APPLE_URL,
        ),
        RuntimeChoice::Podman => (
            "podman",
            PODMAN_MIN,
            if vm {
                "every env in luoto's one VM, under gVisor"
            } else {
                "containers on this machine's kernel, under gVisor where runsc is installed"
            },
            "https://podman.io/docs/installation",
        ),
        RuntimeChoice::Docker => (
            "Docker",
            DOCKER_MIN,
            if vm {
                "containers in the Docker engine's VM; gVisor only where registered with it"
            } else {
                "containers on this machine's kernel; gVisor only where registered with Docker"
            },
            "https://docs.docker.com/engine/install/",
        ),
    };
    // Setup starts Apple's service itself; the others have to be running.
    let reachable = |i: &RuntimeInfo| i.reachable || runtime == RuntimeChoice::Container;
    let status = match found {
        None => "not installed".to_string(),
        Some(i) => {
            let version = i.version.map_or_else(|| "unknown version".into(), dotted);
            if !i.version_ok {
                format!("{version} found")
            } else if reachable(i) {
                version
            } else if runtime == RuntimeChoice::Docker {
                format!("{version}, the engine is not running")
            } else {
                format!("{version}, `podman info` fails")
            }
        }
    };
    RuntimeOption {
        runtime,
        label: label.into(),
        description: description.into(),
        min: dotted(min),
        url: url.into(),
        status,
        ready: found.is_some_and(|i| i.version_ok && reachable(i)),
        current: false,
        selected: false,
        setup: format!("luoto setup --runtime {}", runtime.name()),
    }
}

/// The runtimes luoto runs on here, in the order setup lists and prefers them: Apple's
/// `container` where it can run (`apple` from [`probe_apple`]), podman, Docker.
pub fn runtime_options(
    d: &Detection,
    apple: Option<Option<&RuntimeInfo>>,
    current: Option<Flavor>,
) -> Vec<RuntimeOption> {
    let found = |name: &str| d.runtimes.iter().find(|r| r.name == name);
    let mut options: Vec<RuntimeOption> = apple
        .map(|a| option(RuntimeChoice::Container, a, &d.os))
        .into_iter()
        .chain([
            option(RuntimeChoice::Podman, found("podman"), &d.os),
            option(RuntimeChoice::Docker, found("docker"), &d.os),
        ])
        .collect();
    let is_current = |o: &RuntimeOption| current == Some(o.runtime.flavor());
    let start = options
        .iter()
        .position(|o| o.ready && is_current(o))
        .or_else(|| options.iter().position(|o| o.ready));
    for (i, o) in options.iter_mut().enumerate() {
        o.current = is_current(o);
        o.selected = Some(i) == start;
    }
    options
}

/// What setup says where no runtime is ready: each one luoto runs on with its oldest
/// version, what was found of it, how it isolates an env and its own install page. `wsl` is
/// what Windows said of WSL.
pub fn listing(options: &[RuntimeOption], wsl: Option<&str>) -> String {
    let mut out = String::from("no container runtime luoto runs on is ready here\n");
    for o in options {
        let product = match o.runtime {
            RuntimeChoice::Docker => "Docker Engine",
            _ => &o.label,
        };
        out.push_str(&format!(
            "\n{product} {} or later: {}\n  {}\n  {}",
            o.min, o.status, o.description, o.url
        ));
    }
    if wsl.is_some_and(|w| w.contains("not installed")) {
        out.push_str(
            "\n\npodman and Docker run in WSL2 or Hyper-V on Windows; WSL is not installed",
        );
    }
    out.push_str("\n\ninstall one, then run `luoto setup` again");
    out
}

#[derive(Debug, PartialEq)]
enum Decision {
    Use(RuntimeChoice),
    Ask,
    /// No runtime is ready.
    Nothing,
}

/// Which runtime setup takes: the one `asked` for (`--runtime`), which has to be ready; else
/// the only ready one; else, of several, the user's pick, or where nothing can be asked
/// (`ask` false: `--yes`, no terminal) the one the choice starts at. The current runtime is
/// never left for another unasked.
fn decide(asked: Option<RuntimeChoice>, ask: bool, options: &[RuntimeOption]) -> Result<Decision> {
    if let Some(runtime) = asked {
        let o = options
            .iter()
            .find(|o| o.runtime == runtime)
            .context(APPLE_HOST_ONLY)?;
        if !o.ready {
            bail!(
                "{} is not ready ({}); luoto runs on {} or later: {}",
                o.label,
                o.status,
                o.min,
                o.url
            );
        }
        return Ok(Decision::Use(runtime));
    }
    let ready: Vec<&RuntimeOption> = options.iter().filter(|o| o.ready).collect();
    if let (Some(o), false) = (
        options.iter().find(|o| o.current && !o.ready),
        ready.is_empty(),
    ) {
        bail!(
            "{}, which runs this machine's envs, is not ready ({}); `{}` moves to another",
            o.label,
            o.status,
            ready[0].setup
        );
    }
    Ok(match ready.as_slice() {
        [] => Decision::Nothing,
        [one] => Decision::Use(one.runtime),
        _ if ask => Decision::Ask,
        several => Decision::Use(
            several
                .iter()
                .find(|o| o.selected)
                .unwrap_or(&several[0])
                .runtime,
        ),
    })
}

/// The runtime in a line, as setup's summary and the UI say it.
pub fn runtime_line(rt: &Runtime) -> String {
    let version = parse_version(&rt.version().unwrap_or_default())
        .map(|(a, b, c)| format!(" {a}.{b}.{c}"))
        .unwrap_or_default();
    match rt.flavor {
        Flavor::Apple => format!("Apple's container{version}: each container its own VM"),
        Flavor::Podman if machine::is_luoto(rt.connection.as_deref()) => {
            format!("podman{version}, in luoto's VM")
        }
        _ => format!("{}{version}", rt.name()),
    }
}

/// The runtime an existing config names: its `runtime`, or podman for luoto's VM.
pub fn configured(global: &config::GlobalConfig) -> Option<Flavor> {
    match (&global.runtime, &global.connection) {
        (Some(_), _) => Runtime::from_config(global).ok().map(|rt| rt.flavor),
        (None, Some(_)) => Some(Flavor::Podman),
        (None, None) => None,
    }
}

/// Starts the service of Apple's `container` where it isn't running.
fn apple_start() -> Result<()> {
    let rt = Runtime {
        bin: "container".into(),
        flavor: Flavor::Apple,
        connection: None,
        api: None,
    };
    if !machine::apple_running(&rt) {
        machine::start_apple_service(&rt)?;
    }
    Ok(())
}

fn source_root() -> Option<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .to_path_buf();
    root.join("Containerfile").exists().then_some(root)
}

pub fn build_images(rt: &Runtime, tag: &str) -> Result<()> {
    let root = source_root()
        .context("luoto's source tree is not available; build images from a checkout")?;
    let builder: Vec<String> = match rt.flavor {
        Flavor::Apple => machine::apple_builder().into(),
        _ => Vec::new(),
    };
    let file = root.join("Containerfile").to_string_lossy().into_owned();
    let dir = root.to_string_lossy().into_owned();
    let image_dir = root.join("image");
    let base_file = image_dir
        .join("Containerfile")
        .to_string_lossy()
        .into_owned();
    let base_dir = image_dir.to_string_lossy().into_owned();
    let builds = [
        ("gate", vec!["-f", &file, "--target", "gate", &dir]),
        ("vault", vec!["-f", &file, "--target", "vault", &dir]),
        ("tools", vec!["-f", &file, "--target", "tools", &dir]),
        ("base", vec!["-f", &base_file, &base_dir]),
    ];
    for (comp, args) in builds {
        let image = names::image(comp, tag);
        let (context, args) = args.split_last().context("build args")?;
        let status = crate::progress::step(&format!("building {image}"), || {
            crate::progress::tool(
                rt,
                ["build"]
                    .into_iter()
                    .chain(builder.iter().map(String::as_str))
                    .chain(args.iter().copied())
                    .chain(["-t", &image, context]),
                &|_| {},
            )
        })?;
        if !status.success() {
            bail!("building {image} failed");
        }
    }
    Ok(())
}

pub fn setup(o: SetupOpts) -> Result<ExitCode> {
    if o.build && source_root().is_none() {
        bail!("`--build` needs luoto's source tree; this binary was not built from one");
    }
    let paths = Paths::get()?;
    let mut global = config::load_global(&paths)?;
    let first = first_setup(&global);
    // `apple` is None where Apple's `container` can't run, Some(None) where it isn't installed.
    // Setup opens with the splash, which plays while this looks.
    let (d, apple) = crate::splash::during("looking at this machine's container runtimes", || {
        (detect(), probe_apple())
    });
    println!(
        "host: {} {}{}",
        d.os,
        d.arch,
        d.distro
            .as_deref()
            .map(|s| format!(" ({s})"))
            .unwrap_or_default()
    );
    // In the order setup lists them.
    for r in apple.iter().flatten().chain(&d.runtimes) {
        println!(
            "  {:<9} {} {}",
            r.name,
            r.version
                .map(|(a, b, c)| format!("{a}.{b}.{c}"))
                .unwrap_or_else(|| "?".into()),
            r.detail
        );
    }
    let before = configured(&global);
    let options = runtime_options(&d, apple.as_ref().map(Option::as_ref), before);
    let ask = !o.yes && crate::prompt::interactive();
    let choice = match decide(o.runtime, ask, &options)? {
        Decision::Use(c) => c,
        Decision::Nothing => {
            out_text!("\n{}", listing(&options, d.wsl.as_deref()));
            return Ok(ExitCode::FAILURE);
        }
        Decision::Ask => match crate::wizard::pick_runtime(&options)? {
            Some(c) => c,
            // Esc: unchanged where a runtime is set up, later on a first setup.
            None => match options.iter().find(|o| o.current) {
                Some(o) => o.runtime,
                None => {
                    out!("nothing set up; `luoto setup` asks again");
                    return Ok(ExitCode::SUCCESS);
                }
            },
        },
    };
    if let Some(before) = before.filter(|b| *b != choice.flavor()) {
        let envs = config::list_envs(&paths)?.len();
        if envs > 0 {
            println!(
                "! {envs} env(s) keep their containers and volumes on {}: work not pulled to \
                 this machine stays there",
                RuntimeChoice::of(before).name()
            );
        }
    }
    // Another runtime's VM connection and gVisor path aren't this one's.
    if before != Some(choice.flavor()) {
        global.runtime = Some(choice.name().into());
        global.connection = None;
        global.gvisor = None;
    }
    match choice {
        RuntimeChoice::Container => apple_start()?,
        RuntimeChoice::Podman => podman_ready(&o, &d, &paths, &mut global)?,
        // Docker runs envs as it is: its engine's VM or this machine's kernel.
        RuntimeChoice::Docker => {}
    }
    let other = options
        .iter()
        .find(|x| x.ready && x.runtime != choice)
        .map(|x| x.setup.clone());
    finish(o, paths, global, other, first)
}

/// Whether no setup has completed here: the config names no runtime yet.
fn first_setup(global: &config::GlobalConfig) -> bool {
    global.runtime.is_none() && global.connection.is_none()
}

/// podman's half of `setup`: luoto's VM where podman needs one, gVisor where it is found.
fn podman_ready(
    o: &SetupOpts,
    d: &Detection,
    paths: &Paths,
    global: &mut config::GlobalConfig,
) -> Result<()> {
    let rt = Runtime::from_config(global)?;
    if rt.flavor == Flavor::Podman && machine::supported() {
        // Envs run in luoto's own VM: none of your folders but the shares folder once you share
        // one, an ID range per env, gVisor.
        if !machine::exists(&rt.bin) {
            let memory = machine::host_memory_mib().map_or(4096, |m| (m / 4).clamp(4096, 16_384));
            let cpus = u32::try_from(d.cpus / 2).unwrap_or(2).max(2);
            machine::create(&rt.bin, cpus, memory)?;
        }
        machine::start(&rt.bin, o.yes)?;
        let mounts = crate::progress::wait("checking luoto's VM", || {
            machine::prepare(&rt.bin)?;
            if machine::has_shares(&rt.bin) {
                machine::mount_shares(&rt.bin)?;
            }
            machine::host_mounts(&rt.bin)
        })?;
        if !mounts.is_empty() {
            bail!(
                "luoto's VM mounts host folders ({}); remove it with `podman machine rm {}` and run `luoto setup` again",
                mounts.join(", "),
                machine::NAME
            );
        }
        global.connection = Some(machine::NAME.into());
        global.gvisor = Some(machine::runsc_path());
        out!(
            "\nluoto's VM `{}`: no host folders, an ID range per env, gVisor {}",
            machine::NAME,
            machine::GVISOR_RELEASE
        );
    } else if rt.flavor == Flavor::Podman {
        global.gvisor = match which("runsc") {
            Some(runsc) => {
                let wrapper = paths.data.join("luoto-runsc");
                std::fs::create_dir_all(&paths.data)?;
                std::fs::write(&wrapper, machine::runsc_wrapper(&runsc))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755))?;
                }
                Some(wrapper.display().to_string())
            }
            None => None,
        };
        if global.gvisor.is_none() {
            out!(
                "\n! gVisor (runsc) is not installed (https://gvisor.dev): dev containers share \
                 this machine's kernel. With it installed, `luoto setup` puts them under it."
            );
        }
    }
    Ok(())
}

/// Images, the vault and the summary, once the runtime is ready; the summary names the
/// command that moves to `other`, another runtime that is ready here.
fn finish(
    o: SetupOpts,
    paths: Paths,
    mut global: config::GlobalConfig,
    other: Option<String>,
    first: bool,
) -> Result<ExitCode> {
    let rt = Runtime::from_config(&global)?;
    global.runtime.get_or_insert_with(|| rt.bin.clone());
    let mut new_images = true;
    if o.build {
        // Built images replace the release's pinned ones until `images` is removed again.
        let tag = global.images.get_or_insert_with(|| "dev".into()).clone();
        build_images(&rt, &tag)?;
    } else {
        let refs: Vec<String> = release::COMPONENTS
            .iter()
            .map(|c| release::image(global.images.as_deref(), c))
            .collect();
        let missing: Vec<&String> = crate::progress::wait("checking luoto's images", || {
            refs.iter().filter(|r| !rt.image_exists(r)).collect()
        });
        if missing.is_empty() {
            new_images = false;
            if source_root().is_some() {
                out!("\nimages present; `luoto setup --build` rebuilds them from source");
            } else {
                println!("\nimages present");
            }
        } else if release::pinned() && global.images.is_none() {
            for r in missing {
                rt.pull(r)?;
            }
        } else if source_root().is_some() {
            build_images(&rt, global.images.as_deref().unwrap_or("dev"))?;
        } else {
            bail!("luoto's images are missing and this binary pins none; install a release build");
        }
    }
    config::save_global(&paths, &global)?;
    let ctx = Ctx { paths, global, rt };
    env::ensure_vault(&ctx)?;
    if new_images {
        crate::progress::wait("looking for older images", || {
            crate::disk::note_superseded(&ctx)
        });
    }
    let home = ctx.paths.home_files();
    if crate::personal::seed_home(&home)? {
        out!(
            "\nyour own config for every env goes in {} (copied in on each `up`)",
            crate::ssh::tilde(&home)
        );
    }
    let mut rows = vec![("runtime", runtime_line(&ctx.rt))];
    if let Some(other) = other {
        rows.push(("change it", other));
    }
    close(first, rows);
    Ok(ExitCode::SUCCESS)
}

/// The summary that ends `setup`. A first setup ends with the way on from it as a line of its
/// own; a later one names the next step as a row.
fn close(first: bool, mut rows: Vec<(&str, String)>) {
    if !first {
        rows.push(("next", "luoto init, inside a project folder".into()));
    }
    block!("\n{}", crate::prompt::summary("ready", &rows));
    if first {
        out!("\nNext: run `luoto init` inside a project folder.");
    }
}

/// What `doctor` found, each line printed as it comes; `--report` keeps them.
#[derive(Default)]
struct Checks(Vec<String>);

impl Checks {
    fn say(&mut self, line: String) {
        println!("{}", crate::style::out().check(&line));
        self.0.push(line);
    }
}

/// `luoto doctor`; with `report` (`--report [FILE]`), its checks and more go to a redacted
/// file for a bug report (`report.rs`), also when the checks can't run.
pub fn doctor(report: Option<Option<String>>) -> Result<ExitCode> {
    let mut out = Checks::default();
    let ctx = Ctx::load();
    let checked = match &ctx {
        Ok(ctx) => checks(ctx, &mut out),
        Err(e) => Err(anyhow::anyhow!("{e:#}")),
    };
    let ok = match (checked, &report) {
        (Ok(ok), _) => ok,
        (Err(e), Some(_)) => {
            out.say(format!("doctor could not go on: {e:#}"));
            false
        }
        (Err(e), None) => return Err(e),
    };
    if let Some(file) = report {
        crate::report::write(ctx.as_ref().ok(), &out.0, file.as_deref())?;
    }
    Ok(if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// The checks, printed and kept in `out`; whether all passed.
fn checks(ctx: &Ctx, out: &mut Checks) -> Result<bool> {
    let mut ok = true;
    let current = luoto_shared::VERSION;
    out.say(match crate::upgrade::latest() {
        Ok(Some(l)) if crate::upgrade::newer(&l, current) => {
            format!("luoto {current}: {l} is out (`luoto upgrade`)")
        }
        Ok(Some(_)) => format!("luoto {current} (latest)"),
        Ok(None) => format!("luoto {current} (no release published yet)"),
        Err(_) => format!("luoto {current} (could not check for a newer release)"),
    });
    if ctx.rt.flavor == Flavor::Podman && machine::supported() {
        if !machine::is_luoto(ctx.rt.connection.as_deref()) {
            out.say("VM: not luoto's own (run `luoto setup`); envs refuse to start".into());
            return Ok(false);
        }
        if !machine::running(&ctx.rt.bin) {
            out.say("VM: luoto's VM is stopped; `luoto up` starts it".into());
            return Ok(true);
        }
        match crate::progress::wait("checking luoto's VM", || machine::host_mounts(&ctx.rt.bin)) {
            Ok(m) if m.is_empty() => out.say(
                if machine::has_shares(&ctx.rt.bin) {
                    "VM: luoto's own, none of your folders mounted but the shares folder, read-only"
                } else {
                    "VM: luoto's own, none of your folders mounted"
                }
                .into(),
            ),
            Ok(m) => {
                ok = false;
                out.say(format!(
                    "VM: MOUNTS HOST FOLDERS ({}): an escape reaches them; `podman machine rm {}`, then `luoto setup`",
                    m.join(", "),
                    machine::NAME
                ));
            }
            Err(e) => {
                ok = false;
                out.say(format!("VM: could not check its mounts: {e:#}"));
            }
        }
    }
    if ctx.rt.flavor == Flavor::Apple {
        let (a, b, c) = machine::APPLE_MIN;
        match ctx.rt.version().ok().and_then(|v| parse_version(&v)) {
            None => {
                out.say(format!(
                    "runtime: Apple's container is not installed; {APPLE_URL}"
                ));
                return Ok(false);
            }
            Some(v) if v < machine::APPLE_MIN => {
                ok = false;
                out.say(format!(
                    "runtime: Apple's container {}.{}.{} is older than {a}.{b}.{c}; {APPLE_URL}",
                    v.0, v.1, v.2
                ));
            }
            Some((x, y, z)) => out.say(format!("runtime: Apple's container {x}.{y}.{z}")),
        }
        if !machine::apple_running(&ctx.rt) {
            out.say("runtime: its service is stopped; `container system start`".into());
            return Ok(ok);
        }
        out.say("isolation: every container is a VM of its own".into());
    } else {
        out.say(format!(
            "runtime: {} ({})",
            ctx.rt.name(),
            ctx.rt.version().unwrap_or_else(|e| format!("error: {e}"))
        ));
        out.say(match &ctx.global.gvisor {
            Some(p) => format!("gVisor: {p} (dev containers run on it unless an env opts out)"),
            None => "gVisor: not set up; dev containers share the VM's kernel".into(),
        });
    }
    for c in ["gate", "vault", "tools", "base"] {
        let img = ctx.image(c);
        let present = ctx.rt.image_exists(&img);
        ok &= present || c == "base";
        out.say(format!(
            "image {img}: {}",
            if present { "ok" } else { "missing" }
        ));
    }
    for line in crate::progress::wait("measuring disk use", || crate::disk::doctor_lines(ctx)) {
        out.say(line);
    }
    match crate::ctl::vault_status(&ctx.rt) {
        Ok(v) => {
            out.say(format!(
                "vault: running, {}",
                if v.locked { "locked" } else { "unlocked" }
            ));
            if let Some(line) = swap_line(&v) {
                out.say(line);
            }
        }
        Err(_) => out.say("vault: not running (starts with the first `luoto up`)".into()),
    }
    let probe_port = 47_000 + (rand::random::<u16>() % 1000);
    let probe_name = format!("luoto-probe-{probe_port}");
    // A host-network listener on the env's gateway; Apple's dev containers have no network.
    let probe = crate::progress::wait("starting a probe for the self-tests", || {
        if ctx.rt.flavor == Flavor::Apple {
            bail!("no host network");
        }
        ctx.rt.run([
            "run",
            "-d",
            "--rm",
            "--name",
            &probe_name,
            "--network",
            "host",
            &ctx.image("tools"),
            "sh",
            "-c",
            &format!("while true; do echo luoto-probe | nc -l -p {probe_port}; done"),
        ])
    });
    for env_name in config::list_envs(&ctx.paths)? {
        if let Some(n) = crate::ca::notice(&ctx.paths.env_state(&env_name), &env_name) {
            out.say(format!("env {env_name}: CA {n}"));
        }
        if !ctx.rt.is_running(&names::dev(&env_name)) {
            out.say(format!("env {env_name}: not running"));
            continue;
        }
        let Some(st) = crate::state::EnvState::load(&ctx.paths, &env_name)? else {
            continue;
        };
        let gw = names::addrs(st.octet).gateway;
        let probe_addr = probe.is_ok().then(|| format!("{gw}:{probe_port}"));
        let tested = crate::progress::wait(&format!("testing `{env_name}`'s isolation"), || {
            env::selftest(ctx, &env_name, probe_addr.as_deref())
        });
        match tested {
            Ok(r) => {
                ok &= r.ok;
                let isolation = config::EnvFile::load(&ctx.paths, &env_name)
                    .map(|f| f.cfg.isolation(&ctx.global))
                    .map_or("?", |i| match i {
                        config::Isolation::Gvisor => "gVisor",
                        config::Isolation::Container => "container",
                    });
                out.say(format!(
                    "env {env_name}: {} ({isolation})\n{}",
                    if r.ok { "isolated" } else { "NOT ISOLATED" },
                    r.render()
                ));
            }
            Err(e) => {
                ok = false;
                out.say(format!("env {env_name}: self-test failed to run: {e:#}"));
            }
        }
    }
    if probe.is_ok() {
        let _ = ctx.rt.run(["rm", "-f", &probe_name]);
    }
    Ok(ok)
}

/// Where luoto's containers run has swap: whether the vault stays out of it, and what can be
/// paged to it anyway. Nothing without swap (luoto's VM, Apple's VMs).
fn swap_line(v: &luoto_shared::ctl::VaultStatus) -> Option<String> {
    if v.swap_kib == 0 {
        return None;
    }
    let swap = format!(
        "swap: {} MiB where luoto's containers run",
        v.swap_kib / 1024
    );
    Some(match v.swap_max.as_deref() {
        Some("0") => format!(
            "{swap}; the vault and gates never swap, but `[sandbox_secrets]` in env shells can"
        ),
        Some(_) => format!(
            "{swap}, and THE VAULT CAN BE SWAPPED to it: the next `luoto up` recreates it without"
        ),
        None => format!(
            "{swap}, and THE VAULT CAN BE SWAPPED to it: the runtime limits no swap (cgroup v1); \
             turn swap off there"
        ),
    })
}

/// Full path of `bin` on PATH.
fn which(bin: &str) -> Option<String> {
    std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join(bin))
            .find(|f| f.is_file())
            .map(|f| f.display().to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_setup_is_the_first_until_the_config_names_a_runtime() {
        let mut global = config::GlobalConfig::default();
        assert!(first_setup(&global));
        global.connection = Some("luoto".into());
        assert!(!first_setup(&global));
        global.connection = None;
        global.runtime = Some("docker".into());
        assert!(!first_setup(&global));
    }

    #[test]
    fn swap_is_named_only_where_there_is_some() {
        let v = |swap_kib, swap_max: Option<&str>| luoto_shared::ctl::VaultStatus {
            version: "x".into(),
            started: chrono::Utc::now(),
            locked: false,
            loaded_refs: vec![],
            envs: vec![],
            swap_kib,
            swap_max: swap_max.map(str::to_string),
        };
        assert_eq!(swap_line(&v(0, Some("max"))), None);
        let off = swap_line(&v(1_048_576, Some("0"))).unwrap();
        assert!(off.starts_with("swap: 1024 MiB") && off.contains("never swap"));
        let old = swap_line(&v(1_048_576, Some("max"))).unwrap();
        assert!(old.contains("THE VAULT CAN BE SWAPPED") && old.contains("`luoto up`"));
        let v1 = swap_line(&v(1_048_576, None)).unwrap();
        assert!(v1.contains("THE VAULT CAN BE SWAPPED") && v1.contains("cgroup v1"));
    }

    fn det(os: &str, runtimes: Vec<RuntimeInfo>) -> Detection {
        Detection {
            os: os.into(),
            arch: "aarch64".into(),
            distro: None,
            cpus: 8,
            runtimes,
            wsl: None,
        }
    }

    fn info(name: &str, version: (u32, u32, u32), reachable: bool) -> RuntimeInfo {
        let min = match name {
            "podman" => PODMAN_MIN,
            "docker" => DOCKER_MIN,
            _ => machine::APPLE_MIN,
        };
        RuntimeInfo {
            name: name.into(),
            version: Some(version),
            version_ok: version >= min,
            reachable,
            detail: String::new(),
        }
    }

    /// A Mac with all three ready.
    fn all_three(current: Option<Flavor>) -> Vec<RuntimeOption> {
        let d = det(
            "macos",
            vec![
                info("podman", (6, 2, 0), true),
                info("docker", (29, 1, 0), true),
            ],
        );
        let apple = info("container", machine::APPLE_MIN, false);
        runtime_options(&d, Some(Some(&apple)), current)
    }

    #[test]
    fn versions() {
        assert_eq!(parse_version("podman version 6.1.4"), Some((6, 1, 4)));
        assert_eq!(
            parse_version("Docker version 29.0.1, build abc"),
            Some((29, 0, 1))
        );
        assert_eq!(parse_version("nothing"), None);
    }

    #[test]
    fn the_distribution_is_its_id() {
        let id = os_release("NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\n");
        assert_eq!(id.as_deref(), Some("ubuntu"));
        assert_eq!(os_release("NAME=x\n"), None);
    }

    #[test]
    fn without_a_runtime_setup_lists_what_luoto_runs_on_and_no_command_to_install_one() {
        let d = det("linux", vec![]);
        let options = runtime_options(&d, None, None);
        assert!(options.iter().all(|o| !o.ready && !o.selected));
        assert_eq!(decide(None, true, &options).unwrap(), Decision::Nothing);
        assert_eq!(
            listing(&options, None),
            "no container runtime luoto runs on is ready here\n\n\
             podman 5.2.0 or later: not installed\n  \
             containers on this machine's kernel, under gVisor where runsc is installed\n  \
             https://podman.io/docs/installation\n\
             Docker Engine 28.0.0 or later: not installed\n  \
             containers on this machine's kernel; gVisor only where registered with Docker\n  \
             https://docs.docker.com/engine/install/\n\n\
             install one, then run `luoto setup` again"
        );

        // Where Apple's container can run it is listed first; every line fits 80 columns.
        let mac = runtime_options(&det("macos", vec![]), Some(None), None);
        let text = listing(&mac, None);
        let (a, b, c) = machine::APPLE_MIN;
        assert!(text.contains(&format!(
            "\n\nApple's container {a}.{b}.{c} or later: not installed\n"
        )));
        assert!(text.contains("https://github.com/apple/container/releases"));
        assert!(text.lines().all(|l| l.chars().count() <= 80), "{text}");
        for word in ["brew", "sudo", "winget", "apt", "recommend", "--install"] {
            assert!(!text.contains(word), "{word} in {text}");
        }

        let windows = listing(
            &runtime_options(&det("windows", vec![]), None, None),
            Some("not installed"),
        );
        assert!(windows.contains("WSL is not installed") && !windows.contains("wsl --install"));
    }

    #[test]
    fn a_runtime_too_old_or_not_running_says_so_and_is_no_choice() {
        let d = det(
            "linux",
            vec![
                info("podman", (4, 9, 3), true),
                info("docker", (29, 1, 0), false),
            ],
        );
        let options = runtime_options(&d, None, None);
        assert_eq!(options[0].status, "4.9.3 found");
        assert_eq!(options[1].status, "29.1.0, the engine is not running");
        assert!(options.iter().all(|o| !o.ready));
        let text = listing(&options, None);
        assert!(text.contains("podman 5.2.0 or later: 4.9.3 found"));
        assert!(text.contains("Docker Engine 28.0.0 or later: 29.1.0, the engine is not running"));
        let err = decide(Some(RuntimeChoice::Docker), false, &options).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Docker is not ready (29.1.0, the engine is not running); luoto runs on 28.0.0 or \
             later: https://docs.docker.com/engine/install/"
        );
    }

    #[test]
    fn the_choice_lists_apple_podman_docker_and_starts_at_the_current_or_the_first_ready() {
        let selected = |options: &[RuntimeOption]| {
            let on: Vec<_> = options.iter().filter(|o| o.selected).collect();
            assert_eq!(on.len(), 1);
            on[0].runtime
        };
        let first = all_three(None);
        let order: Vec<_> = first.iter().map(|o| o.runtime).collect();
        assert_eq!(
            order,
            [
                RuntimeChoice::Container,
                RuntimeChoice::Podman,
                RuntimeChoice::Docker
            ]
        );
        // Apple's service is started by setup, so a stopped one is ready.
        assert!(first.iter().all(|o| o.ready && !o.current));
        assert_eq!(selected(&first), RuntimeChoice::Container);

        let docker = all_three(Some(Flavor::Docker));
        assert_eq!(selected(&docker), RuntimeChoice::Docker);
        assert!(docker[2].current && !docker[0].current);

        // Without Apple's container podman comes first; a current one that isn't ready
        // doesn't hold the start.
        let d = det(
            "macos",
            vec![
                info("podman", (6, 2, 0), true),
                info("docker", (29, 1, 0), false),
            ],
        );
        let options = runtime_options(&d, Some(None), Some(Flavor::Docker));
        assert_eq!(selected(&options), RuntimeChoice::Podman);
        assert!(options[2].current && !options[2].ready);

        // Only one installed: it is where the choice starts, and no question.
        let d = det("linux", vec![info("docker", (29, 1, 0), true)]);
        let options = runtime_options(&d, None, None);
        assert_eq!(selected(&options), RuntimeChoice::Docker);
        assert_eq!(
            decide(None, true, &options).unwrap(),
            Decision::Use(RuntimeChoice::Docker)
        );
    }

    #[test]
    fn several_ready_runtimes_are_asked_about_unless_one_is_named_or_nothing_can_be_asked() {
        let first = all_three(None);
        assert_eq!(decide(None, true, &first).unwrap(), Decision::Ask);
        assert_eq!(
            decide(None, false, &first).unwrap(),
            Decision::Use(RuntimeChoice::Container)
        );
        assert_eq!(
            decide(None, false, &all_three(Some(Flavor::Podman))).unwrap(),
            Decision::Use(RuntimeChoice::Podman)
        );
        assert_eq!(
            decide(Some(RuntimeChoice::Docker), true, &first).unwrap(),
            Decision::Use(RuntimeChoice::Docker)
        );

        // Apple's container is no option where it can't run.
        let linux = runtime_options(
            &det("linux", vec![info("podman", (6, 2, 0), true)]),
            None,
            None,
        );
        let err = decide(Some(RuntimeChoice::Container), true, &linux).unwrap_err();
        assert_eq!(err.to_string(), APPLE_HOST_ONLY);

        // The runtime the envs are on isn't left for another unasked.
        let d = det(
            "linux",
            vec![
                info("podman", (6, 2, 0), true),
                info("docker", (29, 1, 0), false),
            ],
        );
        let options = runtime_options(&d, None, Some(Flavor::Docker));
        let err = decide(None, true, &options).unwrap_err().to_string();
        assert!(err.contains("Docker, which runs this machine's envs, is not ready"));
        assert!(err.contains("`luoto setup --runtime podman` moves to another"));
    }

    #[test]
    fn docker_is_an_option_with_what_it_isolates_per_host() {
        let linux = runtime_options(
            &det("linux", vec![info("docker", (29, 1, 0), true)]),
            None,
            None,
        );
        let o = &linux[1];
        assert_eq!(
            (o.runtime.flavor(), o.runtime.name()),
            (Flavor::Docker, "docker")
        );
        assert_eq!(o.setup, "luoto setup --runtime docker");
        assert!(o.ready && o.status == "29.1.0");
        assert!(
            o.description
                .starts_with("containers on this machine's kernel")
        );
        assert!(linux[0].description.contains("where runsc is installed"));

        let mac = all_three(None);
        assert_eq!(mac[0].description, "every container is a VM of its own");
        assert_eq!(
            mac[1].description,
            "every env in luoto's one VM, under gVisor"
        );
        assert!(
            mac[2]
                .description
                .starts_with("containers in the Docker engine's VM")
        );
    }
}
