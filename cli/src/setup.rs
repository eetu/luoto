//! `luoto setup` / `luoto doctor`: detect the host and container runtimes, recommend (and on
//! request install) one, prepare luoto's images, and verify isolation of every env.

use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::config;
use crate::env::{self, Ctx};
use crate::machine;
use crate::names;
use crate::paths::Paths;
use crate::prompt::confirm;
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
    pub package_manager: Option<String>,
    pub wsl: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Recommendation {
    pub summary: String,
    pub reasons: Vec<String>,
    /// Shell command to install (shown first; run only on confirmation).
    pub install: Option<Vec<String>>,
    pub notes: Vec<String>,
}

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
            Err(_) => (
                false,
                "podman installed but no running machine/service (`podman machine start`)".into(),
            ),
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

pub fn os_release(text: &str) -> (Option<String>, Option<String>) {
    let mut id = None;
    let mut like = None;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("ID=") {
            id = Some(v.trim_matches('"').to_string());
        }
        if let Some(v) = line.strip_prefix("ID_LIKE=") {
            like = Some(v.trim_matches('"').to_string());
        }
    }
    (id, like)
}

pub fn package_manager_for(
    os: &str,
    distro: Option<&str>,
    like: Option<&str>,
    has: impl Fn(&str) -> bool,
) -> Option<String> {
    match os {
        "macos" => has("brew").then(|| "brew".into()),
        "windows" => has("winget").then(|| "winget".into()),
        _ => {
            let ids = format!("{} {}", distro.unwrap_or(""), like.unwrap_or(""));
            if ids.contains("debian") || ids.contains("ubuntu") {
                Some("apt".into())
            } else if ids.contains("fedora") || ids.contains("rhel") || ids.contains("centos") {
                Some("dnf".into())
            } else if ids.contains("arch") {
                Some("pacman".into())
            } else if ids.contains("suse") {
                Some("zypper".into())
            } else if ids.contains("alpine") {
                Some("apk".into())
            } else {
                None
            }
        }
    }
}

pub fn detect() -> Detection {
    let os = std::env::consts::OS.to_string();
    let (distro, like) = std::fs::read_to_string("/etc/os-release")
        .map(|t| os_release(&t))
        .unwrap_or((None, None));
    let has = |c: &str| {
        Command::new(c)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
    };
    let runtimes = [(Flavor::Podman, (5, 2, 0)), (Flavor::Docker, (28, 0, 0))]
        .into_iter()
        .filter_map(|(f, min)| probe_runtime(f, min))
        .collect();
    let wsl = (os == "windows")
        .then(|| output("wsl", &["--status"]).unwrap_or_else(|| "not installed".into()));
    Detection {
        package_manager: package_manager_for(&os, distro.as_deref(), like.as_deref(), has),
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

fn cmd(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| w.to_string()).collect()
}

pub fn recommend(d: &Detection) -> Recommendation {
    if let Some(r) = d.runtimes.iter().find(|r| r.reachable && r.version_ok) {
        let mut notes = Vec::new();
        if r.name == "docker" {
            notes.push("Docker Desktop requires a paid subscription for companies above 250 employees or $10M revenue; podman is free.".into());
            if d.os == "linux" {
                notes.push("On Linux there is no VM boundary: prefer rootless podman, or register gVisor with Docker and set `oci_runtime = \"runsc\"` under `[resources]` in each env's config.".into());
            }
        }
        return Recommendation {
            summary: format!("use the installed {} ({})", r.name, r.detail),
            reasons: vec!["a supported runtime is already installed and running".into()],
            install: None,
            notes,
        };
    }
    let install = match (d.os.as_str(), d.package_manager.as_deref()) {
        ("macos", Some("brew")) => Some(cmd(&["brew", "install", "podman"])),
        ("windows", Some("winget")) => {
            Some(cmd(&["winget", "install", "-e", "--id", "RedHat.Podman"]))
        }
        ("linux", Some("apt")) => Some(cmd(&["sudo", "apt-get", "install", "-y", "podman"])),
        ("linux", Some("dnf")) => Some(cmd(&["sudo", "dnf", "install", "-y", "podman"])),
        ("linux", Some("pacman")) => Some(cmd(&["sudo", "pacman", "-S", "--noconfirm", "podman"])),
        ("linux", Some("zypper")) => Some(cmd(&["sudo", "zypper", "install", "-y", "podman"])),
        ("linux", Some("apk")) => Some(cmd(&["sudo", "apk", "add", "podman"])),
        _ => None,
    };
    let mut notes = Vec::new();
    if install.is_none() {
        notes.push(
            "install podman from https://podman.io (no supported package manager found)".into(),
        );
    }
    if d.os == "windows"
        && d.wsl
            .as_deref()
            .is_some_and(|w| w.contains("not installed"))
    {
        notes.push("WSL2 is needed first: run `wsl --install` as administrator and reboot (or use podman's Hyper-V provider).".into());
    }
    if let Some(r) = d.runtimes.iter().find(|r| !r.version_ok) {
        notes.push(format!(
            "{} is too old ({:?}); luoto needs podman ≥ 5.2 or Docker Engine ≥ 28",
            r.name, r.version
        ));
    }
    if let Some(r) = d.runtimes.iter().find(|r| !r.reachable) {
        notes.push(r.detail.clone());
    }
    Recommendation {
        summary: "install podman".into(),
        reasons: vec![
            "free for companies (no Docker Desktop subscription)".into(),
            "rootless by default".into(),
            "luoto gets its own VM with none of your folders mounted".into(),
        ],
        install,
        notes,
    }
}

#[derive(clap::Args)]
pub struct SetupOpts {
    /// Install the recommended runtime with the platform package manager.
    #[arg(long)]
    pub install: bool,
    /// Build luoto's images from this source tree instead of pulling them.
    #[arg(long)]
    pub build: bool,
    /// Run envs on this runtime: `container` (Apple's, on macOS 26 or later on Apple silicon)
    /// or `podman`.
    #[arg(long, value_enum)]
    pub runtime: Option<RuntimeChoice>,
    /// Don't ask first.
    #[arg(long, short)]
    pub yes: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeChoice {
    Container,
    Podman,
}

impl RuntimeChoice {
    pub fn flavor(self) -> Flavor {
        match self {
            RuntimeChoice::Container => Flavor::Apple,
            RuntimeChoice::Podman => Flavor::Podman,
        }
    }
}

const APPLE_HOST_ONLY: &str = "Apple's container needs macOS 26 or later on Apple silicon";

/// Apple's `container` as found: `None` where it can't run, `Some(None)` where it isn't
/// installed.
pub fn probe_apple() -> Option<Option<RuntimeInfo>> {
    machine::apple_host().then(|| probe_runtime(Flavor::Apple, machine::APPLE_MIN))
}

/// What `--runtime podman` looks at: podman alone.
fn podman_only(mut d: Detection) -> Detection {
    d.runtimes.retain(|r| r.name == "podman");
    d
}

/// A runtime setup offers where Apple's `container` runs: its menu row in a terminal, its
/// choice in the UI.
#[derive(Debug, Serialize)]
pub struct RuntimeOption {
    pub runtime: RuntimeChoice,
    pub label: String,
    pub description: String,
    pub recommended: bool,
    /// config.toml names it.
    pub current: bool,
    /// Where the choice starts: the current runtime, else the recommended one.
    pub selected: bool,
    /// The command that sets it up.
    pub setup: String,
}

/// The runtimes setup offers where Apple's `container` runs, the recommended first.
pub fn runtime_options(current: Option<Flavor>) -> Vec<RuntimeOption> {
    let start = if current == Some(Flavor::Podman) {
        RuntimeChoice::Podman
    } else {
        RuntimeChoice::Container
    };
    [
        (
            RuntimeChoice::Container,
            "Apple's container",
            "every container is a VM of its own",
        ),
        (
            RuntimeChoice::Podman,
            "podman",
            "every env in luoto's one VM, under gVisor",
        ),
    ]
    .into_iter()
    .map(|(runtime, label, description)| RuntimeOption {
        runtime,
        label: label.into(),
        description: description.into(),
        recommended: runtime == RuntimeChoice::Container,
        current: current == Some(runtime.flavor()),
        selected: runtime == start,
        setup: format!(
            "luoto setup --runtime {}",
            match runtime {
                RuntimeChoice::Container => "container",
                RuntimeChoice::Podman => "podman",
            }
        ),
    })
    .collect()
}

/// What Apple's `container` lacks before setup can use it.
#[derive(Debug, Serialize)]
pub struct AppleNeed {
    /// The oldest version luoto runs on.
    pub min: String,
    /// The command that installs or upgrades it; `None` without Homebrew.
    pub install: Option<Vec<String>>,
}

/// `None` when `info` (its probe) is installed and new enough.
pub fn apple_need(info: Option<&RuntimeInfo>) -> Option<AppleNeed> {
    if info.is_some_and(|i| i.version_ok) {
        return None;
    }
    let (a, b, c) = machine::APPLE_MIN;
    Some(AppleNeed {
        min: format!("{a}.{b}.{c}"),
        install: machine::apple_install(info.is_some()),
    })
}

/// Setup's choice of runtime where Apple's `container` runs, and what each choice needs.
#[derive(Debug, Serialize)]
pub struct RuntimeOffer {
    pub options: Vec<RuntimeOption>,
    /// Apple's container; `None` when it isn't installed.
    pub apple: Option<RuntimeInfo>,
    pub apple_need: Option<AppleNeed>,
    /// What `--runtime podman` recommends.
    pub podman: Recommendation,
}

/// `None` where Apple's `container` can't run (`apple` from `probe_apple`), and for docker,
/// which only config.toml sets.
pub fn offer(
    d: &Detection,
    apple: Option<Option<RuntimeInfo>>,
    current: Option<Flavor>,
) -> Option<RuntimeOffer> {
    let apple = apple?;
    (current != Some(Flavor::Docker)).then(|| RuntimeOffer {
        options: runtime_options(current),
        apple_need: apple_need(apple.as_ref()),
        apple,
        podman: recommend(&podman_only(d.clone())),
    })
}

/// The install `--install` runs for `runtime`, or for the recommended one.
pub fn install_command(runtime: Option<RuntimeChoice>) -> Result<Vec<String>> {
    let cmd = match runtime {
        Some(RuntimeChoice::Container) => {
            let apple = probe_apple().context(APPLE_HOST_ONLY)?;
            let need = apple_need(apple.as_ref()).context("Apple's container is installed")?;
            return need.install.with_context(|| {
                format!(
                    "install Apple's container {} from https://github.com/apple/container/releases",
                    need.min
                )
            });
        }
        Some(RuntimeChoice::Podman) => recommend(&podman_only(detect())).install,
        None => recommend(&detect()).install,
    };
    cmd.context("nothing to install")
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

/// The runtime to set up on a Mac that runs Apple's `container`: the one asked for, else
/// asked about, else (without a terminal) the configured one or Apple's. `None` for Esc on a
/// first setup.
fn choose(o: &SetupOpts, current: Option<Flavor>) -> Result<Option<Flavor>> {
    Ok(match (o.runtime, current) {
        (Some(RuntimeChoice::Container), _) => Some(Flavor::Apple),
        (Some(RuntimeChoice::Podman), _) => Some(Flavor::Podman),
        // Docker was set by hand; setup doesn't offer it.
        (None, Some(Flavor::Docker)) => Some(Flavor::Docker),
        (None, _) if crate::prompt::interactive() => {
            crate::wizard::pick_runtime(current)?.or(current)
        }
        (None, _) => Some(current.unwrap_or(Flavor::Apple)),
    })
}

/// Install or upgrade Apple's `container` (with `--install`) and start its service; false
/// when the install is left to the user.
fn apple_ready(o: &SetupOpts, info: Option<&RuntimeInfo>) -> Result<bool> {
    if let Some(AppleNeed { min, install }) = apple_need(info) {
        let Some(cmd) = install else {
            bail!(
                "luoto needs Apple's container {min} or later: install it from \
                 https://github.com/apple/container/releases, then `luoto setup --runtime container`"
            );
        };
        println!("\nluoto needs Apple's container {min} or later");
        println!("install command: {}", cmd.join(" "));
        if !o.install {
            println!("re-run with `luoto setup --install --runtime container` to run it");
            return Ok(false);
        }
        if !o.yes && !confirm("Run it now?") {
            bail!("not installed");
        }
        let status = Command::new(&cmd[0])
            .args(&cmd[1..])
            .status()
            .context("run installer")?;
        if !status.success() {
            bail!("installer failed");
        }
    }
    let rt = Runtime {
        bin: "container".into(),
        flavor: Flavor::Apple,
        connection: None,
        api: None,
    };
    if !machine::apple_running(&rt) {
        machine::start_apple_service(&rt)?;
    }
    Ok(true)
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
    let paths = Paths::get()?;
    let mut global = config::load_global(&paths)?;
    // `apple` is None where Apple's `container` can't run, Some(None) where it isn't installed.
    let (mut d, apple) =
        crate::progress::wait("looking at this machine's container runtimes", || {
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
    for r in d.runtimes.iter().chain(apple.iter().flatten()) {
        println!(
            "  {:<9} {} {}",
            r.name,
            r.version
                .map(|(a, b, c)| format!("{a}.{b}.{c}"))
                .unwrap_or_else(|| "?".into()),
            r.detail
        );
    }
    if d.runtimes.is_empty() && apple.as_ref().is_none_or(Option::is_none) {
        println!("  no container runtime found");
    }
    let choice = match &apple {
        None if o.runtime == Some(RuntimeChoice::Container) => bail!(APPLE_HOST_ONLY),
        None => o.runtime.map(|_| Flavor::Podman),
        Some(_) => match choose(&o, configured(&global))? {
            Some(c) => Some(c),
            None => {
                println!("nothing set up; `luoto setup` asks again");
                return Ok(ExitCode::SUCCESS);
            }
        },
    };
    let before = configured(&global);
    if before.is_some() && choice.is_some() && choice != before {
        let envs = config::list_envs(&paths)?.len();
        if envs > 0 {
            println!(
                "! {envs} env(s) keep their containers and volumes on {}: work not pulled to \
                 this machine stays there",
                match before {
                    Some(Flavor::Apple) => "container",
                    Some(Flavor::Docker) => "docker",
                    _ => "podman",
                }
            );
        }
    }
    if choice == Some(Flavor::Apple) {
        if !apple_ready(&o, apple.clone().flatten().as_ref())? {
            return Ok(ExitCode::SUCCESS);
        }
        // Podman's VM and gVisor aren't Apple's: each container is a VM of its own.
        global.runtime = Some("container".into());
        global.connection = None;
        global.gvisor = None;
    } else {
        if choice == Some(Flavor::Podman) {
            d = podman_only(d);
            if configured(&global) != Some(Flavor::Podman) {
                global.runtime = Some("podman".into());
            }
        }
        if !podman_ready(&o, &d, &paths, &mut global)? {
            return Ok(ExitCode::SUCCESS);
        }
    }
    finish(o, paths, global, apple.is_some())
}

/// The podman (or docker) half of `setup`: install it with `--install`, then luoto's VM;
/// false when the install is left to the user.
fn podman_ready(
    o: &SetupOpts,
    d: &Detection,
    paths: &Paths,
    global: &mut config::GlobalConfig,
) -> Result<bool> {
    let rec = recommend(d);
    println!("\nrecommendation: {}", rec.summary);
    for r in &rec.reasons {
        println!("  - {r}");
    }
    for n in &rec.notes {
        println!("  ! {n}");
    }
    if let Some(cmd) = &rec.install {
        println!("\ninstall command: {}", cmd.join(" "));
        if !o.install {
            println!("re-run with `luoto setup --install` to run it");
            return Ok(false);
        }
        if !o.yes && !confirm("Run it now?") {
            bail!("not installed");
        }
        let status = Command::new(&cmd[0])
            .args(&cmd[1..])
            .status()
            .context("run installer")?;
        if !status.success() {
            bail!("installer failed");
        }
    }

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
        println!(
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
            println!(
                "\n! gVisor (runsc) is not installed: dev containers share the host kernel. \
                 Install it from https://gvisor.dev and run `luoto setup` again."
            );
        }
    }
    Ok(true)
}

/// Images, the vault and the summary, once the runtime is ready; on a Mac that runs Apple's
/// `container` the summary names the other runtime.
fn finish(
    o: SetupOpts,
    paths: Paths,
    mut global: config::GlobalConfig,
    apple_host: bool,
) -> Result<ExitCode> {
    let rt = Runtime::from_config(&global)?;
    global.runtime.get_or_insert_with(|| rt.bin.clone());
    let mut new_images = true;
    if o.build {
        // Built images replace the release's pinned ones until `images` is removed again.
        let tag = global.images.get_or_insert_with(|| "dev".into()).clone();
        if source_root().is_none() {
            bail!("`--build` needs luoto's source tree; this binary was not built from one");
        }
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
            println!("\nimages present; `luoto setup --build` rebuilds them from source");
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
        println!(
            "\nyour own config for every env goes in {} (copied in on each `up`)",
            crate::ssh::tilde(&home)
        );
    }
    let mut rows = vec![("runtime", runtime_line(&ctx.rt))];
    if apple_host
        && let Some(other) = runtime_options(Some(ctx.rt.flavor))
            .into_iter()
            .find(|o| !o.current)
    {
        rows.push(("change it", other.setup));
    }
    rows.push((
        "next",
        "luoto init [--agent claude], in a project folder".into(),
    ));
    println!("\n{}", crate::prompt::summary("ready", &rows));
    Ok(ExitCode::SUCCESS)
}

/// What `doctor` found, each line printed as it comes; `--report` keeps them.
#[derive(Default)]
struct Checks(Vec<String>);

impl Checks {
    fn say(&mut self, line: String) {
        println!("{line}");
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
        let fix = |upgrade| {
            machine::apple_install(upgrade).map_or_else(
                || "https://github.com/apple/container/releases".to_string(),
                |cmd| format!("`{}`", cmd.join(" ")),
            )
        };
        match ctx.rt.version().ok().and_then(|v| parse_version(&v)) {
            None => {
                out.say(format!(
                    "runtime: Apple's container is not installed; {}",
                    fix(false)
                ));
                return Ok(false);
            }
            Some(v) if v < machine::APPLE_MIN => {
                ok = false;
                out.say(format!(
                    "runtime: Apple's container {}.{}.{} is older than {a}.{b}.{c}; {}",
                    v.0,
                    v.1,
                    v.2,
                    fix(true)
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
    out.say(match crate::ctl::vault_status(&ctx.rt) {
        Ok(v) => format!(
            "vault: running, {}",
            if v.locked { "locked" } else { "unlocked" }
        ),
        Err(_) => "vault: not running (starts with the first `luoto up`)".into(),
    });
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

    fn det(os: &str, runtimes: Vec<RuntimeInfo>, pm: Option<&str>) -> Detection {
        Detection {
            os: os.into(),
            arch: "aarch64".into(),
            distro: None,
            cpus: 8,
            runtimes,
            package_manager: pm.map(str::to_string),
            wsl: None,
        }
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
    fn recommends_install_per_os() {
        let r = recommend(&det("macos", vec![], Some("brew")));
        assert_eq!(r.install.unwrap().join(" "), "brew install podman");
        let r = recommend(&det("windows", vec![], Some("winget")));
        assert!(r.install.unwrap().join(" ").contains("RedHat.Podman"));
        let r = recommend(&det("linux", vec![], Some("dnf")));
        assert_eq!(r.install.unwrap().join(" "), "sudo dnf install -y podman");
        let running = RuntimeInfo {
            name: "docker".into(),
            version: Some((29, 0, 0)),
            version_ok: true,
            reachable: true,
            detail: "docker engine 29".into(),
        };
        let r = recommend(&det("linux", vec![running], Some("apt")));
        assert!(r.install.is_none() && r.notes.iter().any(|n| n.contains("no VM boundary")));
    }

    #[test]
    fn offers_apple_first_and_starts_at_the_current_runtime() {
        let info = |name: &str| RuntimeInfo {
            name: name.into(),
            version: Some((29, 0, 0)),
            version_ok: true,
            reachable: true,
            detail: String::new(),
        };
        let d = det("macos", vec![info("docker")], Some("brew"));
        let apple = || Some(Some(info("container")));
        assert!(offer(&d, None, None).is_none());
        assert!(offer(&d, apple(), Some(Flavor::Docker)).is_none());

        let first = offer(&d, apple(), None).unwrap();
        let picked: Vec<_> = first.options.iter().map(|o| o.selected).collect();
        assert_eq!(picked, [true, false]);
        assert!(first.options[0].recommended && first.apple_need.is_none());
        // The podman choice ignores the running docker.
        assert_eq!(first.podman.summary, "install podman");

        let podman = offer(&d, apple(), Some(Flavor::Podman)).unwrap();
        let o = &podman.options[1];
        assert!(o.selected && o.current && !o.recommended);
        assert_eq!(o.setup, "luoto setup --runtime podman");
    }

    #[test]
    fn distro_package_managers() {
        let (id, like) = os_release("NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\n");
        assert_eq!(
            package_manager_for("linux", id.as_deref(), like.as_deref(), |_| false).as_deref(),
            Some("apt")
        );
        let (id, like) = os_release("ID=fedora\n");
        assert_eq!(
            package_manager_for("linux", id.as_deref(), like.as_deref(), |_| false).as_deref(),
            Some("dnf")
        );
    }
}
