//! `luoto setup` / `luoto doctor`: detect the host and container runtimes, recommend (and on
//! request install) one, prepare luoto's images, and verify isolation of every env.

use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};

use anyhow::{Context, Result, bail};
use serde::Serialize;

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

fn probe_runtime(flavor: Flavor, min: (u32, u32)) -> Option<RuntimeInfo> {
    let rt = Runtime {
        bin: match flavor {
            Flavor::Podman => "podman",
            Flavor::Docker => "docker",
        }
        .into(),
        flavor,
        connection: None,
        api: None,
    };
    let version = parse_version(&rt.version().ok()?);
    let version_ok = version.is_some_and(|(a, b, _)| (a, b) >= min);
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
    let runtimes = [(Flavor::Podman, (5, 2)), (Flavor::Docker, (28, 0))]
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
    #[arg(long, short)]
    pub yes: bool,
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
    for (target, comp) in [("gate", "gate"), ("vault", "vault"), ("tools", "tools")] {
        let status =
            crate::progress::step(&format!("building {}", names::image(comp, tag)), || {
                crate::progress::tool(
                    rt,
                    [
                        "build",
                        "-f",
                        &root.join("Containerfile").to_string_lossy(),
                        "--target",
                        target,
                        "-t",
                        &names::image(comp, tag),
                        &root.to_string_lossy(),
                    ],
                    &|_| {},
                )
            })?;
        if !status.success() {
            bail!("building {comp} failed");
        }
    }
    let status = crate::progress::step(&format!("building {}", names::image("base", tag)), || {
        crate::progress::tool(
            rt,
            [
                "build",
                "-f",
                &root.join("image").join("Containerfile").to_string_lossy(),
                "-t",
                &names::image("base", tag),
                &root.join("image").to_string_lossy(),
            ],
            &|_| {},
        )
    })?;
    if !status.success() {
        bail!("building the base image failed");
    }
    Ok(())
}

pub fn setup(o: SetupOpts) -> Result<ExitCode> {
    let paths = Paths::get()?;
    let mut global = config::load_global(&paths)?;
    let d = crate::progress::wait("looking at this machine's container runtimes", detect);
    println!(
        "host: {} {}{}",
        d.os,
        d.arch,
        d.distro
            .as_deref()
            .map(|s| format!(" ({s})"))
            .unwrap_or_default()
    );
    for r in &d.runtimes {
        println!(
            "  {:<7} {} {}",
            r.name,
            r.version
                .map(|(a, b, c)| format!("{a}.{b}.{c}"))
                .unwrap_or_else(|| "?".into()),
            r.detail
        );
    }
    if d.runtimes.is_empty() {
        println!("  no container runtime found");
    }
    let rec = recommend(&d);
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
            return Ok(ExitCode::SUCCESS);
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

    let rt = Runtime::from_config(&global)?;
    if rt.flavor == Flavor::Podman && machine::supported() {
        // Envs run in luoto's own VM: none of your folders, an ID range per env, gVisor.
        if !machine::exists(&rt.bin) {
            let memory = machine::host_memory_mib().map_or(4096, |m| (m / 4).clamp(4096, 16_384));
            let cpus = u32::try_from(d.cpus / 2).unwrap_or(2).max(2);
            machine::create(&rt.bin, cpus, memory)?;
        }
        machine::start(&rt.bin, o.yes)?;
        let mounts = crate::progress::wait("checking luoto's VM", || {
            machine::prepare(&rt.bin)?;
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
    println!("\nready. Next, in a project folder: luoto init [--agent claude]");
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
            Ok(m) if m.is_empty() => {
                out.say("VM: luoto's own, none of your folders mounted".into())
            }
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
    out.say(format!(
        "runtime: {} ({})",
        ctx.rt.name(),
        ctx.rt.version().unwrap_or_else(|e| format!("error: {e}"))
    ));
    out.say(match &ctx.global.gvisor {
        Some(p) => format!("gVisor: {p} (dev containers run on it unless an env opts out)"),
        None => "gVisor: not set up; dev containers share the VM's kernel".into(),
    });
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
    let probe = crate::progress::wait("starting a probe for the self-tests", || {
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
