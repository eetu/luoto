//! luoto's own podman machine on macOS and Windows (Linux runs containers natively): a VM with
//! none of your folders mounted but luoto's shares folder (read-only), a subordinate ID range large enough to give every env's dev
//! container its own, and gVisor for the dev containers. Podman runs one machine at a time, so
//! starting luoto's stops whichever other machine is running, after asking.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::runtime::Runtime;

/// The machine (and podman connection) luoto creates and uses.
pub const NAME: &str = "luoto";

/// gVisor release installed into the machine; bump deliberately (it is in the trusted base).
pub const GVISOR_RELEASE: &str = "20261019.0";
/// Where the release is unpacked inside the machine; `runsc` looks for its helpers beside it.
pub const GVISOR_DIR: &str = "/usr/local/lib/gvisor";

/// IDs per container user namespace, and how many such ranges the machine's user gets.
pub const ID_RANGE: u32 = 65_536;
const ID_RANGES: u32 = 512;

/// podman machine is how luoto gets a VM; Linux hosts run containers without one.
pub fn supported() -> bool {
    cfg!(any(target_os = "macos", target_os = "windows"))
}

/// Whether `connection` is luoto's machine (configured by [`prepare`]).
pub fn is_luoto(connection: Option<&str>) -> bool {
    connection == Some(NAME)
}

/// Whether the runtime is luoto's VM and the VM is stopped, so nothing in it can be asked
/// about.
pub fn stopped(rt: &Runtime) -> bool {
    is_luoto(rt.connection.as_deref()) && !running(&rt.bin)
}

/// Whether the runtime is luoto's VM and the VM was deleted, taking every env's containers
/// and volumes with it.
pub fn gone(rt: &Runtime) -> bool {
    is_luoto(rt.connection.as_deref()) && !exists(&rt.bin)
}

/// The oldest Apple `container` luoto runs on.
pub const APPLE_MIN: (u32, u32, u32) = (1, 7, 1);

/// Whether Apple's `container` can run here: macOS 26 or later on Apple silicon (also for an
/// Intel build of luoto under Rosetta).
pub fn apple_host() -> bool {
    let read = |cmd: &str, args: &[&str]| {
        Command::new(cmd)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    };
    cfg!(target_os = "macos")
        && read("sysctl", &["-n", "hw.optional.arm64"]).as_deref() == Some("1")
        && read("sw_vers", &["-productVersion"]).is_some_and(|v| macos_major(&v) >= Some(26))
}

fn macos_major(version: &str) -> Option<u32> {
    version.split('.').next()?.trim().parse().ok()
}

/// The command that installs Apple's `container` (or upgrades an older one), where Homebrew
/// is there.
pub fn apple_install(upgrade: bool) -> Option<Vec<String>> {
    let has_brew = Command::new("brew")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    let verb = if upgrade { "upgrade" } else { "install" };
    has_brew.then(|| vec!["brew".into(), verb.into(), "container".into()])
}

/// Apple's `container` needs its system service, not a VM: started here when it isn't
/// running.
pub fn ensure_apple_service(rt: &Runtime) -> Result<()> {
    if apple_running(rt) {
        return Ok(());
    }
    start_apple_service(rt)
}

/// Whether Apple's container service runs.
pub fn apple_running(rt: &Runtime) -> bool {
    rt.run(["system", "status"])
        .is_ok_and(|s| apple_service_running(&s))
}

/// Start the service; its first start downloads the kernel every container boots, which
/// `container` would otherwise ask about.
pub fn start_apple_service(rt: &Runtime) -> Result<()> {
    let status = crate::progress::step("starting the container service", || {
        crate::progress::tool(rt, ["system", "start", "--enable-kernel-install"], &|_| {})
    })?;
    if !status.success() {
        bail!("`container system start --enable-kernel-install` failed");
    }
    Ok(())
}

/// Whether `container system status` says the service runs.
fn apple_service_running(status: &str) -> bool {
    status.lines().any(|l| {
        let mut w = l.split_whitespace();
        w.next() == Some("status") && w.next() == Some("running")
    })
}

/// `container build`'s flags sizing its builder VM, which starts with 2 CPUs and 2 GB: too
/// small for luoto's Rust workspace. `just images` computes the same.
pub fn apple_builder() -> [String; 4] {
    let cpus = std::thread::available_parallelism().map_or(4, |n| n.get());
    let gib = host_memory_mib().map_or(8, |m| (m / 1024 / 2).clamp(4, 16));
    [
        "--cpus".into(),
        cpus.to_string(),
        "--memory".into(),
        format!("{gib}g"),
    ]
}

/// The API socket podman forwards from the machine (macOS); None where it isn't a file.
pub fn api_socket() -> Option<std::path::PathBuf> {
    cfg!(target_os = "macos").then(|| {
        std::env::temp_dir()
            .join("podman")
            .join(format!("{NAME}-api.sock"))
    })
}

/// What dev containers run on: `runsc` with the flags luoto needs (see [`RUNSC_FLAGS`]).
/// Podman keeps a container's runtime path but not its flags, so a wrapper carries them to
/// every later call (start, exec, kill, delete).
pub fn runsc_path() -> String {
    format!("{GVISOR_DIR}/luoto-runsc")
}

/// Rootless runsc can't create cgroups; gVisor ignores setuid bits (sudo) unless allowed; and
/// its root-filesystem overlay would drop writes (`sudo apt install …`) on every stop and leave
/// a backing file that blocks the next start, so the container keeps its own writable layer.
pub const RUNSC_FLAGS: &str = "--ignore-cgroups --allow-suid --overlay2=none";

/// The wrapper script around `runsc` at `runsc`.
pub fn runsc_wrapper(runsc: &str) -> String {
    format!("#!/bin/sh\nexec {runsc} {RUNSC_FLAGS} \"$@\"\n")
}

/// Intermediate ID where the dev container of env `octet` starts its user namespace: each env
/// gets its own range, and none maps to the machine user that owns podman.
pub fn dev_id_start(octet: u8) -> u32 {
    1 + u32::from(octet) * ID_RANGE
}

fn machines(bin: &str) -> Vec<(String, bool)> {
    let Ok(out) = Command::new(bin)
        .args(["machine", "ls", "--format", "json"])
        .output()
    else {
        return Vec::new();
    };
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|m| {
                    let name = m.get("Name")?.as_str()?.trim_end_matches('*').to_string();
                    let running = m.get("Running").and_then(Value::as_bool).unwrap_or(false);
                    Some((name, running))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The host's RAM, to size the VM (macOS and Windows; elsewhere luoto creates no VM).
pub fn host_memory_mib() -> Option<u64> {
    let out = if cfg!(target_os = "macos") {
        Command::new("sysctl")
            .args(["-n", "hw.memsize"])
            .output()
            .ok()?
    } else if cfg!(target_os = "windows") {
        Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory",
            ])
            .output()
            .ok()?
    } else {
        return None;
    };
    let bytes: u64 = String::from_utf8_lossy(&out.stdout).trim().parse().ok()?;
    Some(bytes / (1024 * 1024))
}

pub fn exists(bin: &str) -> bool {
    machines(bin).iter().any(|(n, _)| n == NAME)
}

pub fn running(bin: &str) -> bool {
    machines(bin).iter().any(|(n, r)| n == NAME && *r)
}

/// Run `c`, a `podman machine` command: what it prints stays off the terminal, but for its
/// last lines when it fails (`o` and `--verbose` show it as it comes).
fn run(c: Command, what: &str) -> Result<()> {
    if !crate::progress::host(c)?.success() {
        bail!("{what} failed");
    }
    Ok(())
}

/// Create the machine with no host folders mounted.
pub fn create(bin: &str, cpus: u32, memory_mib: u64) -> Result<()> {
    let mut c = Command::new(bin);
    c.args(["machine", "init", NAME, "--volume", ""]).args([
        "--cpus",
        &cpus.to_string(),
        "--memory",
        &memory_mib.to_string(),
    ]);
    crate::progress::step(
        &format!("creating luoto's VM `{NAME}` ({cpus} CPUs, {memory_mib} MiB, no host folders)"),
        || run(c, "podman machine init"),
    )
}

/// Start luoto's machine. Podman runs one machine at a time, so another running one is
/// stopped first: `yes`, or a yes on the terminal, allows that.
pub fn start(bin: &str, yes: bool) -> Result<()> {
    let all = machines(bin);
    if all.iter().any(|(n, r)| n == NAME && *r) {
        return Ok(());
    }
    if !all.iter().any(|(n, _)| n == NAME) {
        bail!("luoto's VM `{NAME}` is gone: `luoto setup` creates it again");
    }
    if let Some((other, _)) = all.into_iter().find(|(n, r)| *r && n != NAME) {
        let ok = yes
            || crate::prompt::confirm(&format!(
                "luoto's VM is stopped and podman runs one machine at a time. Stop `{other}` and start `{NAME}`?"
            ));
        if !ok {
            bail!(
                "luoto's VM is stopped while `{other}` runs; `podman machine stop {other}`, then try again"
            );
        }
        let mut c = Command::new(bin);
        c.args(["machine", "stop", &other]);
        crate::progress::step(&format!("stopping `{other}`"), || {
            run(c, "podman machine stop")
        })?;
    }
    let mut c = Command::new(bin);
    c.args(["machine", "start", NAME]);
    crate::progress::step("starting luoto's VM", || run(c, "podman machine start"))
}

pub fn stop(bin: &str) -> Result<()> {
    let mut c = Command::new(bin);
    c.args(["machine", "stop", NAME]);
    crate::progress::wait("stopping luoto's VM", || run(c, "podman machine stop"))
}

/// Delete the machine with everything in it, and its podman connections.
pub fn remove(bin: &str) -> Result<()> {
    let mut c = Command::new(bin);
    c.args(["machine", "rm", "-f", NAME]);
    crate::progress::wait("removing luoto's VM", || run(c, "podman machine rm"))
}

/// The machine's state and size in a line, from `podman machine inspect`.
pub fn info(bin: &str) -> Option<String> {
    let out = Command::new(bin)
        .args(["machine", "inspect", NAME])
        .stdin(Stdio::null())
        .output()
        .ok()?;
    describe(&serde_json::from_slice(&out.stdout).ok()?)
}

fn describe(v: &Value) -> Option<String> {
    let m = v.as_array()?.first()?;
    let r = &m["Resources"];
    let n = |v: &Value| v.as_u64().map_or_else(|| "?".into(), |n| n.to_string());
    Some(format!(
        "{}, {} CPUs, {} MiB memory, {} GiB disk, {}",
        m["State"].as_str().unwrap_or("?"),
        n(&r["CPUs"]),
        n(&r["Memory"]),
        n(&r["DiskSize"]),
        if m["Rootful"].as_bool() == Some(true) {
            "rootful"
        } else {
            "rootless"
        }
    ))
}

/// The machine's disk file and the bytes it takes on this machine's disk: a sparse file takes
/// what was written to it and not trimmed since, however little the VM still uses. None where
/// podman's config for the machine doesn't name the file, or off unix (Windows' WSL and
/// Hyper-V disks are no sparse files).
pub fn disk_file(bin: &str) -> Option<(PathBuf, u64)> {
    let out = Command::new(bin)
        .args(["machine", "inspect", NAME])
        .stdin(Stdio::null())
        .output()
        .ok()?;
    let v: Value = serde_json::from_slice(&out.stdout).ok()?;
    let dir = v.as_array()?.first()?["ConfigDir"]["Path"].as_str()?;
    let config = std::fs::read(Path::new(dir).join(format!("{NAME}.json"))).ok()?;
    let path = PathBuf::from(image_path(&serde_json::from_slice(&config).ok()?)?);
    allocated(&path).map(|n| (path, n))
}

/// The disk image in podman's config for a machine (`<config dir>/<name>.json`).
fn image_path(config: &Value) -> Option<&str> {
    config["ImagePath"]["Path"].as_str()
}

#[cfg(unix)]
fn allocated(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| m.blocks() * 512)
}

#[cfg(not(unix))]
fn allocated(_: &Path) -> Option<u64> {
    None
}

/// Tell the VM's disk which blocks its filesystems no longer use, so the disk file on this
/// machine can shrink: without it the file keeps every block ever written to it.
pub fn trim(bin: &str) -> Result<()> {
    ssh(bin, "sudo fstrim -a")
        .map(drop)
        .context("trim luoto's VM disk")
}

/// Run a shell command inside the machine as its user; returns stdout.
pub fn ssh(bin: &str, script: &str) -> Result<String> {
    let out = Command::new(bin)
        .args(["machine", "ssh", NAME, script])
        .stdin(Stdio::null())
        .output()
        .context("podman machine ssh")?;
    if !out.status.success() {
        bail!(
            "in luoto's VM: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Give the machine's user enough subordinate IDs for a range per env, and install gVisor.
pub fn prepare(bin: &str) -> Result<()> {
    let count = ID_RANGE * ID_RANGES;
    ssh(
        bin,
        &format!(
            "set -e; u=$(id -un); want=\"$u:100000:{count}\"; \
             if [ \"$(cat /etc/subuid)\" != \"$want\" ] || [ \"$(cat /etc/subgid)\" != \"$want\" ]; then \
               echo \"$want\" | sudo tee /etc/subuid /etc/subgid >/dev/null; podman system migrate; \
             fi"
        ),
    )
    .context("configure subordinate IDs")?;
    let have = ssh(
        bin,
        &format!("{GVISOR_DIR}/runsc --version 2>/dev/null | head -1"),
    )
    .unwrap_or_default();
    if have.contains(&format!("release-{GVISOR_RELEASE}")) {
        return write_wrapper(bin);
    }
    crate::progress::step(
        &format!("installing gVisor {GVISOR_RELEASE} in luoto's VM"),
        || {
            ssh(
                bin,
                &format!(
                    "set -e; d=$(mktemp -d); cd \"$d\"; \
                     u=https://storage.googleapis.com/gvisor/releases/release/{GVISOR_RELEASE}/$(uname -m); \
                     curl -fsSLO \"$u/gvisor.tar.bz2\"; curl -fsSLO \"$u/gvisor.tar.bz2.sha512\"; \
                     sha512sum -c gvisor.tar.bz2.sha512 >/dev/null; \
                     sudo rm -rf {GVISOR_DIR}; sudo mkdir -p {GVISOR_DIR}; \
                     sudo tar xjf gvisor.tar.bz2 -C {GVISOR_DIR}; cd /; rm -rf \"$d\""
                ),
            )
        },
    )
    .context("install gVisor")?;
    write_wrapper(bin)
}

fn write_wrapper(bin: &str) -> Result<()> {
    let script = runsc_wrapper(&format!("{GVISOR_DIR}/runsc"));
    ssh(
        bin,
        &format!(
            "printf %s {} | sudo tee {} >/dev/null && sudo chmod 755 {}",
            crate::text::sh_quote(&script),
            runsc_path(),
            runsc_path()
        ),
    )
    .context("install the runsc wrapper")?;
    Ok(())
}

/// Host folders mounted into the machine, but luoto's read-only shares folder.
pub fn host_mounts(bin: &str) -> Result<Vec<String>> {
    let out = ssh(bin, "findmnt -rn -o TARGET,FSTYPE,OPTIONS")?;
    Ok(foreign_mounts(&out))
}

/// The host folders among `findmnt -rn -o TARGET,FSTYPE,OPTIONS` lines, but the shares
/// folder mounted read-only.
fn foreign_mounts(findmnt: &str) -> Vec<String> {
    findmnt
        .lines()
        .filter_map(|l| {
            let mut f = l.split(' ');
            Some((f.next()?, f.next()?, f.next().unwrap_or("")))
        })
        .filter(|(_, fs, _)| {
            matches!(*fs, "virtiofs" | "9p" | "v9fs" | "drvfs") || fs.starts_with("fuse.sshfs")
        })
        .filter(|(t, _, opts)| !(*t == SHARES_IN_VM && opts.split(',').any(|o| o == "ro")))
        .map(|(t, _, _)| t.to_string())
        .collect()
}

/// The one folder of the host the machine mounts, read-only: the shares (`shares.rs`), as
/// its tag and where it is inside.
pub const SHARES_TAG: &str = "luoto-shares";
pub const SHARES_IN_VM: &str = "/var/mnt/luoto-shares";

/// The machine's config file, which podman reads at every start.
fn config_file(bin: &str) -> Option<PathBuf> {
    let out = Command::new(bin)
        .args(["machine", "inspect", NAME])
        .stdin(Stdio::null())
        .output()
        .ok()?;
    let v: Value = serde_json::from_slice(&out.stdout).ok()?;
    let dir = PathBuf::from(v.as_array()?.first()?["ConfigDir"]["Path"].as_str()?);
    let file = format!("{NAME}.json");
    std::iter::once(dir.join(&file))
        .chain(
            std::fs::read_dir(&dir)
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path().join(&file)),
        )
        .find(|p| p.is_file())
}

/// Whether the machine's config attaches the shares folder.
pub fn has_shares(bin: &str) -> bool {
    config_file(bin)
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .is_some_and(|v| shares_entry(&v).is_some())
}

fn shares_entry(config: &Value) -> Option<&Value> {
    config["Mounts"]
        .as_array()?
        .iter()
        .find(|m| m["Tag"] == SHARES_TAG)
}

/// `config` with the shares folder `root` attached, read-only. Refused unless it has the
/// shape luoto knows (a `Mounts` list), so another podman's format isn't guessed at.
fn with_shares(mut config: Value, root: &Path) -> Result<Value> {
    if shares_entry(&config).is_some() {
        return Ok(config);
    }
    let source = root.to_string_lossy().into_owned();
    let mounts = config
        .get_mut("Mounts")
        .and_then(Value::as_array_mut)
        .context(
            "luoto's VM config has no `Mounts` list: this podman keeps its folders elsewhere",
        )?;
    mounts.push(serde_json::json!({
        "OriginalInput": format!("{source}:{SHARES_IN_VM}:ro"),
        "ReadOnly": true,
        "Source": source,
        "Tag": SHARES_TAG,
        "Target": SHARES_IN_VM,
        "Type": "virtiofs",
        "VSockNumber": null,
    }));
    Ok(config)
}

/// Attach the shares folder `root` to the stopped machine: podman attaches what its config
/// names at every start, and has no command that adds a folder later.
pub fn add_shares(bin: &str, root: &Path) -> Result<()> {
    let path = config_file(bin).context("luoto's VM config file not found")?;
    let config: Value = serde_json::from_slice(&std::fs::read(&path)?)
        .with_context(|| format!("read {}", path.display()))?;
    let config = with_shares(config, root)?;
    // Whole or not at all: a half-written file would leave podman unable to start the VM.
    let tmp = path.with_extension("json.luoto");
    std::fs::write(&tmp, serde_json::to_vec(&config)?)
        .and_then(|()| std::fs::rename(&tmp, &path))
        .with_context(|| format!("write {}", path.display()))
}

/// Mount the attached shares folder inside the running machine, read-only and for containers
/// to read (SELinux), at every boot: a systemd unit, written once.
pub fn mount_shares(bin: &str) -> Result<()> {
    ssh(
        bin,
        &format!(
            "set -e; u=$(systemd-escape --path --suffix=mount {SHARES_IN_VM}); \
             f=/etc/systemd/system/$u; \
             want='[Unit]\nDescription=luoto shares\n[Mount]\nWhat={SHARES_TAG}\nWhere={SHARES_IN_VM}\nType=virtiofs\nOptions=ro,nodev,nosuid,noexec,context=system_u:object_r:container_file_t:s0\n[Install]\nWantedBy=multi-user.target'; \
             if [ \"$(cat \"$f\" 2>/dev/null)\" != \"$(printf \"$want\")\" ]; then \
               sudo mkdir -p {SHARES_IN_VM}; printf \"$want\\n\" | sudo tee \"$f\" >/dev/null; \
               sudo systemctl daemon-reload; \
             fi; \
             sudo systemctl enable --now \"$u\" >/dev/null 2>&1"
        ),
    )
    .map(drop)
    .context("mount the shares folder in luoto's VM")
}

/// Give the stopped or running machine the shares folder `root`: attached, the machine
/// restarted (every env in it stops), and mounted. `yes`, or a yes on the terminal, allows
/// the restart; without either, the error names `again`, the command with `--yes`.
pub fn ensure_shares(bin: &str, root: &Path, yes: bool, again: &str) -> Result<()> {
    if has_shares(bin) {
        if running(bin) {
            mount_shares(bin)?;
        }
        return Ok(());
    }
    let ok = yes
        || crate::prompt::confirm(
            "Shares need one read-only folder of this machine in luoto's VM. Adding it restarts \
             the VM: every env in it stops until its next `luoto up`. Add it?",
        );
    if !ok {
        bail!(
            "luoto's VM has no shares folder yet: `{again}` adds it (a VM restart, which stops \
             every env in it)"
        );
    }
    std::fs::create_dir_all(root)?;
    if running(bin) {
        stop(bin)?;
    }
    add_shares(bin, root)?;
    start(bin, yes)?;
    mount_shares(bin)
}

#[cfg(test)]
mod tests {
    #[test]
    fn apple_needs_macos_26() {
        assert_eq!(super::macos_major("26.0"), Some(26));
        assert_eq!(super::macos_major("15.6.1\n"), Some(15));
        assert_eq!(super::macos_major(""), None);
        let status = "FIELD   VALUE\nstatus  running\nclient.version  1.7.1\n";
        assert!(super::apple_service_running(status));
        assert!(!super::apple_service_running("status  stopped\n"));
    }

    #[test]
    fn only_the_read_only_shares_folder_may_be_mounted() {
        let ro = format!("{} virtiofs ro,nosuid,nodev,noexec", super::SHARES_IN_VM);
        let rw = format!("{} virtiofs rw,nosuid", super::SHARES_IN_VM);
        let other = "/Users virtiofs ro";
        assert!(super::foreign_mounts(&format!("/ xfs rw\n{ro}")).is_empty());
        assert_eq!(super::foreign_mounts(&rw), [super::SHARES_IN_VM]);
        assert_eq!(super::foreign_mounts(other), ["/Users"]);
    }

    #[test]
    fn the_shares_folder_joins_the_config_once_and_only_one_luoto_knows() {
        let root = std::path::Path::new("/Users/someone/.local/share/luoto-shares");
        let cfg = serde_json::json!({"Mounts": [], "Name": "luoto"});
        let once = super::with_shares(cfg, root).unwrap();
        let twice = super::with_shares(once.clone(), root).unwrap();
        assert_eq!(once, twice);
        let m = &once["Mounts"][0];
        assert_eq!(
            (
                m["Tag"].as_str(),
                m["Target"].as_str(),
                m["ReadOnly"].as_bool()
            ),
            (
                Some(super::SHARES_TAG),
                Some(super::SHARES_IN_VM),
                Some(true)
            )
        );
        assert!(super::with_shares(serde_json::json!({"Name": "luoto"}), root).is_err());
    }

    #[test]
    fn describes_the_machine_in_a_line_without_its_paths() {
        let v = serde_json::json!([{
            "Name": "luoto", "State": "running", "Rootful": false,
            "Resources": {"CPUs": 6, "Memory": 8192, "DiskSize": 100},
            "ConfigDir": {"Path": "/Users/someone/.config/containers/podman/machine"}
        }]);
        assert_eq!(
            super::describe(&v).unwrap(),
            "running, 6 CPUs, 8192 MiB memory, 100 GiB disk, rootless"
        );
        assert!(super::describe(&serde_json::json!([])).is_none());
    }

    #[test]
    fn the_disk_image_comes_from_podmans_machine_config() {
        // `<config dir>/luoto.json` as podman 5 writes it (trimmed).
        let config = serde_json::json!({
            "ConfigPath": {"Path": "/Users/someone/.config/containers/podman/machine/applehv/luoto.json"},
            "Created": "2026-10-01T09:12:40.123456+03:00",
            "ImagePath": {"Path": "/Users/someone/.local/share/containers/podman/machine/applehv/luoto-arm64.raw"},
            "Name": "luoto",
            "Resources": {"CPUs": 6, "DiskSize": 100, "Memory": 8192, "USBs": []},
            "AppleHypervisor": {"Vfkit": {"Endpoint": "http://localhost:51244"}}
        });
        assert_eq!(
            super::image_path(&config),
            Some("/Users/someone/.local/share/containers/podman/machine/applehv/luoto-arm64.raw")
        );
        assert_eq!(
            super::image_path(&serde_json::json!({"Name": "luoto"})),
            None
        );
    }
}
