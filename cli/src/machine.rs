//! luoto's own podman machine on macOS and Windows (Linux runs containers natively): a VM with
//! none of your folders mounted, a subordinate ID range large enough to give every env's dev
//! container its own, and gVisor for the dev containers. Podman runs one machine at a time, so
//! starting luoto's stops whichever other machine is running, after asking.

use std::io::IsTerminal;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use serde_json::Value;

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

/// What dev containers run on: `runsc` with the flags luoto needs (see [`RUNSC_FLAGS`]).
/// Podman keeps a container's runtime path but not its flags, so a wrapper carries them to
/// every later call (start, exec, kill, delete).
/// The API socket podman forwards from the machine (macOS); None where it isn't a file.
pub fn api_socket() -> Option<std::path::PathBuf> {
    cfg!(target_os = "macos").then(|| {
        std::env::temp_dir()
            .join("podman")
            .join(format!("{NAME}-api.sock"))
    })
}

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

fn run(mut c: Command, what: &str) -> Result<()> {
    let status = c.status().with_context(|| format!("run {what}"))?;
    if !status.success() {
        bail!("{what} failed");
    }
    Ok(())
}

/// Create the machine with no host folders mounted.
pub fn create(bin: &str, cpus: u32, memory_mib: u64) -> Result<()> {
    eprintln!("creating luoto's VM `{NAME}` ({cpus} CPUs, {memory_mib} MiB, no host folders)…");
    let mut c = Command::new(bin);
    c.args(["machine", "init", NAME, "--volume", ""]).args([
        "--cpus",
        &cpus.to_string(),
        "--memory",
        &memory_mib.to_string(),
    ]);
    run(c, "podman machine init")
}

/// Start luoto's machine. Podman runs one machine at a time, so another running one is
/// stopped first: `yes`, or a yes on the terminal, allows that.
pub fn start(bin: &str, yes: bool) -> Result<()> {
    if running(bin) {
        return Ok(());
    }
    if let Some((other, _)) = machines(bin).into_iter().find(|(n, r)| *r && n != NAME) {
        let ok = yes
            || (std::io::stdin().is_terminal()
                && crate::commands::confirm(&format!(
                    "luoto's VM is stopped and podman runs one machine at a time. Stop `{other}` and start `{NAME}`?"
                )));
        if !ok {
            bail!(
                "luoto's VM is stopped while `{other}` runs; `podman machine stop {other}`, then try again"
            );
        }
        let mut c = Command::new(bin);
        c.args(["machine", "stop", &other]).stdout(Stdio::null());
        run(c, "podman machine stop")?;
    }
    eprintln!("starting luoto's VM…");
    let t = std::time::Instant::now();
    let mut c = Command::new(bin);
    c.args(["machine", "start", NAME]).stdout(Stdio::null());
    run(c, "podman machine start")?;
    eprintln!("luoto's VM is up ({} s)", t.elapsed().as_secs());
    Ok(())
}

pub fn stop(bin: &str) -> Result<()> {
    let mut c = Command::new(bin);
    c.args(["machine", "stop", NAME]).stdout(Stdio::null());
    run(c, "podman machine stop")
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
    eprintln!("installing gVisor {GVISOR_RELEASE} in luoto's VM…");
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
    .context("install gVisor")?;
    write_wrapper(bin)
}

fn write_wrapper(bin: &str) -> Result<()> {
    let script = runsc_wrapper(&format!("{GVISOR_DIR}/runsc"));
    ssh(
        bin,
        &format!(
            "printf %s '{}' | sudo tee {} >/dev/null && sudo chmod 755 {}",
            script.replace('\'', "'\\''"),
            runsc_path(),
            runsc_path()
        ),
    )
    .context("install the runsc wrapper")?;
    Ok(())
}

/// Host folders mounted into the machine (none, for luoto's own).
pub fn host_mounts(bin: &str) -> Result<Vec<String>> {
    let out = ssh(bin, "findmnt -rn -o TARGET,FSTYPE")?;
    Ok(out
        .lines()
        .filter_map(|l| l.split_once(' '))
        .filter(|(_, fs)| {
            matches!(*fs, "virtiofs" | "9p" | "v9fs" | "drvfs") || fs.starts_with("fuse.sshfs")
        })
        .map(|(t, _)| t.to_string())
        .collect())
}
