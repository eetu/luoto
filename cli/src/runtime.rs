//! Container runtime driver: shells out to a Docker-compatible CLI (podman or docker) and
//! keeps the per-runtime differences in one place. Everything luoto needs is expressed as a
//! [`RunSpec`] or a network/volume call; nothing else talks to the runtime.

use std::io::Write;
use std::net::Ipv4Addr;
use std::process::{Command, ExitStatus, Stdio};

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::config::GlobalConfig;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flavor {
    Podman,
    Docker,
}

#[derive(Clone, Debug)]
pub struct Runtime {
    pub bin: String,
    pub flavor: Flavor,
    pub connection: Option<String>,
    /// The machine's API socket, used instead of the connection's SSH while it exists.
    pub api: Option<std::path::PathBuf>,
}

#[derive(Default, Clone, Debug)]
pub struct RunSpec {
    pub name: String,
    pub image: String,
    pub hostname: Option<String>,
    /// Networks in order; the first is the primary. `Some(ip)` pins the address.
    pub networks: Vec<(String, Option<Ipv4Addr>)>,
    pub dns: Vec<String>,
    pub add_hosts: Vec<(String, String)>,
    pub env: Vec<(String, String)>,
    /// (source volume or host path, target, read-only)
    pub mounts: Vec<(String, String, bool)>,
    pub ports: Vec<(u16, u16)>,
    pub labels: Vec<(String, String)>,
    pub cap_drop_all: bool,
    pub cap_add: Vec<String>,
    pub entrypoint: Option<String>,
    pub cmd: Vec<String>,
    pub user: Option<String>,
    pub ulimits: Vec<String>,
    pub sysctls: Vec<String>,
    pub tmpfs: Vec<String>,
    pub read_only: bool,
    pub memory: Option<String>,
    pub cpus: Option<f64>,
    /// OCI runtime binary (e.g. gVisor's runsc), and global flags for it.
    pub oci_runtime: Option<String>,
    pub runtime_flags: Vec<String>,
    pub userns: Option<String>,
    /// Podman: map container IDs 0..65536 to this intermediate ID onward, so the container's
    /// root is neither the user that owns podman nor shared with other containers.
    pub id_map: Option<u32>,
    pub restart: Option<String>,
    pub security_opts: Vec<String>,
}

/// `LUOTO_TRACE=1` prints every runtime call: when it started (since the first call) and how
/// long it took. Arguments are safe to show: secrets travel on stdin, never argv.
fn traced<T>(args: &[std::ffi::OsString], f: impl FnOnce() -> T) -> T {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    if std::env::var_os("LUOTO_TRACE").is_none() {
        return f();
    }
    let start = *START.get_or_init(std::time::Instant::now);
    let t = std::time::Instant::now();
    let out = f();
    let mut line: String = args
        .iter()
        .map(|a| a.to_string_lossy().replace('\n', " "))
        .collect::<Vec<_>>()
        .join(" ");
    if line.len() > 110 {
        line.truncate(line.floor_char_boundary(110));
        line.push('…');
    }
    eprintln!(
        "[{:>6.2}s +{:.2}s] {line}",
        (t - start).as_secs_f64(),
        t.elapsed().as_secs_f64()
    );
    out
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn which(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

impl Runtime {
    pub fn from_config(global: &GlobalConfig) -> Result<Self> {
        let bin = match &global.runtime {
            Some(b) => b.clone(),
            None if which("podman") => "podman".into(),
            None if which("docker") => "docker".into(),
            None => {
                bail!("no container runtime found; run `luoto setup` to install podman or docker")
            }
        };
        let flavor = if Self::is_podman(&bin) {
            Flavor::Podman
        } else {
            Flavor::Docker
        };
        let api = (flavor == Flavor::Podman
            && crate::machine::is_luoto(global.connection.as_deref()))
        .then(crate::machine::api_socket)
        .flatten();
        Ok(Runtime {
            bin,
            flavor,
            connection: global.connection.clone(),
            api,
        })
    }

    fn is_podman(bin: &str) -> bool {
        if bin.contains("podman") {
            return true;
        }
        Command::new(bin).arg("--version").output().is_ok_and(|o| {
            String::from_utf8_lossy(&o.stdout)
                .to_lowercase()
                .contains("podman")
        })
    }

    pub fn name(&self) -> &'static str {
        match self.flavor {
            Flavor::Podman => "podman",
            Flavor::Docker => "docker",
        }
    }

    pub fn command(&self) -> Command {
        let mut c = Command::new(&self.bin);
        // The forwarded API socket skips an SSH handshake per call (about 50 ms each) and the
        // VM's sshd limits on parallel connections (port forwards open many).
        if let Some(sock) = self.api.as_ref().filter(|s| s.exists()) {
            c.arg("--url").arg(format!("unix://{}", sock.display()));
            return c;
        }
        if let Some(conn) = &self.connection {
            match self.flavor {
                Flavor::Podman => c.args(["--connection", conn]),
                Flavor::Docker => c.args(["--context", conn]),
            };
        }
        c
    }

    /// Run and capture stdout; stderr becomes the error message.
    pub fn run<I, S>(&self, args: I) -> Result<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        let args: Vec<std::ffi::OsString> =
            args.into_iter().map(|a| a.as_ref().to_owned()).collect();
        let out = traced(&args, || {
            self.command().args(&args).stdin(Stdio::null()).output()
        })
        .with_context(|| format!("run {}", self.bin))?;
        if !out.status.success() {
            let shown: Vec<String> = args
                .iter()
                .take(3)
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            bail!(
                "{} {} failed: {}",
                self.name(),
                shown.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    pub fn succeeds<I, S>(&self, args: I) -> bool
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        let args: Vec<std::ffi::OsString> =
            args.into_iter().map(|a| a.as_ref().to_owned()).collect();
        traced(&args, || {
            self.command()
                .args(&args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        })
    }

    /// Run with `input` on stdin (secrets and control messages never go on argv).
    pub fn run_stdin<I, S>(&self, args: I, input: &[u8]) -> Result<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        let args: Vec<std::ffi::OsString> =
            args.into_iter().map(|a| a.as_ref().to_owned()).collect();
        let out = traced(&args, || -> Result<std::process::Output> {
            let mut child = self
                .command()
                .args(&args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .with_context(|| format!("run {}", self.bin))?;
            child
                .stdin
                .take()
                .context("stdin")?
                .write_all(input)
                .context("write to runtime stdin")?;
            Ok(child.wait_with_output()?)
        })?;
        if !out.status.success() {
            bail!(
                "{}{}",
                String::from_utf8_lossy(&out.stderr).trim(),
                String::from_utf8_lossy(&out.stdout).trim()
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Run attached to the terminal.
    pub fn interactive<I, S>(&self, args: I) -> Result<ExitStatus>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        Ok(self.command().args(args).status()?)
    }

    pub fn version(&self) -> Result<String> {
        Ok(self.run(["--version"])?.trim().to_string())
    }

    pub fn container_state(&self, name: &str) -> Option<String> {
        self.run([
            "container",
            "inspect",
            "--format",
            "{{.State.Status}}",
            name,
        ])
        .ok()
        .map(|s| s.trim().to_string())
    }

    /// State and one label in a single call; None when the container doesn't exist.
    pub fn container_state_label(&self, name: &str, label: &str) -> Option<(String, String)> {
        let out = self
            .run([
                "container",
                "inspect",
                "--format",
                &format!("{{{{.State.Status}}}}\t{{{{index .Config.Labels \"{label}\"}}}}"),
                name,
            ])
            .ok()?;
        let (state, value) = out.trim_end().split_once('\t')?;
        let value = if value == "<no value>" { "" } else { value };
        Some((state.to_string(), value.to_string()))
    }

    pub fn image_exists(&self, image: &str) -> bool {
        self.succeeds(["image", "inspect", image])
    }

    pub fn network_exists(&self, name: &str) -> bool {
        self.succeeds(["network", "inspect", name])
    }

    pub fn volume_exists(&self, name: &str) -> bool {
        self.succeeds(["volume", "inspect", name])
    }

    /// Create the volume unless it exists; true when it was created.
    pub fn create_volume(&self, name: &str, labels: &[(String, String)]) -> Result<bool> {
        if self.volume_exists(name) {
            return Ok(false);
        }
        let mut args = vec!["volume".to_string(), "create".into()];
        for (k, v) in labels {
            args.push("--label".into());
            args.push(format!("{k}={v}"));
        }
        args.push(name.into());
        self.run(args).map(|_| true)
    }

    /// Every subnet in use by any network (to pick a free one).
    pub fn used_subnets(&self) -> Result<Vec<String>> {
        let names = self.run(["network", "ls", "--format", "{{.Name}}"])?;
        let names: Vec<&str> = names
            .lines()
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .collect();
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let mut args = vec!["network", "inspect"];
        args.extend(names);
        let v: Value = serde_json::from_str(&self.run(args)?).context("network inspect JSON")?;
        let mut out = Vec::new();
        for net in v.as_array().into_iter().flatten() {
            for s in net["subnets"].as_array().into_iter().flatten() {
                if let Some(sub) = s["subnet"].as_str() {
                    out.push(sub.to_string());
                }
            }
            for s in net["IPAM"]["Config"].as_array().into_iter().flatten() {
                if let Some(sub) = s["Subnet"].as_str() {
                    out.push(sub.to_string());
                }
            }
        }
        Ok(out)
    }

    /// A network with no route out. `route_via` installs a default route to that address in
    /// every container on the network (podman); Docker gets it from a helper later.
    pub fn create_internal_network(
        &self,
        name: &str,
        subnet: &str,
        gateway: &str,
        route_via: Option<&str>,
        labels: &[(String, String)],
    ) -> Result<()> {
        if self.network_exists(name) {
            return Ok(());
        }
        let mut args: Vec<String> = vec![
            "network".into(),
            "create".into(),
            "--internal".into(),
            "--subnet".into(),
            subnet.into(),
            "--gateway".into(),
            gateway.into(),
        ];
        match self.flavor {
            Flavor::Podman => {
                args.push("--disable-dns".into());
                if let Some(r) = route_via {
                    args.push("--route".into());
                    args.push(format!("0.0.0.0/0,{r}"));
                }
            }
            Flavor::Docker => {
                for o in [
                    "com.docker.network.bridge.gateway_mode_ipv4=isolated",
                    "com.docker.network.bridge.gateway_mode_ipv6=isolated",
                ] {
                    args.push("-o".into());
                    args.push(o.into());
                }
            }
        }
        for (k, v) in labels {
            args.push("--label".into());
            args.push(format!("{k}={v}"));
        }
        args.push(name.into());
        self.run(args).map(|_| ())
    }

    pub fn create_bridge_network(&self, name: &str, labels: &[(String, String)]) -> Result<()> {
        if self.network_exists(name) {
            return Ok(());
        }
        let mut args: Vec<String> = vec!["network".into(), "create".into()];
        for (k, v) in labels {
            args.push("--label".into());
            args.push(format!("{k}={v}"));
        }
        args.push(name.into());
        self.run(args).map(|_| ())
    }

    pub fn run_args(&self, spec: &RunSpec, create_only: bool) -> Vec<String> {
        let mut a: Vec<String> = vec![if create_only { "create" } else { "run" }.into()];
        if !create_only {
            a.push("-d".into());
        }
        a.push("--name".into());
        a.push(spec.name.clone());
        if let Some(h) = &spec.hostname {
            a.extend(["--hostname".into(), h.clone()]);
        }
        let networks: &[(String, Option<Ipv4Addr>)] = match self.flavor {
            Flavor::Podman => &spec.networks,
            // Docker attaches extra networks with `network connect` before start.
            Flavor::Docker => &spec.networks[..spec.networks.len().min(1)],
        };
        for (net, ip) in networks {
            match (self.flavor, ip) {
                (Flavor::Podman, Some(ip)) => {
                    a.extend(["--network".into(), format!("{net}:ip={ip}")])
                }
                (Flavor::Docker, Some(ip)) => a.extend([
                    "--network".into(),
                    net.clone(),
                    "--ip".into(),
                    ip.to_string(),
                ]),
                (_, None) => a.extend(["--network".into(), net.clone()]),
            }
        }
        for d in &spec.dns {
            a.extend(["--dns".into(), d.clone()]);
        }
        for (h, ip) in &spec.add_hosts {
            a.extend(["--add-host".into(), format!("{h}:{ip}")]);
        }
        for (k, v) in &spec.env {
            a.extend(["-e".into(), format!("{k}={v}")]);
        }
        for (src, dst, ro) in &spec.mounts {
            let host_path =
                src.starts_with('/') || src.starts_with('\\') || src.get(1..3) == Some(":\\");
            if host_path {
                a.extend([
                    "--mount".into(),
                    format!(
                        "type=bind,source={src},target={dst}{}",
                        if *ro { ",readonly" } else { "" }
                    ),
                ]);
            } else {
                a.extend([
                    "-v".into(),
                    format!("{src}:{dst}{}", if *ro { ":ro" } else { "" }),
                ]);
            }
        }
        for (host, cont) in &spec.ports {
            a.extend(["-p".into(), format!("127.0.0.1:{host}:{cont}")]);
        }
        for (k, v) in &spec.labels {
            a.extend(["--label".into(), format!("{k}={v}")]);
        }
        if spec.cap_drop_all {
            a.extend(["--cap-drop".into(), "ALL".into()]);
        }
        for c in &spec.cap_add {
            a.extend(["--cap-add".into(), c.clone()]);
        }
        for u in &spec.ulimits {
            a.extend(["--ulimit".into(), u.clone()]);
        }
        for s in &spec.sysctls {
            a.extend(["--sysctl".into(), s.clone()]);
        }
        for t in &spec.tmpfs {
            a.extend(["--tmpfs".into(), t.clone()]);
        }
        for s in &spec.security_opts {
            a.extend(["--security-opt".into(), s.clone()]);
        }
        if spec.read_only {
            a.push("--read-only".into());
        }
        if let Some(m) = &spec.memory {
            a.extend(["--memory".into(), m.clone()]);
        }
        if let Some(c) = spec.cpus {
            a.extend(["--cpus".into(), c.to_string()]);
        }
        match self.flavor {
            // Podman takes the runtime as a global flag (see `create_and_start`).
            Flavor::Docker => {
                if let Some(r) = &spec.oci_runtime {
                    a.extend(["--runtime".into(), r.clone()]);
                }
            }
            Flavor::Podman => {
                if let Some(u) = &spec.userns {
                    a.extend(["--userns".into(), u.clone()]);
                }
                if let Some(start) = spec.id_map {
                    let map = format!("0:{start}:{}", crate::machine::ID_RANGE);
                    a.extend(["--uidmap".into(), map.clone(), "--gidmap".into(), map]);
                }
            }
        }
        if let Some(r) = &spec.restart {
            a.extend(["--restart".into(), r.clone()]);
        }
        if let Some(u) = &spec.user {
            a.extend(["--user".into(), u.clone()]);
        }
        if let Some(e) = &spec.entrypoint {
            a.extend(["--entrypoint".into(), e.clone()]);
        }
        a.push(spec.image.clone());
        a.extend(spec.cmd.iter().cloned());
        a
    }

    pub fn create_and_start(&self, spec: &RunSpec) -> Result<()> {
        match self.flavor {
            Flavor::Podman if spec.oci_runtime.is_some() => self.run_on_runtime(spec),
            Flavor::Podman => self.run(self.run_args(spec, false)).map(|_| ()),
            Flavor::Docker => {
                self.run(self.run_args(spec, true))?;
                for (net, ip) in spec.networks.iter().skip(1) {
                    let mut a = vec!["network".to_string(), "connect".into()];
                    if let Some(ip) = ip {
                        a.extend(["--ip".into(), ip.to_string()]);
                    }
                    a.extend([net.clone(), spec.name.clone()]);
                    self.run(a)?;
                }
                self.run(["start", &spec.name]).map(|_| ())
            }
        }
    }

    /// Podman picks the OCI runtime with a global flag, which its remote client (macOS,
    /// Windows) lacks; there the container is created by podman inside luoto's machine. Later
    /// calls (exec, logs, stop, rm) go through the connection as usual: the container keeps
    /// its runtime.
    fn run_on_runtime(&self, spec: &RunSpec) -> Result<()> {
        let mut args: Vec<String> = Vec::new();
        if let Some(r) = &spec.oci_runtime {
            args.extend(["--runtime".into(), r.clone()]);
        }
        for f in &spec.runtime_flags {
            args.extend(["--runtime-flag".into(), f.clone()]);
        }
        args.extend(self.run_args(spec, false));
        if crate::machine::is_luoto(self.connection.as_deref()) {
            let line: Vec<String> = std::iter::once("podman".to_string())
                .chain(args.iter().map(|a| shell_quote(a)))
                .collect();
            crate::machine::ssh(&self.bin, &line.join(" "))?;
            return Ok(());
        }
        if self.connection.is_some() || !cfg!(target_os = "linux") {
            bail!(
                "a container on `{}` needs luoto's own VM (`luoto setup`) or podman on Linux",
                spec.oci_runtime.as_deref().unwrap_or_default()
            );
        }
        self.run(args).map(|_| ())
    }

    pub fn remove_container(&self, name: &str) -> Result<()> {
        if self.container_state(name).is_some()
            && let Err(e) = self.run(["rm", "-f", name])
            // gVisor's network stack takes over the container's interface, so podman's
            // network teardown can fail after the container itself is gone.
            && self.container_state(name).is_some()
        {
            return Err(e);
        }
        Ok(())
    }

    pub fn exec_args(
        &self,
        container: &str,
        user: Option<&str>,
        workdir: Option<&str>,
        env: &[(String, String)],
        interactive: bool,
        tty: bool,
    ) -> Vec<String> {
        let mut a = vec!["exec".to_string()];
        if interactive {
            a.push("-i".into());
        }
        if tty {
            a.push("-t".into());
        }
        if let Some(u) = user {
            a.extend(["-u".into(), u.into()]);
        }
        if let Some(w) = workdir {
            a.extend(["-w".into(), w.into()]);
        }
        for (k, v) in env {
            a.extend(["-e".into(), format!("{k}={v}")]);
        }
        a.push(container.into());
        a
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(flavor: Flavor) -> Runtime {
        Runtime {
            bin: "x".into(),
            flavor,
            connection: None,
            api: None,
        }
    }

    fn spec() -> RunSpec {
        RunSpec {
            name: "luoto-t-gate".into(),
            image: "img".into(),
            networks: vec![
                ("luoto-t".into(), Some(Ipv4Addr::new(10, 213, 1, 2))),
                ("luoto-t-out".into(), None),
            ],
            ports: vec![(5173, 5173)],
            cap_drop_all: true,
            cap_add: vec!["NET_ADMIN".into()],
            userns: Some("keep-id".into()),
            ..Default::default()
        }
    }

    #[test]
    fn podman_pins_ips_inline_and_attaches_all_networks() {
        let a = rt(Flavor::Podman).run_args(&spec(), false).join(" ");
        assert!(a.contains("--network luoto-t:ip=10.213.1.2 --network luoto-t-out"));
        assert!(a.contains("-p 127.0.0.1:5173:5173"));
        assert!(a.contains("--cap-drop ALL --cap-add NET_ADMIN"));
        assert!(a.contains("--userns keep-id"));
    }

    #[test]
    fn docker_creates_with_primary_network_only() {
        let a = rt(Flavor::Docker).run_args(&spec(), true).join(" ");
        assert!(a.starts_with("create "));
        assert!(a.contains("--network luoto-t --ip 10.213.1.2"));
        assert!(!a.contains("luoto-t-out"));
        assert!(!a.contains("--userns"));
    }

    #[test]
    fn id_maps_and_runtimes_go_where_each_runtime_takes_them() {
        let s = RunSpec {
            id_map: Some(65_537),
            oci_runtime: Some("/r/runsc".into()),
            ..spec()
        };
        let podman = rt(Flavor::Podman).run_args(&s, false).join(" ");
        assert!(podman.contains("--uidmap 0:65537:65536 --gidmap 0:65537:65536"));
        // Podman's runtime is a global flag, set by `create_and_start`.
        assert!(!podman.contains("--runtime"));
        let docker = rt(Flavor::Docker).run_args(&s, false).join(" ");
        assert!(docker.contains("--runtime /r/runsc"));
        assert!(!docker.contains("--uidmap"));
    }

    #[test]
    fn shell_quoting_survives_quotes() {
        assert_eq!(shell_quote("a'b c"), r"'a'\''b c'");
    }
}
