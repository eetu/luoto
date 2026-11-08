//! `luoto export` and `luoto import`: an env moved to another luoto (a release and a source
//! build are separate instances in one VM, `names::instance`) or another machine, as one file
//! (`archive.rs`). Each volume streams through a container in the env's user namespace
//! (`env::dev_id_map`), so the archive holds the container's own IDs and the new volumes get
//! the new env's, whatever subnet each env has; nothing of a volume is unpacked on the host.
//! Secret values, the CA and the vault token don't move: import makes a new CA and token, and
//! the config's refs are read on this machine at `up`.

use std::collections::BTreeSet;
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
    let tar: &[&str] = if write {
        &["tar", "-x", "--numeric-owner", "-f", "-", "-C", MOUNT]
    } else {
        &["tar", "-c", "-f", "-", "-C", MOUNT, "."]
    };
    a.extend(tar.iter().map(|s| s.to_string()));
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

    fn close(&mut self, part: Part, w: Box<dyn Write>) -> Result<()> {
        // Its end of input: tar finishes.
        drop(w);
        let (ok, said) = self.wait();
        if !ok {
            bail!("writing the {} volume failed: {said}", part.label());
        }
        if !said.is_empty() {
            eprintln!("note: tar, writing the {}: {said}", part.label());
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
        for key in ["credentials", "sandbox_secrets"] {
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

/// What the archive is and what importing it as `name` reads on this machine.
fn describe(path: &Path, head: &Head, name: &str, cfg: &EnvConfig) {
    let m = &head.manifest;
    println!(
        "{}: env `{}`, exported by {} {} at {}",
        path.display(),
        display(&m.env),
        display(&m.instance),
        display(&m.luoto),
        display(&m.created)
    );
    let parts: Vec<&str> = m.parts.iter().map(|p| p.label()).collect();
    println!("  holds      {}", parts.join(", "));
    if !m.parts.contains(&Part::Home) {
        println!(
            "  home       not in it: `up` makes a new one, and installs agents and toolchains"
        );
    }
    let ws = &cfg.workspace;
    match (&ws.dir, &ws.url) {
        (Some(d), _) => println!(
            "  folder     {}{}",
            display(d),
            if workspace::canonical(d).is_ok() {
                ""
            } else {
                " (not on this machine)"
            }
        ),
        (None, Some(u)) => println!("  remote     {}", display(u)),
        _ => {}
    }
    let refs = secret_refs(&head.config);
    let az = cfg
        .credentials
        .azure
        .as_ref()
        .is_some_and(|a| a.client_secret.is_none());
    if refs.is_empty() && !az {
        println!("  secrets    none");
    } else {
        println!("  secrets    read on this machine at `up`, from:");
        for (key, r) in &refs {
            println!("    {} = {}", display(key), display(r));
        }
        if az {
            println!("    credentials.azure: your `az` login here");
        }
    }
    println!(
        "  becomes    env `{name}` of {}, with a CA and vault token of its own",
        names::instance()
    );
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

/// The imported env's state and config, once its volumes are written: its own octet, a new
/// vault token and CA. The config goes last: with it, the env exists.
fn settle(ctx: &Ctx, name: &str, octet: u8, head: &Head, config: &str) -> Result<()> {
    let m = &head.state;
    let s = EnvState {
        seeded: m.seeded,
        repos: m.repos.clone(),
        ..EnvState::fresh(octet, m.home.clone())
    };
    s.save(&ctx.paths, name)?;
    if let Some(p) = &head.project {
        write_private(&project::snapshot_path(ctx, name), p.as_bytes())?;
    }
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
    if let Some(p) = &head.project {
        project::parse(p).context("its accepted luoto.toml")?;
    }
    describe(&path, &head, &name, &cfg.cfg);
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
    let octet = state::allocate_octet(&ctx)?;
    let dir = ctx.paths.env_state(&name);
    write_private(&dir.join(PARTIAL), path.display().to_string().as_bytes())?;
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
    let done = read.and_then(|()| settle(&ctx, &name, octet, &head, &cfg.doc.to_string()));
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
