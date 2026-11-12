//! `luoto uninstall`: remove what this instance (`names::instance`) made, after one question
//! that lists it: its envs' containers, networks and volumes, the vault, its images, its
//! keychain entries, its config and data folders, and luoto's VM. The other instance shares
//! the VM, so nothing it made is touched, and the VM goes only when nothing but this
//! instance's objects is in it and the other instance isn't set up to use it. Each step
//! reports its result and a failure leaves the rest to run; the binary stays, and the last
//! line says how to remove it.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};

use crate::paths::Paths;
use crate::prompt::confirm;
use crate::release::repo_of;
use crate::runtime::{Flavor, Runtime};
use crate::{config, machine, names, release, ssh, watch};

pub fn uninstall(yes: bool) -> Result<ExitCode> {
    if std::env::var_os("LUOTO_HOME").is_some() {
        bail!(
            "LUOTO_HOME is set, and envs under it share this luoto's vault, images and VM: \
             `luoto rm` them and delete the folder instead"
        );
    }
    let paths = Paths::get()?;
    let plan = crate::progress::wait("listing what it made", || Plan::gather(&paths));
    let binary = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .map_or_else(
            |_| "remove the luoto binary".into(),
            |p| remove_binary_hint(&p),
        );
    if plan.is_empty() {
        let unseen = plan
            .runtime
            .as_ref()
            .err()
            .map(|why| format!(" (the runtime wasn't looked at: {why})"))
            .unwrap_or_default();
        println!(
            "nothing of {}'s is left here{unseen}; the binary: {binary}",
            plan.inst
        );
        return Ok(ExitCode::SUCCESS);
    }
    println!("{}", plan.describe(&paths, &binary));
    if !yes && !confirm("Remove all this?") {
        bail!("nothing removed (`luoto uninstall --yes` skips the question)");
    }
    let failed = plan.carry_out(&paths);
    if failed == 0 {
        println!("\n{} is uninstalled; the binary stays: {binary}", plan.inst);
        Ok(ExitCode::SUCCESS)
    } else {
        println!(
            "\n{failed} step(s) failed, listed above; `luoto uninstall` again tries what is \
             left. The binary stays: {binary}"
        );
        Ok(ExitCode::FAILURE)
    }
}

struct Plan {
    inst: &'static str,
    other: &'static str,
    envs: Vec<String>,
    /// What is in the runtime, or why it wasn't looked at.
    runtime: Result<Inventory, String>,
    keys: Vec<Key>,
    /// Why some keychain entries may not be listed.
    keys_note: Option<String>,
    dirs: Vec<(PathBuf, &'static str)>,
}

struct Inventory {
    rt: Runtime,
    containers: Vec<String>,
    networks: Vec<String>,
    volumes: Vec<String>,
    images: Vec<String>,
    /// The other instance's containers and volumes, which stay.
    theirs: usize,
    vm: Vm,
}

#[derive(Debug, PartialEq)]
enum Vm {
    /// Not luoto's VM that the runtime uses, or none.
    Absent,
    Remove,
    /// Why it stays.
    Keep(String),
}

struct Key {
    account: String,
    /// What a keychain search found; `None` for an account only a config names.
    found: Option<keyring_core::Entry>,
}

impl Plan {
    fn gather(paths: &Paths) -> Self {
        let inst = names::instance();
        let envs = config::list_envs(paths).unwrap_or_default();
        let runtime = inventory(paths, &envs);
        let (keys, keys_note) = keychain(paths, inst);
        let dirs = [
            (
                paths.config.clone(),
                "env configs, config.toml and your files in home/",
            ),
            (
                paths.data.clone(),
                "env state and CAs, luoto's SSH key, events and logs",
            ),
            (
                crate::shares::root()
                    .map(|r| r.join(inst))
                    .unwrap_or_default(),
                "the clones of shared folders",
            ),
        ]
        .into_iter()
        .filter(|(p, _)| p.exists())
        .collect();
        Plan {
            inst,
            other: names::other_instance(),
            envs,
            runtime,
            keys,
            keys_note,
            dirs,
        }
    }

    fn is_empty(&self) -> bool {
        let runtime_empty = self.runtime.as_ref().ok().is_none_or(|i| {
            i.containers.is_empty()
                && i.networks.is_empty()
                && i.volumes.is_empty()
                && i.images.is_empty()
                && i.vm != Vm::Remove
        });
        runtime_empty && self.envs.is_empty() && self.keys.is_empty() && self.dirs.is_empty()
    }

    fn describe(&self, paths: &Paths, binary: &str) -> String {
        let mut out = format!("`{} uninstall` removes what it made here:\n", self.inst);
        let mut line = |what: &str, text: String| out.push_str(&format!("  {what:<11} {text}\n"));
        if !self.envs.is_empty() {
            line(
                "envs",
                format!(
                    "{}, with their workspaces and homes (work not pushed or pulled is lost)",
                    self.envs.join(", ")
                ),
            );
        }
        let mut stays = Vec::new();
        match &self.runtime {
            Ok(i) => {
                if !i.containers.is_empty() {
                    line("containers", i.containers.join(", "));
                }
                for (what, list) in [("networks", &i.networks), ("volumes", &i.volumes)] {
                    if !list.is_empty() {
                        line(what, list.len().to_string());
                    }
                }
                if !i.images.is_empty() {
                    line("images", format!("{} ({})", i.images.len(), image_family()));
                }
                match &i.vm {
                    Vm::Remove => line(
                        "VM",
                        format!("luoto's VM `{}`, with all in it", machine::NAME),
                    ),
                    Vm::Keep(why) => stays.push(format!("luoto's VM `{}`: {why}", machine::NAME)),
                    Vm::Absent if i.theirs > 0 => stays.push(format!(
                        "{}'s {} containers and volumes, and the images they use",
                        self.other, i.theirs
                    )),
                    Vm::Absent => {}
                }
            }
            Err(why) => stays.push(format!(
                "containers, volumes, images and luoto's VM, not looked at: {why}"
            )),
        }
        if !self.keys.is_empty() {
            let names: Vec<String> = self
                .keys
                .iter()
                .map(|k| format!("{}/{}", self.inst, k.account))
                .collect();
            line("keychain", names.join(", "));
        }
        if let Some(note) = &self.keys_note {
            stays.push(format!("keychain entries no config names: {note}"));
        }
        for (dir, holds) in &self.dirs {
            let what = if *dir == paths.config {
                "config"
            } else {
                "data"
            };
            line(what, format!("{} ({holds})", ssh::tilde(dir)));
        }
        out.push_str("It leaves:\n");
        stays.push(
            "your project folders, and the secrets in 1Password, OpenBao or files that your \
             configs refer to"
                .into(),
        );
        if ssh::include_present(paths) {
            stays.push(format!(
                "`{}` in ~/.ssh/config (luoto never edits that file; remove the line)",
                ssh::include_line(paths)
            ));
        }
        stays.push("the tab completion line in your shell's startup file, if you added one".into());
        stays.push(format!("the binary: {binary}"));
        for s in stays {
            out.push_str(&format!("  {s}\n"));
        }
        out
    }

    /// Remove everything listed; the number of steps that failed.
    fn carry_out(&self, paths: &Paths) -> usize {
        let mut failed = 0;
        let mut report = |what: &str, r: Result<String>| match r {
            Ok(done) => crate::progress::say(|| println!("  {what:<11} {done}")),
            Err(e) => {
                failed += 1;
                crate::progress::say(|| println!("  {what:<11} FAILED: {e:#}"));
            }
        };
        println!();
        let _waiting = crate::progress::waiting("removing it");
        match watch::stop(paths) {
            Ok(true) => report("watcher", Ok("stopped".into())),
            Ok(false) => {}
            Err(e) => report("watcher", Err(e)),
        }
        if let Ok(i) = &self.runtime {
            let rt = &i.rt;
            for (what, list, rm) in [
                (
                    "containers",
                    &i.containers,
                    &(|n: &str| rt.remove_container(n)) as &dyn Fn(&str) -> Result<()>,
                ),
                ("networks", &i.networks, &|n| {
                    rt.run(["network", "rm", n]).map(drop)
                }),
                ("volumes", &i.volumes, &|n| {
                    rt.run(["volume", "rm", n]).map(drop)
                }),
                ("images", &i.images, &|n| {
                    let rm: &[&str] = if rt.flavor == Flavor::Apple {
                        &["image", "rm"]
                    } else {
                        &["rmi"]
                    };
                    rt.run(rm.iter().copied().chain([n])).map(drop)
                }),
            ] {
                if !list.is_empty() {
                    report(what, each(list, rm));
                }
            }
            if i.vm == Vm::Remove {
                report("VM", remove_vm(rt));
            }
        }
        if !self.keys.is_empty() {
            report("keychain", remove_keys(self.inst, &self.keys));
        }
        for (dir, _) in &self.dirs {
            let what = if *dir == paths.config {
                "config"
            } else {
                "data"
            };
            report(
                what,
                remove_dir(dir, self.inst).map(|()| format!("{} removed", ssh::tilde(dir))),
            );
        }
        failed
    }
}

/// `rm` on each of `list`: how many went, and an error naming each that didn't.
fn each(list: &[String], rm: &dyn Fn(&str) -> Result<()>) -> Result<String> {
    let failures: Vec<String> = list
        .iter()
        .filter_map(|n| rm(n).err().map(|e| format!("{n}: {e:#}")))
        .collect();
    if failures.is_empty() {
        Ok(format!("{} removed", list.len()))
    } else {
        bail!(
            "{} of {} not removed\n    {}",
            failures.len(),
            list.len(),
            failures.join("\n    ")
        )
    }
}

/// Remove luoto's VM once nothing is left in it: what failed to go stays, and so does the VM.
fn remove_vm(rt: &Runtime) -> Result<String> {
    let left: usize = [
        &["ps", "-a", "--format", "{{.Names}}"][..],
        &["volume", "ls", "--format", "{{.Name}}"],
    ]
    .iter()
    .map(|args| {
        rt.run(*args)
            .map(|o| o.lines().filter(|l| !l.trim().is_empty()).count())
    })
    .sum::<Result<usize>>()?;
    if left > 0 {
        bail!("kept: {left} container(s) or volume(s) are still in it");
    }
    machine::remove(&rt.bin)?;
    Ok(format!("luoto's VM `{}` removed", machine::NAME))
}

fn remove_keys(inst: &str, keys: &[Key]) -> Result<String> {
    let mut removed = 0;
    let mut failures = Vec::new();
    for k in keys {
        let r = match &k.found {
            Some(e) => e.delete_credential(),
            None => keyring::Entry::new(inst, &k.account).and_then(|e| e.delete_credential()),
        };
        match r {
            Ok(()) => removed += 1,
            Err(keyring::Error::NoEntry) => {}
            Err(e) => failures.push(format!("{inst}/{}: {e}", k.account)),
        }
    }
    if failures.is_empty() {
        Ok(format!(
            "{removed} entr{} removed",
            if removed == 1 { "y" } else { "ies" }
        ))
    } else {
        bail!("{}", failures.join("; "))
    }
}

/// Remove `dir`, and its parent when that is the instance's own and left empty (Windows keeps
/// config and data in `…\luoto\config` and `…\luoto\data`).
fn remove_dir(dir: &Path, inst: &str) -> Result<()> {
    std::fs::remove_dir_all(dir)?;
    if let Some(parent) = dir.parent()
        && parent.file_name().is_some_and(|n| n == inst)
    {
        let _ = std::fs::remove_dir(parent);
    }
    Ok(())
}

/// What the runtime holds of this instance's, and whether luoto's VM can go.
fn inventory(paths: &Paths, envs: &[String]) -> Result<Inventory, String> {
    let global =
        config::load_global(paths).map_err(|e| format!("config.toml doesn't load ({e:#})"))?;
    let rt = Runtime::from_config(&global).map_err(|e| format!("{e:#}"))?;
    let in_vm = rt.flavor == Flavor::Podman
        && machine::supported()
        && machine::is_luoto(rt.connection.as_deref());
    if in_vm && !machine::exists(&rt.bin) {
        return Ok(Inventory {
            rt,
            containers: Vec::new(),
            networks: Vec::new(),
            volumes: Vec::new(),
            images: Vec::new(),
            theirs: 0,
            vm: Vm::Absent,
        });
    }
    if in_vm {
        machine::start(&rt.bin, false).map_err(|e| format!("luoto's VM didn't start ({e:#})"))?;
    }
    let expected: BTreeSet<String> = envs.iter().flat_map(|e| own_names(e)).collect();
    let sorted = |kind| {
        objects(&rt, kind)
            .map(|objs| sort(&objs, names::instance(), names::other_instance(), &expected))
            .map_err(|e| format!("{e:#}"))
    };
    let containers = sorted(Kind::Container)?;
    let networks = sorted(Kind::Network)?;
    let volumes = sorted(Kind::Volume)?;
    let listing = if rt.flavor == Flavor::Apple {
        rt.run(["image", "list", "--format", "json"])
            .map(|j| apple_image_listing(&j))
    } else {
        rt.run([
            "images",
            "--digests",
            "--format",
            "{{.Repository}}\t{{.Tag}}\t{{.Digest}}",
        ])
    }
    .map_err(|e| format!("{e:#}"))?;
    let images = image_refs(&listing, &repos());
    let theirs = containers.theirs + volumes.theirs;
    let vm = if in_vm {
        vm_verdict(
            names::other_instance(),
            theirs,
            containers.foreign + volumes.foreign,
            other_uses_vm(),
        )
    } else {
        Vm::Absent
    };
    Ok(Inventory {
        rt,
        containers: containers.mine,
        networks: networks.mine,
        volumes: volumes.mine,
        images,
        theirs,
        vm,
    })
}

/// Whether the other instance's config.toml points at luoto's VM (or can't be read).
fn other_uses_vm() -> bool {
    let Ok(p) = Paths::of(names::other_instance()) else {
        return false;
    };
    match config::load_global(&p) {
        Ok(g) => machine::is_luoto(g.connection.as_deref()),
        Err(_) => p.global_config().exists(),
    }
}

fn vm_verdict(other: &str, theirs: usize, foreign: usize, other_uses: bool) -> Vm {
    if theirs > 0 {
        Vm::Keep(format!(
            "{other}'s envs or vault are in it ({theirs} containers and volumes)"
        ))
    } else if foreign > 0 {
        Vm::Keep(format!(
            "{foreign} container(s) or volume(s) luoto didn't make are in it"
        ))
    } else if other_uses {
        Vm::Keep(format!(
            "{other} is set up to use it (`{other} uninstall` removes it)"
        ))
    } else {
        Vm::Remove
    }
}

/// Every name this instance gives an env's containers, networks and volumes.
fn own_names(env: &str) -> Vec<String> {
    let mut v = vec![
        names::dev(env),
        names::gate(env),
        names::internal_net(env),
        names::egress_net(env),
    ];
    v.extend(["tools", "gate", "work", "home"].map(|w| names::volume(env, w)));
    v
}

#[derive(Clone, Copy)]
enum Kind {
    Container,
    Network,
    Volume,
}

/// A container, network or volume with luoto's labels (empty when it has none).
#[derive(Debug, Clone, PartialEq)]
struct Obj {
    name: String,
    env: String,
    role: String,
}

fn objects(rt: &Runtime, kind: Kind) -> Result<Vec<Obj>> {
    if rt.flavor == Flavor::Apple {
        let list: &[&str] = match kind {
            Kind::Container => &["ls", "-a", "--format", "json"],
            Kind::Network => &["network", "list", "--format", "json"],
            Kind::Volume => &["volume", "ls", "--format", "json"],
        };
        return parse_apple_objects(&rt.run(list)?);
    }
    let (list, inspect, labels): (&[&str], &[&str], &str) = match kind {
        Kind::Container => (
            &["ps", "-a", "--format", "{{.Names}}"],
            &["container", "inspect"],
            ".Config.Labels",
        ),
        Kind::Network => (
            &["network", "ls", "--format", "{{.Name}}"],
            &["network", "inspect"],
            ".Labels",
        ),
        Kind::Volume => (
            &["volume", "ls", "--format", "{{.Name}}"],
            &["volume", "inspect"],
            ".Labels",
        ),
    };
    let names: Vec<String> = rt
        .run(list)?
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect();
    if names.is_empty() {
        return Ok(Vec::new());
    }
    let format = format!(
        "{{{{.Name}}}}\t{{{{index {labels} \"{}\"}}}}\t{{{{index {labels} \"{}\"}}}}",
        names::LABEL_ENV,
        names::LABEL_ROLE
    );
    let mut args: Vec<String> = inspect.iter().map(|s| s.to_string()).collect();
    args.extend(["--format".into(), format]);
    args.extend(names);
    Ok(parse_objects(&rt.run(args)?))
}

fn parse_objects(text: &str) -> Vec<Obj> {
    let label = |s: Option<&str>| {
        s.map(str::trim)
            .filter(|s| *s != "<no value>")
            .unwrap_or("")
            .to_string()
    };
    text.lines()
        .filter_map(|l| {
            let mut f = l.split('\t');
            // Docker names containers `/name`.
            let name = f.next()?.trim().trim_start_matches('/');
            (!name.is_empty()).then(|| Obj {
                name: name.to_string(),
                env: label(f.next()),
                role: label(f.next()),
            })
        })
        .collect()
}

/// Apple's `ls --format json` of containers, networks or volumes: each has its `id` and its
/// `configuration.labels`.
fn parse_apple_objects(json: &str) -> Result<Vec<Obj>> {
    let v: serde_json::Value = serde_json::from_str(json).context("listing JSON")?;
    let label = |o: &serde_json::Value, k: &str| {
        o["configuration"]["labels"][k]
            .as_str()
            .unwrap_or("")
            .to_string()
    };
    Ok(v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|o| {
            let name = o["id"].as_str().filter(|n| !n.is_empty())?;
            Some(Obj {
                name: name.to_string(),
                env: label(o, names::LABEL_ENV),
                role: label(o, names::LABEL_ROLE),
            })
        })
        .collect())
}

/// Apple's `image list --format json` as the (repository, tag, digest) lines `image_refs`
/// reads.
fn apple_image_listing(json: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(json).unwrap_or_default();
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|i| {
            let name = i["configuration"]["name"].as_str()?;
            let digest = i["configuration"]["descriptor"]["digest"]
                .as_str()
                .unwrap_or("");
            // The tag follows the last `:` after the last `/` (a registry may carry a port).
            let slash = name.rfind('/').map_or(0, |p| p + 1);
            let (repo, tag) = match name[slash..].rfind(':') {
                Some(p) => (&name[..slash + p], &name[slash + p + 1..]),
                None => (name, ""),
            };
            Some(format!("{repo}\t{tag}\t{digest}"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Debug, Default, PartialEq)]
struct Sorted {
    /// This instance's: named so with luoto's labels, or with an env's names from this config.
    mine: Vec<String>,
    /// The other instance's.
    theirs: usize,
    /// Neither's.
    foreign: usize,
}

fn sort(objs: &[Obj], inst: &str, other: &str, expected: &BTreeSet<String>) -> Sorted {
    let mut s = Sorted::default();
    for o in objs {
        let labelled = !o.role.is_empty();
        if labelled && names::named_by(other, &o.name, &o.env, &o.role) {
            s.theirs += 1;
        } else if (labelled && names::named_by(inst, &o.name, &o.env, &o.role))
            || expected.contains(&o.name)
        {
            s.mine.push(o.name.clone());
        } else {
            s.foreign += 1;
        }
    }
    s
}

/// The repositories of this instance's images: the release's registry for a release, the
/// local builds for a source build.
fn repos() -> Vec<String> {
    release::COMPONENTS
        .iter()
        .map(|c| repo_of(&release::image(None, c)).to_string())
        .collect()
}

fn image_family() -> String {
    let gate = repo_of(&release::image(None, "gate")).to_string();
    format!("{}*", gate.trim_end_matches("gate"))
}

/// From an `images` listing (repository, tag, digest), a reference to each image of `repos`:
/// by tag, else by digest (a release's images are pulled by digest).
fn image_refs(listing: &str, repos: &[String]) -> Vec<String> {
    let mut out = BTreeSet::new();
    for line in listing.lines() {
        let mut f = line.split('\t').map(str::trim);
        let (Some(repo), tag, digest) = (f.next(), f.next().unwrap_or(""), f.next().unwrap_or(""))
        else {
            continue;
        };
        if !repos.iter().any(|r| r == repo) {
            continue;
        }
        if !tag.is_empty() && tag != "<none>" {
            out.insert(format!("{repo}:{tag}"));
        } else if digest.starts_with("sha256:") {
            out.insert(format!("{repo}@{digest}"));
        }
    }
    out.into_iter().collect()
}

/// This instance's keychain entries: those its configs name, and those a search of the
/// keychain finds under its service (macOS and Linux; Windows' store can't be searched).
fn keychain(paths: &Paths, inst: &str) -> (Vec<Key>, Option<String>) {
    let mut keys: BTreeMap<String, Option<keyring_core::Entry>> = BTreeMap::new();
    for text in config_texts(paths) {
        for account in keyring_accounts(&text, inst) {
            keys.entry(account).or_insert(None);
        }
    }
    let note = match search(inst) {
        Ok(found) => {
            for (account, entry) in found {
                keys.insert(account, Some(entry));
            }
            None
        }
        Err(e) => Some(format!("the keychain can't be searched ({e}); they stay")),
    };
    let keys = keys
        .into_iter()
        .map(|(account, found)| Key { account, found })
        .collect();
    (keys, note)
}

fn search(service: &str) -> Result<Vec<(String, keyring_core::Entry)>, String> {
    if let Err(e) = keyring::Entry::store_status() {
        return Err(e.to_string());
    }
    let spec = HashMap::from([("service", service)]);
    let found = keyring_core::Entry::search(&spec).map_err(|e| e.to_string())?;
    Ok(found
        .into_iter()
        .filter_map(|e| {
            let account = e.get_specifiers().map(|(_, a)| a).or_else(|| {
                e.get_attributes()
                    .ok()
                    .and_then(|a| a.get("username").cloned())
            })?;
            Some((account, e))
        })
        .collect())
}

/// config.toml and every file in envs/ (older formats kept beside an env's file included).
fn config_texts(paths: &Paths) -> Vec<String> {
    let mut files = vec![paths.global_config()];
    if let Ok(rd) = std::fs::read_dir(paths.envs_dir()) {
        files.extend(rd.flatten().map(|e| e.path()));
    }
    files
        .iter()
        .filter_map(|f| std::fs::read_to_string(f).ok())
        .collect()
}

/// The accounts of `keyring:<service>/<account>` refs in `text`.
pub fn keyring_accounts(text: &str, service: &str) -> BTreeSet<String> {
    let needle = format!("keyring:{service}/");
    text.match_indices(&needle)
        .map(|(i, _)| {
            text[i + needle.len()..]
                .chars()
                .take_while(|c| !matches!(c, '"' | '\'' | '`' | '\n' | '\r' | '\t' | ' '))
                .collect::<String>()
        })
        .filter(|a| !a.is_empty())
        .collect()
}

/// How the binary was installed, as what removes it.
fn remove_binary_hint(exe: &Path) -> String {
    let path = exe.display().to_string();
    let lower = path.to_lowercase();
    if lower.contains("/cellar/") || lower.contains("brew/") {
        "`brew uninstall luoto` (then `brew untap eetu/tap`)".into()
    } else if lower.contains("\\scoop\\") {
        "`scoop uninstall luoto` (then `scoop bucket rm luoto`)".into()
    } else if lower.contains("/.cargo/bin/") {
        "`cargo uninstall luoto`".into()
    } else if lower.contains("/target/") {
        format!("a build in your source checkout ({})", ssh::tilde(exe))
    } else {
        format!("delete {}", ssh::tilde(exe))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apple_listings_give_names_labels_and_image_refs() {
        let objs = parse_apple_objects(
            r#"[{"configuration":{"labels":{"luoto.env":"ae","luoto.role":"work"},"name":"luoto-dev-ae-work"},"id":"luoto-dev-ae-work"},
                {"configuration":{"labels":{"com.apple.container.resource.role":"builtin"}},"id":"default"}]"#,
        )
        .unwrap();
        assert_eq!(
            objs,
            vec![
                obj("luoto-dev-ae-work", "ae", "work"),
                obj("default", "", "")
            ]
        );
        let listing = apple_image_listing(
            r#"[{"configuration":{"name":"localhost/luoto-gate:dev","descriptor":{"digest":"sha256:ab"}}},
                {"configuration":{"name":"reg.example:5000/luoto-base","descriptor":{"digest":"sha256:cd"}}}]"#,
        );
        assert_eq!(
            listing,
            "localhost/luoto-gate\tdev\tsha256:ab\nreg.example:5000/luoto-base\t\tsha256:cd"
        );
    }

    fn obj(name: &str, env: &str, role: &str) -> Obj {
        Obj {
            name: name.into(),
            env: env.into(),
            role: role.into(),
        }
    }

    #[test]
    fn each_instance_keeps_to_its_own_objects() {
        let objs = [
            obj("luoto-web", "web", "dev"),
            obj("luoto-web-gate", "web", "gate"),
            obj("luoto-vault", "", "vault"),
            obj("luoto-dev-web", "web", "dev"),
            obj("luoto-dev-web-gate", "web", "gate"),
            obj("luoto-dev-vault", "", "vault"),
            // Labelled, but under no name either instance gives.
            obj("luoto-stray", "web", "dev"),
            // Unlabelled: an env of this config by name, and the user's own.
            obj("luoto-api-home", "", ""),
            obj("postgres", "", ""),
        ];
        let expected: BTreeSet<String> = ["luoto-api-home".to_string()].into();
        let release = sort(&objs, "luoto", "luoto-dev", &expected);
        assert_eq!(
            release.mine,
            [
                "luoto-web",
                "luoto-web-gate",
                "luoto-vault",
                "luoto-api-home"
            ]
        );
        assert_eq!((release.theirs, release.foreign), (3, 2));
        let dev = sort(&objs, "luoto-dev", "luoto", &BTreeSet::new());
        assert_eq!(
            dev.mine,
            ["luoto-dev-web", "luoto-dev-web-gate", "luoto-dev-vault"]
        );
        assert_eq!((dev.theirs, dev.foreign), (3, 3));
    }

    #[test]
    fn a_name_of_this_config_never_takes_the_other_instances_object() {
        // A source build's env `web` is `luoto-dev-web`; a release env named `dev-web`
        // (older than the rule against such names) would expect the same name.
        let objs = [obj("luoto-dev-web", "web", "dev")];
        let expected: BTreeSet<String> = ["luoto-dev-web".to_string()].into();
        let s = sort(&objs, "luoto", "luoto-dev", &expected);
        assert!(s.mine.is_empty());
        assert_eq!(s.theirs, 1);
    }

    #[test]
    fn inspect_output_parses_for_podman_and_docker() {
        let objs = parse_objects(
            "luoto-web\tweb\tdev\n/luoto-vault\t\tvault\npostgres\t<no value>\t<no value>\n\n",
        );
        assert_eq!(
            objs,
            [
                obj("luoto-web", "web", "dev"),
                obj("luoto-vault", "", "vault"),
                obj("postgres", "", ""),
            ]
        );
    }

    #[test]
    fn the_vm_goes_only_when_nothing_else_needs_it() {
        assert_eq!(vm_verdict("luoto-dev", 0, 0, false), Vm::Remove);
        assert!(
            matches!(vm_verdict("luoto-dev", 2, 0, false), Vm::Keep(w) if w.contains("luoto-dev's envs"))
        );
        assert!(
            matches!(vm_verdict("luoto-dev", 0, 1, false), Vm::Keep(w) if w.contains("didn't make"))
        );
        assert!(
            matches!(vm_verdict("luoto", 0, 0, true), Vm::Keep(w) if w.contains("`luoto uninstall`"))
        );
    }

    #[test]
    fn images_of_this_instance_by_tag_or_digest() {
        let listing = "ghcr.io/eetu/luoto-gate\t<none>\tsha256:aa\n\
                       ghcr.io/eetu/luoto-gate\t<none>\tsha256:bb\n\
                       localhost/luoto-gate\tdev\tsha256:cc\n\
                       ghcr.io/eetu/luoto-base\t0.3.0\tsha256:dd\n\
                       docker.io/library/postgres\t16\tsha256:ee\n\
                       <none>\t<none>\t<none>\n";
        let release = [
            "ghcr.io/eetu/luoto-gate".into(),
            "ghcr.io/eetu/luoto-base".into(),
        ];
        assert_eq!(
            image_refs(listing, &release),
            [
                "ghcr.io/eetu/luoto-base:0.3.0",
                "ghcr.io/eetu/luoto-gate@sha256:aa",
                "ghcr.io/eetu/luoto-gate@sha256:bb",
            ]
        );
        assert_eq!(
            image_refs(listing, &["localhost/luoto-gate".into()]),
            ["localhost/luoto-gate:dev"]
        );
    }

    #[test]
    fn references_lose_tags_and_digests() {
        assert_eq!(
            repo_of("ghcr.io/eetu/luoto-gate@sha256:aa"),
            "ghcr.io/eetu/luoto-gate"
        );
        assert_eq!(repo_of("localhost/luoto-gate:dev"), "localhost/luoto-gate");
        assert_eq!(
            repo_of("localhost:5000/luoto-gate"),
            "localhost:5000/luoto-gate"
        );
        assert!(image_family().ends_with("luoto-*"));
        for r in repos() {
            assert_eq!(repo_of(&r), r);
        }
    }

    #[test]
    fn keychain_accounts_come_from_this_instances_refs_only() {
        let text = r#"oauth_token = "keyring:luoto/anthropic.oauth_token"
token = "keyring:luoto/github.token-2"
key = "keyring:luoto-dev/ssh.key"
other = "keyring:corp/vpn"
service_account_token = 'keyring:luoto/op-sa'"#;
        assert_eq!(
            keyring_accounts(text, "luoto"),
            ["anthropic.oauth_token", "github.token-2", "op-sa"]
                .map(String::from)
                .into()
        );
        assert_eq!(
            keyring_accounts(text, "luoto-dev"),
            ["ssh.key".to_string()].into()
        );
    }

    #[test]
    fn the_hint_names_how_to_remove_the_binary() {
        let h = |p: &str| remove_binary_hint(Path::new(p));
        assert!(h("/opt/homebrew/Cellar/luoto/0.3.1/bin/luoto").contains("brew uninstall"));
        assert!(h(r"C:\Users\x\scoop\apps\luoto\current\luoto.exe").contains("scoop uninstall"));
        assert!(h("/home/x/.cargo/bin/luoto").contains("cargo uninstall"));
        assert!(h("/home/x/src/luoto/target/debug/luoto").contains("source checkout"));
        assert_eq!(h("/opt/bin/luoto"), "delete /opt/bin/luoto");
    }

    #[test]
    fn own_names_match_what_up_creates() {
        let n = own_names("web");
        for name in [
            names::dev("web"),
            names::gate("web"),
            names::volume("web", "home"),
            names::egress_net("web"),
        ] {
            assert!(n.contains(&name), "{name}");
        }
    }

    #[test]
    fn the_question_lists_what_goes_and_what_stays() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths {
            config: tmp.path().join("config"),
            data: tmp.path().join("data"),
        };
        let rt = Runtime {
            bin: "podman".into(),
            flavor: Flavor::Podman,
            connection: Some(machine::NAME.into()),
            api: None,
        };
        let plan = Plan {
            inst: "luoto",
            other: "luoto-dev",
            envs: vec!["web".into(), "api".into()],
            runtime: Ok(Inventory {
                rt,
                containers: vec![
                    "luoto-web".into(),
                    "luoto-web-gate".into(),
                    "luoto-vault".into(),
                ],
                networks: vec!["luoto-web".into(), "luoto-web-out".into()],
                volumes: vec!["luoto-web-work".into(), "luoto-web-home".into()],
                images: vec!["ghcr.io/eetu/luoto-gate@sha256:aa".into()],
                theirs: 4,
                vm: Vm::Keep(
                    "luoto-dev's envs or vault are in it (4 containers and volumes)".into(),
                ),
            }),
            keys: vec![Key {
                account: "anthropic.oauth_token".into(),
                found: None,
            }],
            keys_note: None,
            dirs: vec![(paths.config.clone(), "env configs")],
        };
        let text = plan.describe(&paths, "`brew uninstall luoto`");
        for line in [
            "  envs        web, api, with their workspaces and homes",
            "  containers  luoto-web, luoto-web-gate, luoto-vault",
            "  networks    2",
            "  keychain    luoto/anthropic.oauth_token",
            "It leaves:\n  luoto's VM `luoto`: luoto-dev's envs or vault are in it",
            "  the binary: `brew uninstall luoto`",
        ] {
            assert!(text.contains(line), "{line} not in\n{text}");
        }
        assert!(!text.contains("  VM  "), "{text}");
    }
}
