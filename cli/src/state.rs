//! An env's host-side state (`<data>/envs/<env>/state.json`): its subnet, vault token, the
//! dev user's home and login name, and whether its workspace and repositories have been
//! filled. The env's first `up` makes it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config;
use crate::env::Ctx;
use crate::names;
use crate::paths::{Paths, write_private};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvState {
    pub octet: u8,
    /// Home of uid 1000 in the image, where the home volume is mounted; `None` when the image
    /// has no such user (init.sh creates `/home/dev`).
    pub home: Option<String>,
    pub vault_token: String,
    /// The folder has been copied into the workspace volume.
    #[serde(default)]
    pub seeded: bool,
    /// Repositories copied or cloned into the workspace volume, or found there (`repos.rs`).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub repos: BTreeSet<String>,
    /// The env's own remote is cloned and nobody has said yes to installing what it pins:
    /// until someone does, `up` asks, or installs nothing.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub installs_pending: bool,
    /// Login user in the dev container (uid 1000).
    #[serde(default)]
    pub user: Option<String>,
    /// What the tools volume was filled from: the tools image and the env's CA, hashed.
    #[serde(default)]
    pub tools: Option<String>,
    /// The CA (`EnvCa::pem_sha256`) the dev container last started with: init.sh puts it in
    /// the container's trust stores at each start.
    #[serde(default)]
    pub dev_ca: Option<String>,
    /// What luoto has written of the model servers into each agent's config, by agent: what it
    /// removes when a server goes (`agents::configure`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub agent_servers: BTreeMap<String, crate::model_servers::Written>,
}

impl EnvState {
    /// The dev user's login name for SSH: the recorded one if it is a plain user name.
    pub fn login(&self) -> &str {
        self.user
            .as_deref()
            .filter(|u| crate::ssh::valid_user(u))
            .unwrap_or("dev")
    }

    /// Where the home volume is mounted in the dev container.
    pub fn home(&self) -> &str {
        self.home.as_deref().unwrap_or("/home/dev")
    }

    fn path(paths: &Paths, env: &str) -> PathBuf {
        paths.env_state(env).join("state.json")
    }

    pub fn load(paths: &Paths, env: &str) -> Result<Option<Self>> {
        let p = Self::path(paths, env);
        match std::fs::read(&p) {
            Ok(b) => Ok(Some(
                serde_json::from_slice(&b).with_context(|| format!("parse {}", p.display()))?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, paths: &Paths, env: &str) -> Result<()> {
        write_private(&Self::path(paths, env), &serde_json::to_vec_pretty(self)?)
    }

    /// Change the saved state with `f`; nothing when the env has none.
    pub fn update(paths: &Paths, env: &str, f: impl FnOnce(&mut Self)) -> Result<()> {
        if let Some(mut s) = Self::load(paths, env)? {
            f(&mut s);
            s.save(paths, env)?;
        }
        Ok(())
    }
}

/// The env's state, made on its first `up`: a free subnet, a vault token, and the home of the
/// dev user in `image`.
pub fn ensure(ctx: &Ctx, env: &str, image: &str) -> Result<EnvState> {
    if let Some(s) = EnvState::load(&ctx.paths, env)? {
        return Ok(s);
    }
    let home = detect_home(ctx, image);
    reserve(ctx, env, |octet| EnvState::fresh(octet, home))
}

/// Save `env`'s first state, `make` given a free octet: under a lock, and with the state
/// written before the lock goes, so an `up` or import running beside it picks another.
pub fn reserve(ctx: &Ctx, env: &str, make: impl FnOnce(u8) -> EnvState) -> Result<EnvState> {
    std::fs::create_dir_all(&ctx.paths.data)?;
    let lock = std::fs::File::create(ctx.paths.data.join("octets.lock"))?;
    lock.lock().context("lock the subnets")?;
    let used: Vec<String> = ctx.rt.subnets()?.into_iter().map(|(_, s)| s).collect();
    let octet = free_octet(names::env_octets(), &taken(&ctx.paths)?, &used)
        .context("no free subnet left for a new env")?;
    let s = make(octet);
    s.save(&ctx.paths, env)?;
    Ok(s)
}

impl EnvState {
    /// A new env's state on subnet `octet`, with a vault token of its own.
    pub fn fresh(octet: u8, home: Option<String>) -> Self {
        EnvState {
            octet,
            home,
            vault_token: hex::encode(rand::random::<[u8; 32]>()),
            seeded: false,
            repos: BTreeSet::new(),
            installs_pending: false,
            user: None,
            tools: None,
            dev_ca: None,
            agent_servers: BTreeMap::new(),
        }
    }
}

/// The octets of every env with state here, one whose config isn't written yet (an import
/// under way) included. The octet also picks the env's dev container's ID range
/// (`env::dev_id_map`).
fn taken(paths: &Paths) -> Result<BTreeSet<u8>> {
    let mut names: BTreeSet<String> = config::list_envs(paths)?.into_iter().collect();
    if let Ok(dirs) = std::fs::read_dir(paths.data.join("envs")) {
        names.extend(
            dirs.flatten()
                .filter_map(|d| d.file_name().into_string().ok())
                .filter(|n| config::validate_name(n).is_ok()),
        );
    }
    let mut taken = BTreeSet::new();
    for env in names {
        if let Some(s) = EnvState::load(paths, &env)? {
            taken.insert(s.octet);
        }
    }
    Ok(taken)
}

/// The first octet no env here has (`taken`) and no network's subnet (`used`) holds.
fn free_octet(
    octets: std::ops::RangeInclusive<u8>,
    taken: &BTreeSet<u8>,
    used: &[String],
) -> Option<u8> {
    octets
        .into_iter()
        .find(|o| !taken.contains(o) && !used.iter().any(|s| s == &names::addrs(*o).subnet))
}

/// Home of uid 1000 in the image, or None.
fn detect_home(ctx: &Ctx, image: &str) -> Option<String> {
    ctx.rt
        .run([
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "sh",
            image,
            "-c",
            "awk -F: '$3==1000{print $6}' /etc/passwd 2>/dev/null",
        ])
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| s.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_env_gets_an_octet_no_env_here_or_network_has() {
        let taken: BTreeSet<u8> = [1, 2, 4].into();
        let used = vec!["10.213.3.0/24".to_string(), "10.88.0.0/16".to_string()];
        assert_eq!(free_octet(1..=254, &taken, &used), Some(5));
        assert_eq!(free_octet(1..=254, &BTreeSet::new(), &[]), Some(1));
        assert_eq!(free_octet(128..=254, &BTreeSet::new(), &[]), Some(128));
        let all: BTreeSet<u8> = (1..=253).collect();
        assert_eq!(free_octet(1..=254, &all, &[]), Some(254));
        assert_eq!(
            free_octet(1..=254, &all, &["10.213.254.0/24".to_string()]),
            None
        );
    }

    #[test]
    fn an_env_with_state_but_no_config_yet_holds_its_octet() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths {
            config: dir.path().join("config"),
            data: dir.path().join("data"),
        };
        std::fs::create_dir_all(paths.envs_dir()).unwrap();
        std::fs::write(paths.env_config("web"), "").unwrap();
        EnvState::fresh(3, None).save(&paths, "web").unwrap();
        // An import under way: its state first, its config once its volumes are written.
        EnvState::fresh(4, None).save(&paths, "moving").unwrap();
        assert_eq!(taken(&paths).unwrap(), BTreeSet::from([3, 4]));
    }
}
