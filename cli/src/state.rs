//! An env's host-side state (`<data>/envs/<env>/state.json`): its subnet, vault token, the
//! dev user's home and login name, and whether its workspace has been filled. The env's first
//! `up` makes it.

use std::collections::BTreeSet;
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
    /// Login user in the dev container (uid 1000).
    #[serde(default)]
    pub user: Option<String>,
    /// What the tools volume was filled from: the tools image and the env's CA, hashed.
    #[serde(default)]
    pub tools: Option<String>,
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
    let s = EnvState {
        octet: allocate_octet(ctx)?,
        home: detect_home(ctx, image),
        vault_token: hex::encode(rand::random::<[u8; 32]>()),
        seeded: false,
        user: None,
        tools: None,
    };
    s.save(&ctx.paths, env)?;
    Ok(s)
}

/// Pick a free 10.213.x.0/24 for a new env.
fn allocate_octet(ctx: &Ctx) -> Result<u8> {
    let used = ctx.rt.used_subnets()?;
    let mut taken: BTreeSet<u8> = BTreeSet::new();
    for env in config::list_envs(&ctx.paths)? {
        if let Some(s) = EnvState::load(&ctx.paths, &env)? {
            taken.insert(s.octet);
        }
    }
    (1..=254u8)
        .find(|o| !taken.contains(o) && !used.iter().any(|s| s == &names::addrs(*o).subnet))
        .context("no free 10.213.x.0/24 subnet left for a new env")
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
