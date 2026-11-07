//! Keeping an env's gate and vault in line with its config: the gate's policy, the vault's
//! bindings and secrets, the sandbox's runtime env, and grants that expire on their own.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use luoto_shared::ctl::{GateCtl, VaultCtl};
use luoto_shared::policy::Rule;
use sha2::{Digest, Sha256};

use crate::compile::Compiled;
use crate::config::{self, EnvFile};
use crate::env::{self, Ctx, Plan};
use crate::state::EnvState;
use crate::{ctl, names, secrets};

/// Register the env's bindings with the vault. With a running gate this comes before
/// `apply_policy`: applying flushes the gate's credential cache, and whatever the gate fetches
/// after that must come from the new bindings, not refill the cache with the old value.
pub fn bind_vault(ctx: &Ctx, env: &str, state: &EnvState, compiled: &Compiled) -> Result<()> {
    ctl::vault::<bool>(
        &ctx.rt,
        &VaultCtl::Bind {
            env: env.into(),
            token_sha256: hex::encode(Sha256::digest(state.vault_token.as_bytes())),
            bindings: compiled.bindings.clone(),
        },
    )?;
    Ok(())
}

/// Load those of `refs` the vault is missing, prompting the user's secret store only for
/// them; `whose` names them for the user. Each loads on its own: one that doesn't resolve
/// (a typo in its reference) leaves the others working, and the error names it.
pub fn load_secrets(ctx: &Ctx, refs: &BTreeSet<String>, whose: &str) -> Result<()> {
    let status = ctl::vault_status(&ctx.rt)?;
    let missing: BTreeSet<String> = refs
        .iter()
        .filter(|r| !status.loaded_refs.contains(r))
        .cloned()
        .collect();
    if !missing.is_empty() {
        eprintln!(
            "unlocking {} secret(s) for {whose} from your secret store…",
            missing.len()
        );
        let mut values = BTreeMap::new();
        let mut failed = Vec::new();
        for r in &missing {
            match secrets::resolve(&ctx.global, r) {
                Ok(v) => {
                    values.insert(r.clone(), v);
                }
                Err(e) => failed.push(format!("{r}: {e:#}")),
            }
        }
        if !values.is_empty() {
            ctl::vault::<usize>(&ctx.rt, &VaultCtl::Load { secrets: values })?;
        }
        if !failed.is_empty() {
            bail!(
                "{} of {} secret(s) not loaded, so the credentials using them stay locked: {}",
                failed.len(),
                missing.len(),
                failed.join("; ")
            );
        }
    }
    Ok(())
}

pub fn apply_policy(ctx: &Ctx, env: &str, compiled: &Compiled) -> Result<()> {
    ctl::gate::<usize>(
        &ctx.rt,
        env,
        &GateCtl::ApplyPolicy {
            policy: Box::new(compiled.policy.clone()),
        },
    )?;
    Ok(())
}

/// Bring a running env in line with its config without recreating anything: gate policy,
/// vault bindings, and the sandbox's runtime env when what it should hold has changed.
/// Image, port and workspace changes still need `up --recreate`. `None` when the env is down.
pub fn reapply(ctx: &Ctx, env: &str) -> Result<Option<Plan>> {
    let p = env::plan(ctx, env)?;
    let Some(state) = &p.state else {
        return Ok(None);
    };
    let running = |c: String| ctx.rt.is_running(&c);
    if !running(names::gate(env)) || !running(names::dev(env)) {
        return Ok(None);
    }
    // The policy lands even when the vault can't be reached.
    let bound = bind_vault(ctx, env, state, &p.compiled);
    apply_policy(ctx, env, &p.compiled)?;
    bound?;
    load_secrets(ctx, &p.compiled.vault_refs(), &format!("`{env}`"))?;
    let applied = ctx
        .rt
        .run([
            "exec",
            &names::dev(env),
            "cat",
            &format!("{RUN_DIR}/{ENV_SUM}"),
        ])
        .unwrap_or_default();
    if applied.trim() != runtime_env_sum(&p.compiled) {
        write_runtime_env(ctx, env, &p.compiled)?;
    }
    Ok(Some(p))
}

/// Wipe credentials from the vault and from every running gate's cache. Best effort: one
/// failure must not leave the others holding credentials. Returns what failed.
pub fn lock_all(ctx: &Ctx) -> Result<Vec<String>> {
    let mut failed = Vec::new();
    if let Err(e) = ctl::vault::<bool>(&ctx.rt, &VaultCtl::Lock) {
        failed.push(format!("vault: {e:#}"));
    }
    failed.extend(flush_gates(ctx)?);
    Ok(failed)
}

/// Drop every running gate's cached credentials, so what the vault holds applies at once.
/// The gates that couldn't be reached.
fn flush_gates(ctx: &Ctx) -> Result<Vec<String>> {
    let states = match ctx.rt.states() {
        Ok(s) => s,
        Err(e) => {
            return Ok(vec![format!(
                "gates: none flushed, the runtime could not list them ({e:#})"
            )]);
        }
    };
    let mut failed = Vec::new();
    for e in config::list_envs(&ctx.paths)? {
        if states.running(&names::gate(&e))
            && let Err(err) = ctl::gate::<bool>(&ctx.rt, &e, &GateCtl::FlushCredentials)
        {
            failed.push(format!(
                "gate of `{e}`: {err:#} (stop it: luoto down -e {e})"
            ));
        }
    }
    Ok(failed)
}

/// What [`reload`] did.
pub struct Reloaded {
    pub read: usize,
    pub changed: usize,
    /// The references that couldn't be read, and the gates that weren't flushed.
    pub failed: Vec<String>,
}

/// Read `refs` from the secret store again (a token rotated there) and give the vault those
/// that changed; the gates then drop their cached copies. A reference that can't be read
/// keeps the value the vault has.
pub fn reload(ctx: &Ctx, refs: &BTreeSet<String>) -> Result<Reloaded> {
    let mut values = BTreeMap::new();
    let mut failed = Vec::new();
    for r in refs {
        match secrets::resolve(&ctx.global, r) {
            Ok(v) => {
                values.insert(r.clone(), v);
            }
            Err(e) => failed.push(format!("{r}: {e:#}")),
        }
    }
    let read = values.len();
    let changed = if values.is_empty() {
        0
    } else {
        ctl::vault::<usize>(&ctx.rt, &VaultCtl::Load { secrets: values })?
    };
    if changed > 0 {
        failed.extend(flush_gates(ctx)?);
    }
    Ok(Reloaded {
        read,
        changed,
        failed,
    })
}

/// Recompile every env, re-register bindings and load all secrets (after a VM reboot), with
/// one trip to the secret store.
pub fn unlock_all(ctx: &Ctx) -> Result<usize> {
    env::ensure_vault(ctx)?;
    let mut refs = BTreeSet::new();
    let mut n = 0;
    for env in config::list_envs(&ctx.paths)? {
        if EnvState::load(&ctx.paths, &env)?.is_none() {
            continue;
        }
        let p = env::plan(ctx, &env)?;
        let Some(state) = &p.state else { continue };
        bind_vault(ctx, &env, state, &p.compiled)?;
        refs.extend(p.compiled.vault_refs());
        n += 1;
    }
    load_secrets(ctx, &refs, "your envs")?;
    Ok(n)
}

/// Run `f` with `rules` added to the env's policy as grants that expire after `ttl`. They
/// are removed when `f` returns, and expire on their own if luoto dies first.
pub fn with_grants<T>(
    ctx: &Ctx,
    env: &str,
    rules: &[Rule],
    ttl: chrono::TimeDelta,
    note: &str,
    f: impl FnOnce() -> T,
) -> Result<T> {
    if rules.is_empty() {
        return Ok(f());
    }
    let expires = Utc::now() + ttl;
    let grants: Vec<Rule> = rules
        .iter()
        .map(|r| Rule {
            id: Some(config::new_rule_id()),
            expires: Some(expires),
            note: Some(note.to_string()),
            ..r.clone()
        })
        .collect();
    EnvFile::load(&ctx.paths, env)?.add_rules(&grants)?;
    let push = || -> Result<()> { apply_policy(ctx, env, &env::plan(ctx, env)?.compiled) };
    push()?;
    let out = f();
    let ids: Vec<&String> = grants.iter().filter_map(|g| g.id.as_ref()).collect();
    EnvFile::load(&ctx.paths, env)?
        .retain_rules(|r| r.id.as_ref().is_none_or(|id| !ids.contains(&id)))?;
    push()?;
    Ok(out)
}

/// Agent/placeholder env + sandbox secrets, written to a tmpfs inside the dev container
/// (memory only) and sourced by shells.
fn runtime_env(ctx: &Ctx, compiled: &Compiled) -> Result<BTreeMap<String, String>> {
    let mut env = compiled.dev_env.clone();
    if !compiled.sandbox_refs.is_empty() {
        let refs: BTreeSet<String> = compiled.sandbox_refs.values().cloned().collect();
        let values = secrets::resolve_all(&ctx.global, &refs)?;
        for (k, r) in &compiled.sandbox_refs {
            if let Some(v) = values.get(r) {
                env.insert(k.clone(), v.clone());
            }
        }
    }
    Ok(env)
}

/// The dev container's tmpfs for what luoto writes at `up`.
const RUN_DIR: &str = "/run/luoto";
const ENV_SUM: &str = "env.sum";

/// Fingerprint of what the runtime env should hold: variable names, placeholders and secret
/// refs, never resolved values. Kept beside env.sh so `reapply` resolves secrets only when it
/// has to rewrite, and a restarted container (empty tmpfs) never looks current.
fn runtime_env_sum(compiled: &Compiled) -> String {
    let mut h = Sha256::new();
    h.update(format!(
        "{:?}{:?}{:?}{:?}",
        compiled.dev_env, compiled.sandbox_refs, compiled.git_config, compiled.known_hosts
    ));
    hex::encode(h.finalize())
}

/// fish's single quotes: only `\\` and `\'` are escapes, and newlines are kept.
fn fish_quote(v: &str) -> String {
    format!("'{}'", v.replace('\\', "\\\\").replace('\'', "\\'"))
}

pub fn write_runtime_env(ctx: &Ctx, env: &str, compiled: &Compiled) -> Result<()> {
    let vars = runtime_env(ctx, compiled)?;
    let mut script = String::from("# written by luoto (memory only)\n");
    let mut fish = script.clone();
    for (k, v) in &vars {
        if k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            script.push_str(&format!("export {k}={}\n", crate::text::sh_quote(v)));
            fish.push_str(&format!("set -gx {k} {}\n", fish_quote(v)));
        }
    }
    // Git's remote rewrites and SSH's pinned host keys (the system configs init.sh writes read
    // them from here), the shells' env and last its fingerprint, in one extraction. The tar
    // goes over stdin, so the secrets in env.sh touch neither argv nor a disk.
    let tar = runtime_tar(&[
        ("gitconfig", compiled.git_config.as_bytes()),
        ("ssh_known_hosts", compiled.known_hosts.as_bytes()),
        ("env.fish", fish.as_bytes()),
        ("env.sh", script.as_bytes()),
        (ENV_SUM, runtime_env_sum(compiled).as_bytes()),
    ])?;
    ctx.rt.run_stdin(
        [
            "exec",
            "-i",
            "-u",
            "0",
            &names::dev(env),
            "tar",
            "-x",
            "-m",
            "-f",
            "-",
            "-C",
            RUN_DIR,
        ],
        &tar,
    )?;
    Ok(())
}

/// `files` as a tar of root-owned files readable by all, built in memory. No times: `tar -m`
/// stamps them in the env.
fn runtime_tar(files: &[(&str, &[u8])]) -> Result<Vec<u8>> {
    let mut b = tar::Builder::new(Vec::new());
    for (name, data) in files {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_uid(0);
        h.set_gid(0);
        h.set_cksum();
        b.append_data(&mut h, name, *data)
            .with_context(|| format!("pack {name}"))?;
    }
    Ok(b.into_inner()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fish_quoting_keeps_multi_line_values_and_quotes() {
        assert_eq!(fish_quote("a'b\\c\nd"), "'a\\'b\\\\c\nd'");
    }

    #[test]
    fn the_runtime_tar_holds_root_owned_files_in_order() {
        let raw = runtime_tar(&[("env.sh", b"export A='1'\n"), (ENV_SUM, b"abc")]).unwrap();
        let mut a = tar::Archive::new(raw.as_slice());
        let entries: Vec<(String, u32, u64, u64)> = a
            .entries()
            .unwrap()
            .map(|e| {
                let h = e.unwrap().header().clone();
                (
                    h.path().unwrap().display().to_string(),
                    h.mode().unwrap(),
                    h.uid().unwrap(),
                    h.size().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            entries,
            [
                ("env.sh".into(), 0o644, 0, 13),
                ("env.sum".into(), 0o644, 0, 3)
            ]
        );
    }
}
