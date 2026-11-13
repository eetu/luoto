//! `luoto var`: an env's environment variables, in its own file only. `[env]` holds plain
//! values; `[sandbox_secrets]` holds refs, resolved on this machine at `up` and readable by
//! any code in the env. A name lives in one of the two.

use std::collections::{BTreeMap, BTreeSet};
use std::process::ExitCode;

use anyhow::{Result, bail};
use luoto_shared::api::{AccessRequest, Install, RequestStatus};
use luoto_shared::ctl::GateCtl;

use crate::config::{EnvConfig, EnvFile};
use crate::env::Ctx;
use crate::paths::Paths;
use crate::text::{self, display};
use crate::wizard::Mode;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Plain(String),
    /// A secret ref (`op://`, `keyring:`, …).
    Secret(String),
}

/// One of the env's variables as the UI lists it: a plain one with its value, a secret with
/// where it is kept (its ref as `luoto var` shows it), never its value.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum EnvVar {
    Plain { name: String, value: String },
    Secret { name: String, kept: String },
}

/// The env's variables for the UI.
pub fn listed(cfg: &EnvConfig) -> Vec<EnvVar> {
    of(cfg)
        .into_iter()
        .map(|(name, v)| match v {
            Value::Plain(value) => EnvVar::Plain { name, value },
            Value::Secret(r) => EnvVar::Secret {
                name,
                kept: crate::secrets::shown_ref(&r),
            },
        })
        .collect()
}

/// The env's variables, by name.
pub fn of(cfg: &EnvConfig) -> BTreeMap<String, Value> {
    let plain = cfg.env.iter().map(|(k, v)| (k, Value::Plain(v.clone())));
    let secret = cfg
        .sandbox_secrets
        .iter()
        .map(|(k, r)| (k, Value::Secret(r.clone())));
    plain.chain(secret).map(|(k, v)| (k.clone(), v)).collect()
}

/// What is wrong with `name` as a variable of the env's.
pub fn check_name(name: &str) -> Result<()> {
    match luoto_shared::variable_refused(name) {
        Some(why) => bail!("{}", display(&why)),
        None => Ok(()),
    }
}

/// What luoto sets in the env's shells besides its own variables: credentials' placeholders
/// and agents' settings. A value of the env's own in their place would replace a placeholder,
/// and could put the real secret where the gate keeps it out.
pub fn luoto_names(compiled: &crate::compile::Compiled, cfg: &EnvConfig) -> BTreeSet<String> {
    compiled
        .dev_env
        .keys()
        .filter(|k| !cfg.env.contains_key(*k))
        .cloned()
        .collect()
}

/// [`check_name`], and that luoto sets no `name` of its own in `env`.
fn check_free(ctx: &Ctx, env: &str, name: &str) -> Result<()> {
    check_name(name)?;
    let p = crate::env::plan(ctx, env)?;
    if luoto_names(&p.compiled, &p.cfg).contains(name) {
        bail!("luoto sets `{name}` in `{env}` itself, for one of its credentials or agents");
    }
    Ok(())
}

/// What setting `name` to `value` replaces in the other table, for people.
fn replaces(cfg: &EnvConfig, name: &str, value: &Value) -> Option<String> {
    match value {
        Value::Plain(_) => cfg
            .sandbox_secrets
            .get(name)
            .map(|r| format!("the secret from {}", crate::secrets::shown_ref(r))),
        Value::Secret(_) => cfg
            .env
            .get(name)
            .map(|v| format!("the plain value `{}`", display(v))),
    }
}

/// Set `name` to `value` in the env's file, out of the other table if it was there.
pub fn set(paths: &Paths, env: &str, name: &str, value: &Value) -> Result<()> {
    check_name(name)?;
    let mut f = EnvFile::load(paths, env)?;
    match value {
        Value::Plain(v) => f.set_var(false, name, v),
        Value::Secret(r) => {
            crate::secrets::check_ref(r)?;
            f.set_var(true, name, r)
        }
    }
}

/// Ask where the secret `name` is kept and write its ref; whether it wrote one.
pub fn ask(ctx: &Ctx, mode: Mode, env: &str, name: &str, own: &EnvConfig) -> Result<bool> {
    check_free(ctx, env, name)?;
    println!(
        "{}",
        text::wrap(
            &format!(
                "`{}` goes into the env as the secret itself, so any code there can read it.",
                display(name)
            ),
            "",
            text::columns()
        )
    );
    let label = format!("`{}`", display(name));
    // The env's own: the same name in another env never offers this one's.
    let acct = format!("sandbox.{env}.{name}");
    let title = format!("luoto {env} {name}");
    let help = crate::prompt::menu_help(mode.esc());
    let ask = crate::wizard::SecretAsk {
        label: &label,
        acct: &acct,
        title: &title,
        later: mode == Mode::Missing,
        known: &[],
        current: own.sandbox_secrets.get(name).map(String::as_str),
        help: &help,
        kind: None,
        how: None,
        shape: None,
    };
    let crate::wizard::Step::Got(crate::wizard::Secret::Ref(r)) =
        crate::wizard::secret(&ask, &ctx.global)?
    else {
        if mode == Mode::Change {
            println!("unchanged");
        }
        return Ok(false);
    };
    let value = Value::Secret(r);
    let was = replaces(own, name, &value);
    set(&ctx.paths, env, name, &value)?;
    summary(env, name, &value, was);
    Ok(true)
}

fn summary(env: &str, name: &str, value: &Value, replaced: Option<String>) {
    let (title, row, change) = match value {
        Value::Plain(v) => (
            format!("variable {name}"),
            ("value", display(v)),
            format!("luoto var set -e {env} {name}=<value>"),
        ),
        Value::Secret(r) => (
            format!("sandbox secret {name}"),
            ("credential", crate::secrets::shown_ref(r)),
            format!("luoto var set -e {env} {name}"),
        ),
    };
    let mut rows = vec![row];
    if let Some(r) = replaced {
        rows.push(("replaces", r));
    }
    rows.push(("change it", change));
    println!("{}", crate::prompt::summary(&title, &rows));
}

/// Apply the env's variables to it if it runs (new shells there see them, without what was
/// `removed`); a variable set resolves the sandbox's pending requests for it, whether or not
/// it applied. What happened, for people.
fn applied(ctx: &Ctx, env: &str, name: &str, removed: bool) -> String {
    let line = match crate::sync::reapply(ctx, env) {
        Ok(Some(_)) if removed => {
            format!("shells in `{env}` drop it at their next prompt; running programs keep it")
        }
        Ok(Some(_)) => {
            format!("shells in `{env}` have it at their next prompt; running programs don't")
        }
        Ok(None) => format!("applies on `luoto up -e {env}`"),
        Err(e) => format!("applies on `luoto up -e {env}` ({e:#})"),
    };
    if !removed {
        resolve_requests(ctx, env, name, &line);
    }
    line
}

fn finish(ctx: &Ctx, env: &str, name: &str, removed: bool) {
    println!("{}", applied(ctx, env, name, removed));
}

/// Approve the sandbox's pending requests for variable `name`, telling it `note`.
fn resolve_requests(ctx: &Ctx, env: &str, name: &str, note: &str) {
    let Ok(reqs) = crate::ctl::gate::<Vec<AccessRequest>>(&ctx.rt, env, &GateCtl::Requests) else {
        return;
    };
    let asked = |r: &&AccessRequest| {
        r.status == RequestStatus::Pending
            && r.install.as_ref().and_then(Install::variable) == Some(name)
    };
    for r in reqs.iter().filter(asked) {
        let resolve = GateCtl::Resolve {
            id: r.id,
            approved: true,
            note: Some(note.to_string()),
        };
        let _ = crate::ctl::gate::<AccessRequest>(&ctx.rt, env, &resolve);
    }
}

/// Why a request for variable `name` takes a value, and the commands that give it.
pub fn needs_terminal(env: &str, id: u64, name: &str) -> String {
    format!(
        "request #{id} asks for the variable `{}`, whose value you give: `luoto approve -e \
         {env} {id}` on a terminal, `luoto ui`, or `luoto var set -e {env} {}=<value>`",
        display(name),
        display(name)
    )
}

/// The variable a pending request asks for, checked.
fn requested(req: &AccessRequest) -> Result<&str> {
    let Some(name) = req.install.as_ref().and_then(Install::variable) else {
        bail!("request #{} asks for no variable", req.id);
    };
    if req.status != RequestStatus::Pending {
        bail!("request #{} is already {}", req.id, req.status);
    }
    check_name(name)?;
    Ok(name)
}

/// `luoto approve` of the sandbox's request for a variable: the plain value it suggests,
/// confirmed, or one typed; whether it was set.
pub fn approve(ctx: &Ctx, env: &str, req: &AccessRequest) -> Result<bool> {
    use crate::prompt::Ask;
    let name = requested(req)?;
    check_free(ctx, env, name)?;
    if !crate::prompt::interactive() {
        bail!(needs_terminal(env, req.id, name));
    }
    let own = EnvFile::load(&ctx.paths, env)?.cfg;
    let instead = replaces(&own, name, &Value::Plain(String::new()))
        .map(|r| format!(", in place of {r}"))
        .unwrap_or_default();
    let value = match &req.install {
        Some(Install::Var { value: Some(v), .. }) => {
            let q = format!("Set {name}={} (a plain value{instead})?", display(v));
            if !crate::prompt::confirm(&q) {
                return Ok(false);
            }
            v.clone()
        }
        _ => {
            let help = crate::prompt::menu_help("not approved");
            let Some(v) = inquire::Text::new(&format!("Value of {name}{instead}:"))
                .with_help_message(&help)
                .ask()?
            else {
                return Ok(false);
            };
            v
        }
    };
    let value = Value::Plain(value);
    let was = replaces(&own, name, &value);
    set(&ctx.paths, env, name, &value)?;
    summary(env, name, &value, was);
    finish(ctx, env, name, false);
    Ok(true)
}

/// Approve the sandbox's request for a variable with the plain `value` the UI gives; what
/// happened, for people.
pub fn approve_with(ctx: &Ctx, env: &str, req: &AccessRequest, value: String) -> Result<String> {
    let name = requested(req)?;
    check_free(ctx, env, name)?;
    set(&ctx.paths, env, name, &Value::Plain(value))?;
    Ok(format!("{name} set; {}", applied(ctx, env, name, false)))
}

/// `luoto var list`.
pub fn list(env: &str) -> Result<ExitCode> {
    let cfg = EnvFile::load(&Paths::get()?, env)?.cfg;
    let vars = of(&cfg);
    if vars.is_empty() {
        println!(
            "env `{env}` has no variables (`luoto var set NAME=value`, or `luoto var set NAME` \
             for a secret)"
        );
        return Ok(ExitCode::SUCCESS);
    }
    let width = vars.keys().map(String::len).max().unwrap_or(0);
    for (k, v) in &vars {
        let shown = match v {
            Value::Plain(v) => display(v),
            Value::Secret(r) => format!("secret, {}", crate::secrets::shown_ref(r)),
        };
        println!("{k:<width$}  {shown}");
    }
    Ok(ExitCode::SUCCESS)
}

/// `luoto var set`: `NAME=value` a plain value, `NAME --ref <ref>` a secret, and `NAME` alone
/// asks where the secret is kept.
pub fn set_cmd(env: &str, var: &str, reference: Option<&str>) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let (name, plain) = match var.split_once('=') {
        Some((n, v)) => (n, Some(v)),
        None => (var, None),
    };
    check_free(&ctx, env, name)?;
    let value = match (plain, reference) {
        (Some(_), Some(_)) => bail!("`{name}=…` sets a plain value and --ref a secret: give one"),
        (Some(v), None) => Value::Plain(v.to_string()),
        (None, Some(r)) => Value::Secret(r.to_string()),
        (None, None) if !crate::prompt::interactive() => bail!(
            "no terminal to ask where `{name}` is kept: `luoto var set {name} --ref <ref>` \
             (op://, keyring:, vault://, env: or file:), or `luoto var set {name}=<value>` for \
             a plain value"
        ),
        (None, None) => {
            let own = EnvFile::load(&ctx.paths, env)?.cfg;
            if ask(&ctx, Mode::Change, env, name, &own)? {
                finish(&ctx, env, name, false);
            }
            return Ok(ExitCode::SUCCESS);
        }
    };
    let was = replaces(&EnvFile::load(&ctx.paths, env)?.cfg, name, &value);
    set(&ctx.paths, env, name, &value)?;
    summary(env, name, &value, was);
    finish(&ctx, env, name, false);
    Ok(ExitCode::SUCCESS)
}

/// `luoto var rm`.
pub fn rm_cmd(env: &str, name: &str) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    if !EnvFile::load(&ctx.paths, env)?.remove_var(name)? {
        bail!(
            "env `{env}` has no variable `{}` (`luoto var list`)",
            display(name)
        );
    }
    println!("removed `{name}` from env `{env}`");
    finish(&ctx, env, name, true);
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(dir: &tempfile::TempDir) -> Paths {
        let p = Paths {
            config: dir.path().join("config"),
            data: dir.path().join("data"),
        };
        EnvFile::create(&p, "web", &EnvConfig::default()).unwrap();
        p
    }

    #[test]
    fn names_a_shell_exports_and_luoto_leaves_to_the_env() {
        for ok in ["RUST_LOG", "_X", "database_url", "A1"] {
            check_name(ok).unwrap();
        }
        for bad in [
            "",
            "1A",
            "A-B",
            "A B",
            "A=B",
            "HTTPS_PROXY",
            "SSL_CERT_FILE",
            "LUOTO_X",
        ] {
            assert!(check_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_name_lives_in_one_table() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        let get = || of(&EnvFile::load(&p, "web").unwrap().cfg);
        set(&p, "web", "A", &Value::Plain("1".into())).unwrap();
        set(&p, "web", "B", &Value::Plain("2".into())).unwrap();
        set(
            &p,
            "web",
            "A",
            &Value::Secret("op://Vault/item/field".into()),
        )
        .unwrap();
        let vars = get();
        assert_eq!(vars["A"], Value::Secret("op://Vault/item/field".into()));
        assert_eq!(vars["B"], Value::Plain("2".into()));
        assert_eq!(vars.len(), 2);
        set(&p, "web", "A", &Value::Plain("3".into())).unwrap();
        let text = std::fs::read_to_string(p.env_config("web")).unwrap();
        assert!(!text.contains("sandbox_secrets"), "{text}");
        assert!(set(&p, "web", "C", &Value::Secret("nope".into())).is_err());
    }

    #[test]
    fn removing_the_last_one_drops_its_table() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        set(&p, "web", "A", &Value::Plain("1".into())).unwrap();
        let mut f = EnvFile::load(&p, "web").unwrap();
        assert!(f.remove_var("A").unwrap());
        assert!(!f.remove_var("A").unwrap());
        let text = std::fs::read_to_string(p.env_config("web")).unwrap();
        assert!(!text.contains("[env]"), "{text}");
    }
}
