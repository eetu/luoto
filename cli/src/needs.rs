//! A project's `[needs]`: what its luoto.toml says each developer gives their own env, and the
//! questions `up` asks for it. A need is named in a list (`credentials = ["hetzner"]`,
//! `github = ["acme/web"]`, `sandbox_secrets = ["DATABASE_URL"]`) or by a table of what the team
//! knows of it, named as the need (`[needs.azure] subscriptions`, `[needs.custom.<name>] host`),
//! which `up` offers first; the developer's answer is what the env gets. Each kind is a
//! [`Need`] variant, with its check, whether the env has it, its review line, its snippet
//! without a terminal and its question in one place: a new kind is a field of [`Needs`], a
//! variant and its arms.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use luoto_shared::profiles;
use serde::{Deserialize, Serialize};

use crate::config::{EnvConfig, EnvFile};
use crate::env::Ctx;
use crate::repos::Forge;
use crate::text::{self, display};
use crate::wizard::Mode;

/// What a project's luoto.toml says each developer gives their own env.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Needs {
    /// `owner/repo` the env should be able to push to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub github: Vec<String>,
    /// Provider profiles (`hetzner`, `anthropic`, …), `azure` or `custom.<name>`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<String>,
    /// Names of `[sandbox_secrets]` the project's code reads.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sandbox_secrets: Vec<String>,
    /// What the team knows of Azure; the table alone names the need.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure: Option<AzureNeed>,
    /// What the team knows of its custom credentials, by name; a table alone names the need.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub custom: BTreeMap<String, CustomNeed>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AzureNeed {
    /// The subscriptions the project works in, offered first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subscriptions: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CustomNeed {
    /// The host the credential goes to, offered first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

/// One thing a developer gives their env, and what the team knows of it.
#[derive(Clone, Debug, PartialEq)]
pub enum Need {
    /// Push access to a GitHub repository: the repo access question.
    Github(String),
    Provider(String),
    Custom {
        name: String,
        host: Option<String>,
    },
    Azure {
        subscriptions: Vec<String>,
    },
    Secret(String),
}

impl Need {
    /// Every need `n` names, once each.
    pub fn all(n: &Needs) -> Vec<Need> {
        let mut out: Vec<Need> = n.github.iter().map(|r| Need::Github(r.clone())).collect();
        let mut custom: BTreeSet<&str> = n.custom.keys().map(String::as_str).collect();
        let mut azure = n.azure.is_some();
        for c in &n.credentials {
            match c.strip_prefix("custom.") {
                Some(name) => {
                    custom.insert(name);
                }
                None if c == "azure" => azure = true,
                None => out.push(Need::Provider(c.clone())),
            }
        }
        out.extend(custom.into_iter().map(|name| Need::Custom {
            name: name.to_string(),
            host: n.custom.get(name).and_then(|c| c.host.clone()),
        }));
        if azure {
            out.push(Need::Azure {
                subscriptions: n
                    .azure
                    .as_ref()
                    .map(|a| a.subscriptions.clone())
                    .unwrap_or_default(),
            });
        }
        out.extend(n.sandbox_secrets.iter().map(|s| Need::Secret(s.clone())));
        out
    }

    /// What is wrong with it as a luoto.toml wrote it.
    fn check(&self) -> Result<(), String> {
        let word = |s: &str, extra: &[u8]| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
        };
        match self {
            Need::Github(r) if r.split('/').count() != 2 || !word(r, b"/._-") => {
                Err(format!("needs.github: `{}` is not owner/repo", display(r)))
            }
            Need::Provider(n) if !word(n, b"_-") => {
                Err(format!("needs.credentials: `{}` is not a name", display(n)))
            }
            Need::Custom { name, .. } if !word(name, b"_-") => {
                Err(format!("needs.custom: `{}` is not a name", display(name)))
            }
            Need::Custom {
                name,
                host: Some(h),
            } if !exact_host(h) => Err(format!(
                "needs.custom.{name}.host: `{}` is not one exact host name",
                display(h)
            )),
            Need::Azure { subscriptions } => match subscriptions
                .iter()
                .find(|s| !luoto_shared::azure_identity::is_guid(s))
            {
                Some(s) => Err(format!(
                    "needs.azure.subscriptions: `{}` is not a subscription ID",
                    display(s)
                )),
                None => Ok(()),
            },
            Need::Secret(s) if !word(s, b"_") => Err(format!(
                "needs.sandbox_secrets: `{}` is not a name",
                display(s)
            )),
            _ => Ok(()),
        }
    }

    /// Whether the env's own file has it (a repo answered as public, `declined`, counts).
    fn met(&self, cfg: &EnvConfig, declined: &BTreeSet<String>) -> bool {
        match self {
            Need::Github(r) => {
                crate::repos::uncovered(&[github_url(r)], &cfg.credentials).is_empty()
                    || declined.contains(&self.key())
            }
            Need::Provider(n) => cfg.credentials.providers.contains_key(n),
            Need::Custom { name, .. } => cfg.credentials.custom.contains_key(name),
            Need::Azure { .. } => cfg.credentials.azure.is_some(),
            Need::Secret(n) => cfg.sandbox_secrets.contains_key(n),
        }
    }

    fn key(&self) -> String {
        match self {
            Need::Github(r) => Forge::Github(owner(r)).key(r),
            Need::Provider(n) => n.clone(),
            Need::Custom { name, .. } => format!("custom.{name}"),
            Need::Azure { .. } => "azure".into(),
            Need::Secret(n) => format!("sandbox_secrets.{n}"),
        }
    }

    /// Its line in the review of the luoto.toml.
    fn review(&self) -> String {
        match self {
            Need::Github(r) => format!("GitHub push to {}", display(r)),
            Need::Provider(n) => format!("{} credential", display(n)),
            Need::Custom { name, host } => match host {
                Some(h) => format!("custom.{} credential, to {}", display(name), display(h)),
                None => format!("custom.{} credential", display(name)),
            },
            Need::Azure { subscriptions } if !subscriptions.is_empty() => format!(
                "Azure credential, subscription {} offered",
                display(&subscriptions.join(", "))
            ),
            Need::Azure { .. } => "Azure credential".into(),
            Need::Secret(s) => format!("secret {}", display(s)),
        }
    }

    /// What to add without a terminal, as a line of a snippet's table (GitHub repos and
    /// secrets share theirs).
    fn snippet(&self) -> String {
        const REF: &str = "\"op://<vault>/<item>/<field>\"";
        match self {
            Need::Github(r) => format!("\"{r}\""),
            Need::Provider(n) => {
                let kind = profiles::provider(n)
                    .and_then(|p| p.auth.keys().next().cloned())
                    .unwrap_or_else(|| "api_key".into());
                format!("[credentials.{n}]\n{kind} = {REF}")
            }
            Need::Custom { name, host } => format!(
                "[credentials.custom.{name}]\nhost = \"{}\"\nsecret = {REF}",
                host.as_deref().unwrap_or("<api host>")
            ),
            Need::Azure { subscriptions } => {
                let subs = if subscriptions.is_empty() {
                    "\"<subscription id>\"".to_string()
                } else {
                    subscriptions
                        .iter()
                        .map(|s| format!("\"{s}\""))
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                format!(
                    "[credentials.azure]\n# your az login's token; or client_id + client_secret \
                     + tenant\nsubscriptions = [{subs}]"
                )
            }
            Need::Secret(s) => format!("{s} = {REF}"),
        }
    }

    /// Its question; whether it wrote something.
    fn ask(&self, ctx: &Ctx, mode: Mode, env: &str, own: &EnvConfig) -> Result<bool> {
        match self {
            Need::Github(r) => {
                let line = format!(
                    "{} (GitHub, named by the project's luoto.toml) has no credential, so the \
                     env can only fetch it if it is public.",
                    display(r)
                );
                println!("{}", text::wrap(&line, "", text::columns()));
                crate::repos::ask_repo(ctx, env, &Forge::Github(owner(r)), r, mode)
            }
            Need::Provider(n) => ask_provider(ctx, mode, env, n, own),
            Need::Custom { name, host } => ask_custom(ctx, mode, env, name, host.as_deref(), own),
            Need::Azure { subscriptions } => ask_azure(ctx, mode, env, own, subscriptions),
            Need::Secret(n) => crate::vars::ask(ctx, mode, env, n, own),
        }
    }
}

fn owner(repo: &str) -> String {
    repo.split('/').next().unwrap_or_default().to_string()
}

fn github_url(repo: &str) -> String {
    format!("https://github.com/{repo}.git")
}

fn exact_host(h: &str) -> bool {
    !h.contains(['*', '/', ' ']) && luoto_shared::host::normalize_host(h.trim()).is_ok()
}

/// What is wrong with `n`, a luoto.toml's.
pub fn check(n: &Needs) -> Result<()> {
    for need in Need::all(n) {
        if let Err(e) = need.check() {
            bail!("luoto.toml: {e}");
        }
    }
    Ok(())
}

/// Its review lines, one a need.
pub fn review(n: &Needs) -> Vec<String> {
    Need::all(n).iter().map(Need::review).collect()
}

/// The snippets to add what the env's own file `cfg` lacks (repos answered as public,
/// `declined`, need none).
pub fn snippets(n: &Needs, cfg: &EnvConfig, declined: &BTreeSet<String>) -> Vec<String> {
    let missing: Vec<Need> = Need::all(n)
        .into_iter()
        .filter(|x| !x.met(cfg, declined))
        .collect();
    grouped(&missing)
}

/// Each need's snippet: GitHub repos in one credential, sandbox secrets in one table.
fn grouped(missing: &[Need]) -> Vec<String> {
    let repos: Vec<String> = missing
        .iter()
        .filter(|x| matches!(x, Need::Github(_)))
        .map(Need::snippet)
        .collect();
    let secrets: Vec<String> = missing
        .iter()
        .filter(|x| matches!(x, Need::Secret(_)))
        .map(Need::snippet)
        .collect();
    let mut out = Vec::new();
    if !repos.is_empty() {
        out.push(format!(
            "[credentials.github]\n# or app_id + installation_id + private_key\ntoken = \
             \"op://<vault>/<item>/<field>\"\nrepos = [{}]",
            repos.join(", ")
        ));
    }
    out.extend(
        missing
            .iter()
            .filter(|x| !matches!(x, Need::Github(_) | Need::Secret(_)))
            .map(Need::snippet),
    );
    if !secrets.is_empty() {
        out.push(format!("[sandbox_secrets]\n{}", secrets.join("\n")));
    }
    out
}

/// Needs left for later in this command: `up` asks before the gate starts and again after a
/// review, and asks only once.
static LATER: std::sync::Mutex<BTreeSet<(String, String)>> = std::sync::Mutex::new(BTreeSet::new());

/// What the env's accepted luoto.toml needs: on a terminal, each one its env's file lacks is
/// asked (`Mode::Missing`, by `up` and `project apply`) or each one asked again from what it has
/// (`Mode::Change`, `luoto project needs`), then written; without one, the snippets to add.
/// Whether anything was written.
pub fn ask(ctx: &Ctx, env: &str, mode: Mode) -> Result<bool> {
    let Some((_, p)) = crate::project::accepted(ctx, env) else {
        if mode == Mode::Change {
            println!("env `{env}` has no accepted luoto.toml, so nothing it needs");
        }
        return Ok(false);
    };
    let own = EnvFile::load(&ctx.paths, env)?.cfg;
    let declined = crate::repos::declined(ctx, env);
    // A repo left for later by `up`'s repo questions is left here too.
    let later = |n: &Need| {
        LATER
            .lock()
            .is_ok_and(|s| s.contains(&(env.to_string(), n.key())))
            || matches!(n, Need::Github(_)) && crate::repos::left_for_later(&n.key())
    };
    let asked: Vec<Need> = Need::all(&p.needs)
        .into_iter()
        .filter(|n| mode == Mode::Change || (!n.met(&own, &declined) && !later(n)))
        .collect();
    if asked.is_empty() {
        if mode == Mode::Change {
            println!("the project's luoto.toml needs nothing only you add");
        }
        return Ok(false);
    }
    if !crate::prompt::interactive() {
        if mode == Mode::Change {
            bail!(
                "these questions need a terminal; without one, add them to the env's file \
                 (`luoto edit -e {env}`):\n\n{}",
                grouped(&asked).join("\n\n")
            );
        }
        // A repo the env has is in the repo questions' hint already.
        let have: BTreeSet<String> =
            crate::repos::remotes(&crate::env::layered(ctx, env)?.workspace)
                .iter()
                .filter_map(|u| crate::repos::github_repo(u))
                .map(|r| r.to_lowercase())
                .collect();
        let left: Vec<Need> = asked
            .into_iter()
            .filter(|x| !matches!(x, Need::Github(r) if have.contains(&r.to_lowercase())))
            .collect();
        crate::init::print_needs(env, &grouped(&left));
        return Ok(false);
    }
    println!(
        "\n{}",
        text::wrap(
            "The project's luoto.toml needs credentials only you can add: the gate adds them to \
             requests, and the sandbox sees a placeholder (a sandbox secret is the exception).",
            "",
            text::columns()
        )
    );
    let mut wrote = false;
    for need in asked {
        println!();
        if need.ask(ctx, mode, env, &own)? {
            wrote = true;
        } else if mode == Mode::Missing
            && let Ok(mut s) = LATER.lock()
        {
            s.insert((env.to_string(), need.key()));
        }
    }
    Ok(wrote)
}

/// The summary a need's question ends with.
fn summary(env: &str, title: &str, rows: Vec<(&str, String)>) {
    let mut rows = rows;
    rows.push(("change it", format!("luoto project needs -e {env}")));
    println!("{}", crate::prompt::summary(title, &rows));
}

fn ask_provider(ctx: &Ctx, mode: Mode, env: &str, name: &str, own: &EnvConfig) -> Result<bool> {
    use crate::agents::Auth;
    let Some(p) = profiles::provider(name) else {
        println!(
            "luoto.toml: needs.credentials: no provider `{}`",
            display(name)
        );
        return Ok(false);
    };
    // A provider only signed in to inside the env is an agent's to log in to.
    if p.auth.is_empty() {
        return Ok(false);
    }
    let have = own.credentials.providers.get(name).and_then(|entries| {
        p.auth.keys().find_map(|kind| match entries.get(kind) {
            Some(crate::config::ProviderValue::Ref(r)) => Some(Auth::Kind {
                provider: name.to_string(),
                kind: kind.clone(),
                reference: r.clone(),
            }),
            _ => None,
        })
    });
    match crate::wizard::provider_credential(&p, &ctx.global, have.as_ref(), mode)? {
        crate::wizard::Answer::Set(auth) => {
            let (key, value) = auth.entry();
            EnvFile::load(&ctx.paths, env)?.set_provider_kind(name, key, &value)?;
            let shown = match &auth {
                Auth::Kind {
                    kind, reference, ..
                } => format!(
                    "{} = {}",
                    p.auth.get(kind).map_or(kind.as_str(), |k| k.label.as_str()),
                    crate::secrets::shown_ref(reference)
                ),
                Auth::LoginInside { .. } => "log in inside the sandbox".into(),
            };
            summary(env, p.title(), vec![("credential", shown)]);
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn ask_custom(
    ctx: &Ctx,
    mode: Mode,
    env: &str,
    name: &str,
    named: Option<&str>,
    own: &EnvConfig,
) -> Result<bool> {
    use crate::prompt::Ask;
    let had = own.credentials.custom.get(name);
    // What the env has, else what the team knows: shown to confirm, as it is where the
    // secret goes.
    let start = had.map(|c| c.host.as_str()).or(named).unwrap_or_default();
    let help = format!(
        "{}; Esc: {}",
        if named.is_some() {
            "the project's, or one exact host name"
        } else {
            "one exact host name, such as api.example.com"
        },
        mode.esc()
    );
    let Some(host) = inquire::Text::new(&format!(
        "Which host does the `{}` credential go to?",
        display(name)
    ))
    .with_initial_value(start)
    .with_help_message(&help)
    .with_validator(|v: &str| {
        Ok(if exact_host(v) {
            inquire::validator::Validation::Valid
        } else {
            inquire::validator::Validation::Invalid("one exact host name".into())
        })
    })
    .ask()?
    else {
        return Ok(false);
    };
    let host = host.trim().to_ascii_lowercase();
    let label = format!("The `{}` credential", display(name));
    let acct = format!("custom.{name}");
    let title = format!("luoto custom {name}");
    let help = crate::prompt::menu_help(mode.esc());
    let ask = crate::wizard::SecretAsk {
        label: &label,
        acct: &acct,
        title: &title,
        later: mode == Mode::Missing,
        known: &[],
        current: had.map(|c| c.secret.as_str()),
        help: &help,
        kind: None,
        how: None,
        shape: None,
    };
    let crate::wizard::Step::Got(crate::wizard::Secret::Ref(r)) =
        crate::wizard::secret(&ask, &ctx.global)?
    else {
        return Ok(false);
    };
    EnvFile::load(&ctx.paths, env)?.set_in_tables(
        &["credentials", "custom", name],
        vec![
            ("host", host.as_str().into()),
            ("secret", r.as_str().into()),
        ],
    )?;
    summary(
        env,
        &format!("credentials.custom.{}", display(name)),
        vec![
            ("host", host.clone()),
            ("credential", crate::secrets::shown_ref(&r)),
        ],
    );
    Ok(true)
}

fn ask_azure(ctx: &Ctx, mode: Mode, env: &str, own: &EnvConfig, named: &[String]) -> Result<bool> {
    use crate::prompt::Ask;
    let had: Vec<String> = own
        .credentials
        .azure
        .as_ref()
        .map(|a| a.subscriptions.clone())
        .unwrap_or_default();
    // What the project names, offered first; another is typed.
    if !named.is_empty() {
        let current = if had == named { " (current)" } else { "" };
        let mut rows = vec![(
            Some(true),
            format!("The project's (recommended){current}"),
            named.join(", "),
        )];
        rows.push((
            Some(false),
            "Another subscription".into(),
            "its ID, typed".into(),
        ));
        if mode == Mode::Missing {
            rows.push((
                None,
                "Later".into(),
                "the env gets no Azure token yet".into(),
            ));
        }
        match crate::wizard::ask_menu(crate::wizard::Question {
            text: "Which Azure subscription should the env use?".into(),
            rows,
            at: 0,
            help: crate::prompt::menu_help(mode.esc()),
        })? {
            Some(Some(true)) => return write_azure(ctx, env, named),
            Some(Some(false)) => {}
            Some(None) | None => return Ok(false),
        }
    }
    let Some(id) = inquire::Text::new("Which Azure subscription should the env use?")
        .with_initial_value(had.first().map_or("", String::as_str))
        .with_help_message(&format!(
            "its ID (`az account list -o table`), read through your `az` login; Esc: {}",
            mode.esc()
        ))
        .with_validator(|v: &str| {
            Ok(if luoto_shared::azure_identity::is_guid(v.trim()) {
                inquire::validator::Validation::Valid
            } else {
                inquire::validator::Validation::Invalid("a subscription ID".into())
            })
        })
        .ask()?
    else {
        return Ok(false);
    };
    write_azure(ctx, env, &[id.trim().to_ascii_lowercase()])
}

/// `[credentials.azure] subscriptions`, its other keys kept, and the summary.
fn write_azure(ctx: &Ctx, env: &str, ids: &[String]) -> Result<bool> {
    let mut subs = toml_edit::Array::new();
    for id in ids {
        subs.push(id.as_str());
    }
    EnvFile::load(&ctx.paths, env)?.set_in_tables(
        &["credentials", "azure"],
        vec![("subscriptions", subs.into())],
    )?;
    summary(
        env,
        "Azure",
        vec![
            ("subscription", ids.join(", ")),
            ("token", "from your `az` login here (`az login`)".into()),
        ],
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn needs(text: &str) -> Needs {
        toml::from_str(text).unwrap()
    }

    #[test]
    fn a_need_is_named_in_a_list_or_by_a_table_of_what_the_team_knows() {
        let n = needs(
            r#"
github = ["acme/web"]
credentials = ["hetzner", "custom.stripe", "azure"]
sandbox_secrets = ["DATABASE_URL"]
[azure]
subscriptions = ["00000000-0000-0000-0000-00000000000a"]
[custom.stripe]
host = "api.stripe.com"
[custom.sentry]
"#,
        );
        assert_eq!(
            Need::all(&n),
            [
                Need::Github("acme/web".into()),
                Need::Provider("hetzner".into()),
                Need::Custom {
                    name: "sentry".into(),
                    host: None
                },
                Need::Custom {
                    name: "stripe".into(),
                    host: Some("api.stripe.com".into())
                },
                Need::Azure {
                    subscriptions: vec!["00000000-0000-0000-0000-00000000000a".into()]
                },
                Need::Secret("DATABASE_URL".into()),
            ]
        );
        assert!(check(&n).is_ok());
        // The table alone names it.
        assert_eq!(
            Need::all(&needs("[azure]\n")),
            [Need::Azure {
                subscriptions: vec![]
            }]
        );
    }

    #[test]
    fn what_a_luoto_toml_names_is_checked() {
        for bad in [
            "github = [\"acme\"]",
            "credentials = [\"a b\"]",
            "[azure]\nsubscriptions = [\"prod\"]",
            "[custom.stripe]\nhost = \"*.stripe.com\"",
            "sandbox_secrets = [\"A-B\"]",
        ] {
            assert!(check(&needs(bad)).is_err(), "{bad}");
        }
        assert!(toml::from_str::<Needs>("[custom.stripe]\nsecret = \"op://x\"").is_err());
    }

    #[test]
    fn each_need_is_one_question_until_the_env_has_it() {
        let n = needs(
            r#"
github = ["acme/web"]
credentials = ["hetzner", "custom.stripe", "azure"]
sandbox_secrets = ["DATABASE_URL"]
"#,
        );
        let none = EnvConfig::default();
        assert!(
            Need::all(&n)
                .iter()
                .all(|x| !x.met(&none, &BTreeSet::new()))
        );
        let have: EnvConfig = toml::from_str(
            r#"
[workspace]
dir = "/w"
[credentials.hetzner]
token = "env:H"
[credentials.custom.stripe]
host = "api.stripe.com"
secret = "env:S"
[sandbox_secrets]
DATABASE_URL = "env:D"
"#,
        )
        .unwrap();
        // A repo answered as public counts as answered.
        let declined: BTreeSet<String> = ["github:acme/web".to_string()].into();
        let left: Vec<String> = Need::all(&n)
            .iter()
            .filter(|x| !x.met(&have, &declined))
            .map(Need::key)
            .collect();
        assert_eq!(left, ["azure"]);
    }

    #[test]
    fn without_a_terminal_the_snippets_say_what_the_team_knows() {
        let n = needs(
            r#"
github = ["acme/web", "acme/api"]
sandbox_secrets = ["A", "B"]
[azure]
subscriptions = ["00000000-0000-0000-0000-00000000000a"]
[custom.stripe]
host = "api.stripe.com"
"#,
        );
        let s = snippets(&n, &EnvConfig::default(), &BTreeSet::new());
        assert!(
            s[0].contains("repos = [\"acme/web\", \"acme/api\"]"),
            "{s:?}"
        );
        assert!(s.iter().any(|x| x.contains("host = \"api.stripe.com\"")));
        assert!(
            s.iter()
                .any(|x| x.contains("00000000-0000-0000-0000-00000000000a"))
        );
        assert!(s.last().unwrap().starts_with("[sandbox_secrets]\nA = "));
        assert_eq!(review(&n).len(), 6);
    }
}
