//! `luoto feed`: the package feeds an env installs from, each in its service's credential
//! (`packages`): Azure DevOps `[credentials.azure_devops] feeds`, GitHub Packages
//! `[[credentials.github]] feeds`, Gitea, Forgejo and GitLab `[[credentials.git]] feeds`,
//! with the token the gate adds on them.

use std::process::ExitCode;

use anyhow::{Result, bail};

use crate::azure;
use crate::config::{EnvConfig, EnvFile, GitCred};
use crate::env::Ctx;
use crate::packages::{self, Feed, Scope};
use crate::prompt::menu_help;
use crate::text::display;
use crate::wizard::{Secret, SecretAsk, Step, shown_ref};

/// Every feed the env's credentials list, as `packages` tells them.
fn feeds(cfg: &EnvConfig) -> Vec<Feed> {
    let c = &cfg.credentials;
    let azure = c
        .azure_devops
        .iter()
        .flat_map(|a| &a.feeds)
        .filter_map(|e| azure::parse_feed(e).ok().map(Feed::Azure));
    let github = c
        .github
        .0
        .iter()
        .flat_map(|g| &g.feeds)
        .filter_map(|e| packages::github_entry(e).ok())
        .map(|owner| Feed::Github { owner });
    let forge = c.git.iter().flat_map(|g| {
        g.feeds.iter().filter_map(|e| {
            packages::forge_entry(e).ok().map(|scope| Feed::Forge {
                host: g.host.to_ascii_lowercase(),
                scope,
            })
        })
    });
    azure.chain(github).chain(forge).collect()
}

/// `luoto feed list`.
pub fn list(env_name: &str) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let f = EnvFile::load(&ctx.paths, env_name)?;
    let all = feeds(&f.cfg);
    if all.is_empty() {
        out!(
            "env `{env_name}` installs from no private feed (`luoto feed add -e {env_name} <feed URL>`)"
        );
    }
    for feed in all {
        let label = display(&feed.label());
        println!("{label}  {}", crate::style::out().dim(feed.service()));
    }
    Ok(ExitCode::SUCCESS)
}

/// `luoto feed add`: the feed into its service's credential, created with `token` (asked
/// for on a terminal) when the env has none for it; applied at once to a running env.
pub fn add(
    env_name: &str,
    entry: &str,
    token: Option<&str>,
    ca: Option<&str>,
    storage: &[String],
) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let feed = packages::parse(entry)?;
    if let Some(t) = token {
        crate::secrets::check_ref(t)?;
    }
    if (ca.is_some() || !storage.is_empty()) && !matches!(feed, Feed::Forge { .. }) {
        bail!(
            "`--ca` and `--storage-host` are for a self-hosted forge's feed, not {}",
            feed.service()
        );
    }
    // Checked before anything is written, so a mistake leaves the env's file as it was.
    let storage: Vec<String> = match &feed {
        Feed::Forge { host, .. } => {
            if let Some(ca) = ca {
                crate::compile::git_ca(host, ca)?;
            }
            storage
                .iter()
                .map(|s| crate::compile::storage_host(host, s))
                .collect::<Result<_>>()?
        }
        _ => Vec::new(),
    };
    let mut f = EnvFile::load(&ctx.paths, env_name)?;
    let before = f.cfg.clone();
    let listed = feeds(&f.cfg).contains(&feed);
    // The token the feed's credential has now, if any.
    let have = match &feed {
        Feed::Azure(_) => f
            .cfg
            .credentials
            .azure_devops
            .as_ref()
            .map(|c| c.token.clone()),
        Feed::Github { .. } => f
            .cfg
            .credentials
            .github
            .0
            .iter()
            .find(|g| !g.feeds.is_empty())
            .and_then(|g| g.token.clone()),
        Feed::Forge { host, .. } => forge_cred(&f.cfg, host).and_then(|g| g.token.clone()),
    };
    let scripted = format!(
        "luoto feed add -e {env_name} {} --token <REF>",
        entry.trim()
    );
    let token = match (token, &have) {
        (Some(t), _) => Some(t.to_string()),
        (None, Some(_)) => None,
        (None, None) if !crate::prompt::interactive() => bail!(
            "env `{env_name}` has no token for {} yet: `{scripted}` ({})",
            feed.service(),
            token_kind(&feed)
        ),
        (None, None) => match ask_token(&ctx, &feed)? {
            Some(t) => Some(t),
            None => return Err(crate::prompt::declined("written", &scripted)),
        },
    };
    if listed && token.is_none() && ca.is_none() && storage.is_empty() {
        block!(
            "{}",
            summary(env_name, &f.cfg, &feed, have.as_deref(), None)
        );
        return Ok(ExitCode::SUCCESS);
    }
    match &feed {
        Feed::Azure(a) => {
            if let (Some(old), None, false) = (&have, &token, listed) {
                let line = format!(
                    "The env's Azure DevOps credential takes it, with its token {}: a PAT needs \
                     Packaging (Read) for feeds.",
                    shown_ref(old)
                );
                out_text!("{}", crate::text::wrap(&line, "", crate::text::columns()));
            }
            f.add_azure_feeds(token.as_deref(), &[a.entry()])?;
        }
        Feed::Github { owner } => {
            if let (Some(old), None, false) = (&have, &token, listed) {
                let line = format!(
                    "The env's GitHub credential for feeds takes it, with its token {}.",
                    shown_ref(old)
                );
                out_text!("{}", crate::text::wrap(&line, "", crate::text::columns()));
            }
            f.add_github_feeds(token.as_deref(), std::slice::from_ref(owner))?;
        }
        Feed::Forge { host, scope } => {
            let known = forge_cred(&f.cfg, host).cloned();
            let new = GitCred {
                host: host.clone(),
                token: token.clone(),
                username: known
                    .as_ref()
                    .map(|k| k.username.clone())
                    .unwrap_or_else(|| "oauth2".into()),
                private: known.as_ref().is_some_and(|k| k.private)
                    || crate::repos::private_host(host),
                ca: ca
                    .map(str::to_string)
                    .or_else(|| known.as_ref().and_then(|k| k.ca.clone())),
                storage_hosts: storage.iter().map(|h| h.to_ascii_lowercase()).collect(),
                ..Default::default()
            };
            let new = match (&known, ca, new.private) {
                // A new credential for a host on a private network: its certificate may be an
                // internal CA's.
                (None, None, true) if crate::prompt::interactive() => GitCred {
                    ca: ask_ca(host)?,
                    ..new
                },
                _ => new,
            };
            f.add_git_feeds(&new, &[scope.entry()])?;
            if let (Some(ca), Some(k)) = (ca, &known)
                && k.ca.as_deref() != Some(ca)
            {
                f.set_git_ca(host, ca)?;
            }
        }
    }
    let f = EnvFile::load(&ctx.paths, env_name)?;
    let now = token.as_deref().or(have.as_deref());
    let applied = crate::sync::reapply(&ctx, env_name)?.is_some();
    // The gate reads a host's CA when it starts: a new one waits for `up`, which restarts it.
    let ca_of = |cfg: &EnvConfig| match &feed {
        Feed::Forge { host, .. } => forge_cred(cfg, host)
            .filter(|g| g.ca.is_some())
            .map(|g| (g.ca.clone(), g.storage_hosts.clone())),
        _ => None,
    };
    let applied = Some(if !applied {
        Applies::AtUp
    } else if ca_of(&before) != ca_of(&f.cfg) {
        Applies::AtRestart
    } else {
        Applies::Now
    });
    block!("{}", summary(env_name, &f.cfg, &feed, now, applied));
    Ok(ExitCode::SUCCESS)
}

/// `luoto feed rm`.
pub fn rm(env_name: &str, entry: &str) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let feed = packages::parse(entry)?;
    let mut f = EnvFile::load(&ctx.paths, env_name)?;
    let removed = match &feed {
        Feed::Azure(a) => f.remove_azure_feed(&|e| {
            azure::parse_feed(e).is_ok_and(|x| x.entry().eq_ignore_ascii_case(&a.entry()))
        })?,
        Feed::Github { owner } => f.remove_feed(None, &|e| {
            packages::github_entry(e).is_ok_and(|o| &o == owner)
        })?,
        Feed::Forge { host, scope } => f.remove_feed(Some(host), &|e| {
            packages::forge_entry(e).is_ok_and(|s| &s == scope)
        })?,
    };
    if !removed {
        bail!(
            "env `{env_name}` doesn't install from `{}` (`luoto feed list -e {env_name}` lists \
             its feeds)",
            feed.label()
        );
    }
    out!("removed feed `{}` from env `{env_name}`", feed.label());
    let cfg = EnvFile::load(&ctx.paths, env_name)?.cfg;
    let gone = match &feed {
        Feed::Azure(_) => cfg.credentials.azure_devops.is_none(),
        Feed::Github { .. } => false,
        Feed::Forge { host, .. } => forge_cred(&cfg, host).is_none(),
    };
    if gone {
        println!(
            "  the {} credential had no other repo or feed, so it is removed (not its token)",
            feed.service()
        );
    }
    crate::sync::reapply(&ctx, env_name)?;
    Ok(ExitCode::SUCCESS)
}

/// The `[[credentials.git]]` of `host` (`host` or `host:port`).
fn forge_cred<'a>(cfg: &'a EnvConfig, host: &str) -> Option<&'a GitCred> {
    cfg.credentials
        .git
        .iter()
        .find(|g| g.host.eq_ignore_ascii_case(host))
}

/// The token a feed's service wants, in a few words.
fn token_kind(feed: &Feed) -> &'static str {
    match feed {
        Feed::Azure(_) => "a PAT with Packaging (Read)",
        Feed::Github { .. } => "a classic token with read:packages",
        Feed::Forge {
            scope: Scope::Gitea { .. },
            ..
        } => "a token with read:package",
        Feed::Forge { .. } => "a personal, group or project access token with read_api",
    }
}

/// Where the token for `feed` is kept: the keychain or 1Password, or a reference.
fn ask_token(ctx: &Ctx, feed: &Feed) -> Result<Option<String>> {
    let (label, acct, how) = match feed {
        Feed::Azure(a) => {
            let org = azure::decode(&a.org);
            (
                format!("Azure DevOps PAT for {org}"),
                format!("azure_devops.{org}"),
                format!("A PAT (dev.azure.com/{org}/_usersSettings/tokens) with Packaging (Read)."),
            )
        }
        Feed::Github { owner } => (
            format!("GitHub token for {owner}'s packages"),
            "github.feeds".to_string(),
            "A classic token (github.com/settings/tokens) with read:packages; fine-grained \
             tokens don't reach GitHub's package registries."
                .to_string(),
        ),
        Feed::Forge { host, .. } => (
            format!("token for {host}'s feeds"),
            format!("git.{host}"),
            format!("{} of {host}.", capitalized(token_kind(feed))),
        ),
    };
    let title = format!("luoto {label}");
    let how = crate::text::wrap(&how, "  ", crate::text::columns());
    let help = menu_help("later");
    let ask = SecretAsk {
        label: &label,
        acct: &acct,
        title: &title,
        later: false,
        known: &[],
        current: None,
        help: &help,
        kind: None,
        how: Some(&how),
        shape: None,
    };
    Ok(match crate::wizard::secret(&ask, &ctx.global)? {
        Step::Got(Secret::Ref(r)) => Some(r),
        _ => None,
    })
}

fn capitalized(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

/// The CA certificate of a host on a private network, if an internal one signs it.
fn ask_ca(host: &str) -> Result<Option<String>> {
    use crate::prompt::Ask;
    let question = format!(
        "The CA certificate (a PEM file) of {}, if an internal CA signs it:",
        display(host)
    );
    let path = inquire::Text::new(&question)
        .with_help_message("empty when its certificate is public")
        .ask()?
        .unwrap_or_default();
    let path = path.trim();
    Ok((!path.is_empty()).then(|| path.to_string()))
}

/// When a written feed reaches the env.
#[derive(Clone, Copy)]
enum Applies {
    /// The running env took it.
    Now,
    /// The env isn't running: its next `up`.
    AtUp,
    /// A new CA: the gate reads it as it starts, at the next `up`.
    AtRestart,
}

/// The closing summary of `luoto feed add`; `applied`, when the env takes it (`None`: nothing
/// changed).
fn summary(
    env: &str,
    cfg: &EnvConfig,
    feed: &Feed,
    token: Option<&str>,
    applied: Option<Applies>,
) -> String {
    let mut rows = vec![(
        "token",
        token.map(shown_ref).unwrap_or_else(|| "none".into()),
    )];
    match feed {
        Feed::Azure(a) => rows.push((
            "reaches",
            format!(
                "every feed of {}, to install (its links name feeds by ID)",
                azure::decode(&a.org)
            ),
        )),
        Feed::Github { owner } => rows.push((
            "reaches",
            format!("{owner}'s packages on GitHub's registries, to install"),
        )),
        Feed::Forge { host, scope } => {
            rows.push(("reaches", scope.reaches()));
            if let Some(g) = forge_cred(cfg, host) {
                if g.private {
                    rows.push(("network", "private (`private = true`)".into()));
                }
                if let Some(ca) = &g.ca {
                    rows.push(("CA", display(ca)));
                }
            }
        }
    }
    match applied {
        Some(Applies::Now) => rows.push(("applied", "now".into())),
        Some(Applies::AtUp) => rows.push(("applies", format!("at `luoto up -e {env}`"))),
        Some(Applies::AtRestart) => rows.push((
            "applies",
            format!("at `luoto up -e {env}` (its gate takes a new CA as it starts)"),
        )),
        None => {}
    }
    rows.push((
        "remove it",
        format!("luoto feed rm -e {env} {}", feed.label()),
    ));
    crate::prompt::summary(&format!("feed {}", feed.label()), &rows)
}
