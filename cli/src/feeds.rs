//! `luoto feed`: the Azure DevOps package feeds an env installs from, in
//! `[credentials.azure_devops] feeds`, with the token the gate adds on them.

use std::process::ExitCode;

use anyhow::{Result, bail};

use crate::azure::{self, Feed};
use crate::config::EnvFile;
use crate::env::Ctx;
use crate::prompt::menu_help;
use crate::text::display;
use crate::wizard::{Secret, SecretAsk, Step, shown_ref};

/// Whether `entry` of `feeds` names `feed`.
fn same(entry: &str, feed: &Feed) -> bool {
    azure::parse_feed(entry).is_ok_and(|e| e.entry().eq_ignore_ascii_case(&feed.entry()))
}

/// `luoto feed list`.
pub fn list(env_name: &str) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let f = EnvFile::load(&ctx.paths, env_name)?;
    let feeds = f
        .cfg
        .credentials
        .azure_devops
        .map(|c| c.feeds)
        .unwrap_or_default();
    if feeds.is_empty() {
        out!("env `{env_name}` installs from no Azure DevOps feed (`luoto feed add <feed URL>`)");
    }
    for e in feeds {
        println!("{}", display(&e));
    }
    Ok(ExitCode::SUCCESS)
}

/// `luoto feed add`: the feed into the env's Azure DevOps credential, created with `token`
/// (asked for on a terminal) when the env has none; applied at once to a running env.
pub fn add(env_name: &str, entry: &str, token: Option<&str>) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let feed = azure::parse_feed(entry)?;
    let org = azure::decode(&feed.org);
    let mut f = EnvFile::load(&ctx.paths, env_name)?;
    let cred = f.cfg.credentials.azure_devops.clone();
    let have = cred.as_ref().map(|c| c.token.clone());
    let listed = cred
        .as_ref()
        .is_some_and(|c| c.feeds.iter().any(|e| same(e, &feed)));
    let token = match (token, &have) {
        (Some(t), _) => Some(t.to_string()),
        (None, Some(_)) => None,
        (None, None) if !crate::prompt::interactive() => bail!(
            "env `{env_name}` has no Azure DevOps credential yet, so the feed needs a token: \
             `luoto feed add -e {env_name} {} --token <ref>` (a PAT with Packaging (Read))",
            feed.entry()
        ),
        (None, None) => match ask_token(&ctx, &org)? {
            Some(t) => Some(t),
            None => {
                println!("nothing written");
                return Ok(ExitCode::SUCCESS);
            }
        },
    };
    if listed && token.is_none() {
        block!("{}", summary(env_name, &feed, have.as_deref(), None));
        return Ok(ExitCode::SUCCESS);
    }
    if let (Some(old), None, false) = (&have, &token, listed) {
        let line = format!(
            "The env's Azure DevOps credential takes it, with its token {}: a PAT needs \
             Packaging (Read) for feeds.",
            shown_ref(old)
        );
        out_text!("{}", crate::text::wrap(&line, "", crate::text::columns()));
    }
    f.add_azure_feeds(token.as_deref(), &[feed.entry()])?;
    let now = token.as_deref().or(have.as_deref());
    let applied = crate::sync::reapply(&ctx, env_name)?.is_some();
    block!("{}", summary(env_name, &feed, now, Some(applied)));
    Ok(ExitCode::SUCCESS)
}

/// `luoto feed rm`.
pub fn rm(env_name: &str, entry: &str) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let feed = azure::parse_feed(entry)?;
    let mut f = EnvFile::load(&ctx.paths, env_name)?;
    if !f.remove_azure_feed(&|e| same(e, &feed))? {
        bail!(
            "env `{env_name}` doesn't install from `{}`; `luoto feed -e {env_name}` lists its \
             feeds",
            feed.entry()
        );
    }
    out!("removed feed `{}` from env `{env_name}`", feed.entry());
    if EnvFile::load(&ctx.paths, env_name)?
        .cfg
        .credentials
        .azure_devops
        .is_none()
    {
        println!(
            "  the Azure DevOps credential had no other repo or feed, so it is removed (not its token)"
        );
    }
    crate::sync::reapply(&ctx, env_name)?;
    Ok(ExitCode::SUCCESS)
}

/// Where the PAT for `org`'s feeds is kept: the keychain or 1Password, or a reference.
fn ask_token(ctx: &Ctx, org: &str) -> Result<Option<String>> {
    let label = format!("Azure DevOps PAT for {org}");
    let acct = format!("azure_devops.{org}");
    let title = format!("luoto {label}");
    let how = crate::text::wrap(
        &format!("A PAT (dev.azure.com/{org}/_usersSettings/tokens) with Packaging (Read)."),
        "  ",
        crate::text::columns(),
    );
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

/// The closing summary of `luoto feed add`; `applied`, whether the running env took it now
/// (`None`: nothing changed).
fn summary(env: &str, feed: &Feed, token: Option<&str>, applied: Option<bool>) -> String {
    let org = azure::decode(&feed.org);
    let mut rows = vec![
        (
            "token",
            token.map(shown_ref).unwrap_or_else(|| "none".into()),
        ),
        (
            "reaches",
            format!("every feed of {org}, to install (its links name feeds by ID)"),
        ),
    ];
    match applied {
        Some(true) => rows.push(("applied", "now".into())),
        Some(false) => rows.push(("applies", format!("at `luoto up -e {env}`"))),
        None => {}
    }
    rows.push((
        "remove it",
        format!("luoto feed rm -e {env} {}", feed.entry()),
    ));
    crate::prompt::summary(&format!("feed {}", feed.entry()), &rows)
}
