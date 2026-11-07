//! Questions asked one at a time: the `luoto init` walk-through (`c` at its prompt) and the
//! credential question `luoto agent run` shares with it. Each starts from the current value,
//! and Esc keeps that value.

use std::collections::BTreeMap;
use std::fmt;

use anyhow::{Context, Result, bail};
use inquire::list_option::ListOption;
use inquire::validator::Validation;
use inquire::{MultiSelect, Password, Select, Text};
use luoto_shared::{presets, profiles};

use crate::config::{EnvConfig, GlobalConfig, Isolation, ProviderValue};
use crate::detect;
use crate::init::Proposal;
use crate::secrets;

struct Choice<T> {
    value: T,
    /// What the answered prompt echoes.
    short: String,
    label: String,
}

impl<T> fmt::Display for Choice<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label)
    }
}

fn choice<T>(value: T, short: impl Into<String>, label: impl Into<String>) -> Choice<T> {
    Choice {
        value,
        short: short.into(),
        label: label.into(),
    }
}

fn short<T>(o: ListOption<&Choice<T>>) -> String {
    o.value.short.clone()
}

fn shorts<T>(opts: &[ListOption<&Choice<T>>]) -> String {
    let names: Vec<&str> = opts.iter().map(|o| o.value.short.as_str()).collect();
    if names.is_empty() {
        "none".into()
    } else {
        names.join(", ")
    }
}

/// Walk the proposal's settings; a credential question follows each agent that needs one.
pub fn customize(p: &mut Proposal, global: &GlobalConfig) -> Result<()> {
    println!();
    isolation(p)?;
    pick_presets(p)?;
    toolchains(p)?;
    pick_agents(&mut p.cfg)?;
    for name in p.cfg.agents.names().cloned().collect::<Vec<_>>() {
        if let Some(a) = profiles::agent(&name)
            && let Some((provider, entries)) = credential(&p.cfg, &a, global)?
        {
            p.cfg.credentials.providers.insert(provider, entries);
        }
    }
    ports(&mut p.cfg)?;
    Ok(())
}

fn isolation(p: &mut Proposal) -> Result<()> {
    if !p.gvisor {
        return Ok(());
    }
    let options = vec![
        choice(
            Isolation::Gvisor,
            "gVisor",
            "gVisor     its own user-space kernel: an exploit stays in the env (builds about 1.6× slower)",
        ),
        choice(
            Isolation::Container,
            "container",
            "container  shares the VM's kernel: builds about 1.6× faster, weaker",
        ),
    ];
    let current = usize::from(p.cfg.isolation == Some(Isolation::Container));
    if let Some(c) = Select::new("Isolation:", options)
        .with_starting_cursor(current)
        .with_formatter(&short)
        .prompt_skippable()?
    {
        // gVisor is the default, so only the opt-out is written.
        p.cfg.isolation = (c.value == Isolation::Container).then_some(Isolation::Container);
    }
    Ok(())
}

fn pick_presets(p: &mut Proposal) -> Result<()> {
    let options: Vec<Choice<String>> = presets::names()
        .map(|n| {
            let desc = presets::get(n).map(|p| p.description).unwrap_or_default();
            let found = p
                .found
                .presets
                .iter()
                .find(|(f, _)| f == n)
                .map(|(_, file)| format!("  [{file}]"))
                .unwrap_or_default();
            choice(n.to_string(), n, format!("{n:<11} {desc}{found}"))
        })
        .collect();
    let selected: Vec<usize> = options
        .iter()
        .enumerate()
        .filter(|(_, o)| p.cfg.presets.contains(&o.value))
        .map(|(i, _)| i)
        .collect();
    if let Some(chosen) =
        MultiSelect::new("Egress presets (read access to these registries):", options)
            .with_default(&selected)
            .with_help_message("space toggles, enter confirms; [file] = suggested by the folder")
            .with_formatter(&shorts)
            .prompt_skippable()?
    {
        p.cfg.presets = chosen.into_iter().map(|c| c.value).collect();
    }
    Ok(())
}

fn toolchains(p: &mut Proposal) -> Result<()> {
    let found: Vec<String> = p
        .found
        .tools
        .iter()
        .map(|t| format!("{} {} ({})", t.tool, t.version, t.source))
        .collect();
    if !found.is_empty() {
        println!(
            "  the folder pins {}; those files keep deciding",
            found.join(", ")
        );
    }
    let current: Vec<String> = p
        .cfg
        .tools
        .iter()
        .map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or_default()))
        .collect();
    let current = current.join(" ");
    let Some(answer) = Text::new("Default toolchains:")
        .with_initial_value(&current)
        .with_placeholder("e.g. node=lts python=3.12")
        .with_help_message("tool=version, space-separated; installed by mise in the env")
        .with_validator(|s: &str| {
            Ok(match s.split_whitespace().find(|t| !t.contains('=')) {
                Some(t) => Validation::Invalid(format!("`{t}` is not tool=version").into()),
                None => Validation::Valid,
            })
        })
        .prompt_skippable()?
    else {
        return Ok(());
    };
    p.cfg.tools = answer
        .split_whitespace()
        .filter_map(|t| t.split_once('='))
        .map(|(k, v)| (k.to_string(), toml::Value::String(v.to_string())))
        .collect();
    // A runtime's packages come from its registry, which the env can't read without the preset.
    for tool in p.cfg.tools.keys() {
        if let Some(preset) = detect::preset_for(tool)
            && !p.cfg.presets.iter().any(|x| x == preset)
        {
            p.cfg.presets.push(preset.to_string());
            println!("  + preset {preset}, for {tool}'s packages");
        }
    }
    Ok(())
}

fn pick_agents(cfg: &mut EnvConfig) -> Result<()> {
    let options: Vec<Choice<String>> = profiles::agent_names()
        .map(|n| {
            let desc = profiles::agent(n)
                .map(|a| a.description)
                .unwrap_or_default();
            choice(n.to_string(), n, format!("{n:<9} {desc}"))
        })
        .collect();
    let selected: Vec<usize> = options
        .iter()
        .enumerate()
        .filter(|(_, o)| cfg.agents.contains(&o.value))
        .map(|(i, _)| i)
        .collect();
    if let Some(chosen) = MultiSelect::new("Coding agents:", options)
        .with_default(&selected)
        .with_help_message(
            "space toggles, enter confirms; each installs on first `luoto agent run`",
        )
        .with_formatter(&shorts)
        .prompt_skippable()?
    {
        cfg.agents = crate::config::Agents::from_names(chosen.into_iter().map(|c| c.value));
    }
    Ok(())
}

fn ports(cfg: &mut EnvConfig) -> Result<()> {
    let current: Vec<String> = cfg.ports.iter().map(u16::to_string).collect();
    let current = current.join(" ");
    let Some(answer) = Text::new("Dev-server ports:")
        .with_initial_value(&current)
        .with_placeholder("e.g. 5173")
        .with_help_message("published on 127.0.0.1, space-separated")
        .with_validator(|s: &str| {
            Ok(
                match s.split_whitespace().find(|t| t.parse::<u16>().is_err()) {
                    Some(t) => Validation::Invalid(format!("`{t}` is not a port").into()),
                    None => Validation::Valid,
                },
            )
        })
        .prompt_skippable()?
    else {
        return Ok(());
    };
    cfg.ports = answer
        .split_whitespace()
        .filter_map(|t| t.parse().ok())
        .collect();
    Ok(())
}

/// How an agent's provider is authenticated.
#[derive(Clone, PartialEq)]
enum Auth {
    Kind(String),
    LoginInside,
    Later,
}

/// Where a credential of a known kind is kept.
#[derive(Clone, Copy, PartialEq)]
enum Source {
    /// A reference the config has already, for another account (index into `known`).
    Known(usize),
    InKeychain,
    PasteKeychain,
    Paste1Password,
    Reference,
    Later,
}

/// Ask how agent `a` authenticates when `cfg` has no credential for its providers: the kind,
/// with where to get one, then where it is kept. Returns the `[credentials.<provider>]` entries
/// to write; a pasted secret is in the OS keychain or 1Password by then, and only its
/// reference goes in the config.
pub fn credential(
    cfg: &EnvConfig,
    a: &profiles::Agent,
    global: &GlobalConfig,
) -> Result<Option<(String, BTreeMap<String, ProviderValue>)>> {
    let configured = |p: &String| cfg.credentials.providers.contains_key(p);
    if a.providers.is_empty() || a.providers.iter().any(configured) {
        return Ok(None);
    }
    let provider_name = if a.providers.len() == 1 {
        a.providers[0].clone()
    } else {
        let options: Vec<Choice<String>> = a
            .providers
            .iter()
            .filter_map(|n| {
                profiles::provider(n)
                    .map(|p| choice(n.clone(), n, format!("{n:<11} {}", p.description)))
            })
            .collect();
        match Select::new(&format!("Model provider for {}:", a.description), options)
            .with_formatter(&short)
            .prompt_skippable()?
        {
            Some(c) => c.value,
            None => return Ok(None),
        }
    };
    let p = profiles::provider(&provider_name)
        .with_context(|| format!("unknown provider `{provider_name}`"))?;
    if p.auth.is_empty() {
        println!(
            "{} signs in inside the sandbox, with your own account.",
            a.description
        );
    } else {
        println!(
            "{} needs a credential for {provider_name}. The gate adds it to every request; the \
             sandbox sees only a placeholder.",
            a.description
        );
    }
    let kinds: Vec<String> = match &p.suggested {
        // The suggested kind first.
        Some(s) => std::iter::once(s.clone())
            .chain(p.auth.keys().filter(|k| *k != s).cloned())
            .collect(),
        None => p.auth.keys().cloned().collect(),
    };
    let mut options: Vec<Choice<Auth>> = kinds
        .iter()
        .map(|k| {
            let label = &p.auth[k].label;
            choice(Auth::Kind(k.clone()), label, format!("{label} ({k})"))
        })
        .collect();
    if !p.login_hosts.is_empty() {
        options.push(choice(
            Auth::LoginInside,
            "log in inside the sandbox",
            "log in inside the sandbox: the session lives in the env, readable by its code",
        ));
    }
    let later = if p.login_hosts.is_empty() {
        "later: `luoto agent run` asks again"
    } else {
        "later: log in inside the sandbox until then"
    };
    let auth = if options.len() == 1 {
        options.remove(0).value
    } else {
        if p.login_hosts.is_empty() {
            options.push(choice(Auth::Later, "later", later));
        }
        match Select::new("Authenticate with:", options)
            .with_formatter(&short)
            .prompt_skippable()?
        {
            Some(c) => c.value,
            None => return Ok(None),
        }
    };
    let kind = match auth {
        Auth::Later => return Ok(None),
        Auth::LoginInside => {
            if let Some(h) = &p.login_how {
                println!("  {h}");
            }
            let entry = ("login_inside".to_string(), ProviderValue::Flag(true));
            return Ok(Some((provider_name, BTreeMap::from([entry]))));
        }
        Auth::Kind(k) => k,
    };
    let how = &p.auth[&kind];
    println!("  {}", how.how);
    let title = format!("luoto {provider_name} {kind}");
    let acct = format!("{provider_name}.{kind}");
    let Some(reference) = secret(&how.label, &acct, &title, later, &[], global)? else {
        return Ok(None);
    };
    Ok(Some((
        provider_name,
        BTreeMap::from([(kind, ProviderValue::Ref(reference))]),
    )))
}

/// Where a secret (`label`, e.g. "GitHub token") is kept, as a reference the host resolves:
/// one of `known` (references the config has for other accounts, as (what for, reference),
/// offered first so one token can serve several), the keychain entry `acct` of luoto's
/// service, pasted into the keychain or into 1Password (item `title`), or a reference to where
/// it is already. `None` for later (`later` says what happens then) or when skipped.
pub fn secret(
    label: &str,
    acct: &str,
    title: &str,
    later: &str,
    known: &[(String, String)],
    global: &GlobalConfig,
) -> Result<Option<String>> {
    let svc = crate::names::instance();
    let mut options: Vec<Choice<Source>> = known
        .iter()
        .enumerate()
        .map(|(i, (what, r))| {
            choice(
                Source::Known(i),
                format!("the one for {what}"),
                format!("the same as for {what} ({r})"),
            )
        })
        .collect();
    if keychain_has(acct) {
        options.push(choice(
            Source::InKeychain,
            "the one in your keychain",
            format!("the one already in your keychain ({svc}/{acct})"),
        ));
    }
    options.push(choice(
        Source::PasteKeychain,
        "paste it into your keychain",
        "paste it: kept in your OS keychain",
    ));
    if secrets::op_available() {
        options.push(choice(
            Source::Paste1Password,
            "paste it into 1Password",
            "paste it: saved as a new 1Password item, in a vault you pick",
        ));
    }
    options.extend([
        choice(
            Source::Reference,
            "a secret reference",
            "a reference to where it already is: op://…, vault://…, keyring:…, env:…, file:…",
        ),
        choice(Source::Later, "later", later),
    ]);
    let Some(source) = Select::new(&format!("The {label}:"), options)
        .with_formatter(&short)
        .prompt_skippable()?
    else {
        return Ok(None);
    };
    Ok(Some(match source.value {
        Source::Known(i) => known[i].1.clone(),
        Source::Later => return Ok(None),
        Source::InKeychain => format!("keyring:{svc}/{acct}"),
        Source::PasteKeychain => {
            let Some(secret) = paste(label)? else {
                return Ok(None);
            };
            let free = free_account(acct, keychain_taken)?;
            keyring::Entry::new(svc, &free)
                .and_then(|e| e.set_password(&secret))
                .context("store the secret in the OS keychain")?;
            if free == acct {
                println!("stored in your keychain as {svc}/{free}");
            } else {
                println!(
                    "stored in your keychain as {svc}/{free} \
                     ({svc}/{acct} holds another one, kept as it is)"
                );
            }
            format!("keyring:{svc}/{free}")
        }
        Source::Paste1Password => {
            let Some(secret) = paste(label)? else {
                return Ok(None);
            };
            let Some(vault) =
                Select::new("1Password vault:", secrets::op_vaults(global)?).prompt_skippable()?
            else {
                return Ok(None);
            };
            let note = format!(
                "{label}. luoto hands it to its gate, which adds it to requests; the sandbox \
                 never sees it."
            );
            let r = secrets::op_save(global, &vault, title, &secret, &note)?;
            println!("saved in 1Password ({vault}) as \"{title}\": {r}");
            r
        }
        Source::Reference => {
            // Resolved once here (the value is dropped), so a typo shows now rather than as a
            // locked credential at `up`.
            let global = global.clone();
            let Some(r) = Text::new(&format!("Reference to the {label}:"))
                .with_placeholder("op://<vault>/<item>/<field>")
                .with_help_message("checked against your secret store; Esc for later")
                .with_validator(move |s: &str| {
                    let s = s.trim();
                    Ok(
                        match secrets::check_ref(s).and_then(|()| secrets::resolve(&global, s)) {
                            Ok(_) => Validation::Valid,
                            Err(e) => Validation::Invalid(format!("{e:#}").into()),
                        },
                    )
                })
                .prompt_skippable()?
            else {
                return Ok(None);
            };
            r.trim().to_string()
        }
    }))
}

/// A hidden paste, trimmed; `None` when skipped.
fn paste(label: &str) -> Result<Option<String>> {
    Ok(Password::new(&format!("Paste the {label}:"))
        .without_confirmation()
        .with_help_message("hidden; never written to a file")
        .with_validator(|s: &str| {
            Ok(if s.trim().is_empty() {
                Validation::Invalid("empty".into())
            } else {
                Validation::Valid
            })
        })
        .prompt_skippable()?
        .map(|s| s.trim().to_string()))
}

fn keychain_has(account: &str) -> bool {
    keyring::Entry::new(crate::names::instance(), account)
        .and_then(|e| e.get_password())
        .is_ok()
}

/// Whether the keychain holds anything under `account`. Only a definite "no entry" is free:
/// an entry the keychain can't read may still be another env's secret.
fn keychain_taken(account: &str) -> Result<bool> {
    let svc = crate::names::instance();
    match keyring::Entry::new(svc, account).and_then(|e| e.get_password()) {
        Err(keyring::Error::NoEntry) => Ok(false),
        Ok(_) | Err(keyring::Error::BadEncoding(_) | keyring::Error::Ambiguous(_)) => Ok(true),
        Err(e) => Err(e).with_context(|| format!("read {svc}/{account} from the OS keychain")),
    }
}

/// The first of `base`, `base-2`, `base-3`, … that holds nothing: the vault keeps secrets by
/// ref, so a paste never replaces one another env may use.
fn free_account(base: &str, taken: impl Fn(&str) -> Result<bool>) -> Result<String> {
    for n in 1..=99 {
        let account = match n {
            1 => base.to_string(),
            n => format!("{base}-{n}"),
        };
        if !taken(&account)? {
            return Ok(account);
        }
    }
    let svc = crate::names::instance();
    bail!("{svc}/{base} through {base}-99 are all taken in your keychain")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_paste_takes_the_first_free_account() {
        let free =
            |held: &[&str]| free_account("anthropic.api_key", |a| Ok(held.contains(&a))).unwrap();
        assert_eq!(free(&[]), "anthropic.api_key");
        assert_eq!(free(&["anthropic.api_key"]), "anthropic.api_key-2");
        assert_eq!(
            free(&["anthropic.api_key", "anthropic.api_key-2"]),
            "anthropic.api_key-3"
        );
        assert_eq!(free(&["anthropic.api_key-2"]), "anthropic.api_key");
        assert!(free_account("x", |_| bail!("keychain locked")).is_err());
        assert!(free_account("x", |_| Ok(true)).is_err());
    }
}
