//! Questions asked one at a time: the `luoto init` walk-through (`c` at its prompt) and the
//! credential question `luoto agent run` shares with it. Each starts from the current value,
//! and Esc keeps that value.

use std::collections::BTreeMap;
use std::fmt;

use anyhow::{Context, Result, bail};
use inquire::list_option::ListOption;
use inquire::type_aliases::Sorter;
use inquire::validator::Validation;
use inquire::{MultiSelect, Password, Select, Text};
use luoto_shared::{presets, profiles};

use crate::config::{EnvConfig, GlobalConfig, Isolation, ProviderValue};
use crate::detect;
use crate::init::Proposal;
use crate::secrets::{self, OpAccount, OpItem, OpVault};
use crate::text::display;

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
        .map(|t| crate::text::display(&format!("{} {} ({})", t.tool, t.version, t.source)))
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
    let menu = options.len() > 1;
    let auth = if !menu {
        options.remove(0).value
    } else {
        // Where each comes from, before the choice rather than after it.
        for k in &kinds {
            let a = &p.auth[k];
            println!("  {}: {}", a.label, a.how);
        }
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
    if !menu {
        println!("  {}", how.how);
    }
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
                format!("the same as for {what} ({})", secrets::shown_ref(r)),
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
            let accounts = op_accounts(global);
            let account = if accounts.is_empty() {
                None
            } else {
                match pick_op_account("1Password account to save it in:", &accounts, None)? {
                    Some(a) => Some(a),
                    None => return Ok(None),
                }
            };
            let vaults = secrets::op_vaults(global, account.as_deref())?;
            let Some(vault) = pick_vault(&vaults)? else {
                return Ok(None);
            };
            let note = format!(
                "{label}. luoto hands it to its gate, which adds it to requests; the sandbox \
                 never sees it."
            );
            let r = secrets::op_save(global, account.as_deref(), &vault.id, title, &secret, &note)?;
            println!(
                "saved in 1Password ({}) as \"{title}\": {}",
                display(&vault.name),
                secrets::shown_ref(&r)
            );
            r
        }
        Source::Reference => match reference(global, label)? {
            Some(r) => r,
            None => return Ok(None),
        },
    }))
}

enum How {
    Type,
    Browse,
}

/// A reference to the `label`: typed, or found by browsing 1Password when `op` can list its
/// vaults. `None` when skipped.
fn reference(global: &GlobalConfig, label: &str) -> Result<Option<String>> {
    if can_browse(global) {
        loop {
            let options = vec![
                choice(
                    How::Type,
                    "type it",
                    "type it: op://…, vault://…, keyring:…, env:…, file:…",
                ),
                choice(
                    How::Browse,
                    "browse 1Password",
                    "browse 1Password: account, vault, item",
                ),
            ];
            let Some(how) = Select::new(&format!("Reference to the {label}:"), options)
                .with_formatter(&short)
                .prompt_skippable()?
            else {
                return Ok(None);
            };
            match how.value {
                How::Type => break,
                How::Browse => {
                    if let Some(r) = browse(global, label)? {
                        return Ok(Some(r));
                    }
                }
            }
        }
    }
    typed_reference(global, label)
}

/// Whether browsing 1Password can work: `op` is installed, and as a service account, may list
/// vaults.
fn can_browse(global: &GlobalConfig) -> bool {
    secrets::op_available()
        && (!secrets::op_service_account(global) || secrets::op_vaults(global, None).is_ok())
}

/// A reference typed, and read once it is entered; with several 1Password accounts, an
/// `op://` one that didn't read is tried in the account picked. `None` when skipped.
fn typed_reference(global: &GlobalConfig, label: &str) -> Result<Option<String>> {
    println!("  {OP_FIELDS}");
    let mut last = String::new();
    loop {
        // The prompt checks only the form: reading the ref runs `op`, which may ask on the
        // terminal, so it runs after the prompt has given the terminal back.
        let Some(r) = Text::new(&format!("Reference to the {label}:"))
            .with_initial_value(&last)
            .with_placeholder("op://<vault>/<item>/<field>")
            .with_help_message("read from your secret store on enter; Esc for later")
            .with_validator(|s: &str| {
                Ok(match secrets::check_ref(s.trim()) {
                    Ok(()) => Validation::Valid,
                    Err(e) => Validation::Invalid(format!("{e:#}").into()),
                })
            })
            .prompt_skippable()?
        else {
            return Ok(None);
        };
        let r = r.trim().to_string();
        // Read once here (the value is dropped), so a typo shows now rather than as a
        // locked credential at `up`.
        match readable(global, &r, label) {
            Ok(()) => return Ok(Some(r)),
            Err(e) => show_error(&e),
        }
        last = r;
        // A ref naming no account is read from op's default; the token may be in another.
        if last.starts_with("op://") && secrets::op_parts(&last).1.is_none() {
            let accounts = op_accounts(global);
            if !accounts.is_empty()
                && let Some(a) = pick_op_account(
                    "Which 1Password account holds it?",
                    &accounts,
                    Some("none of these: edit the reference"),
                )?
            {
                let with = secrets::op_with_account(&last, &a);
                match readable(global, &with, label) {
                    Ok(()) => return Ok(Some(with)),
                    Err(e) => show_error(&e),
                }
                last = with;
            }
        }
    }
}

/// A reference found in 1Password: the account (when the app has several), vault, item, and
/// the field the item's kind keeps its secret in or one typed. It names them by ID, and that
/// field is the only value read. `None` on Esc, or when `op` fails (its error shown).
fn browse(global: &GlobalConfig, label: &str) -> Result<Option<String>> {
    let accounts = op_accounts(global);
    let account = if accounts.is_empty() {
        None
    } else {
        match pick_op_account("1Password account:", &accounts, None)? {
            Some(a) => Some(a),
            None => return Ok(None),
        }
    };
    let account = account.as_deref();
    let vaults = match secrets::op_vaults(global, account) {
        Ok(v) => v,
        Err(e) => {
            show_error(&e);
            return Ok(None);
        }
    };
    let (vault, items) = loop {
        let Some(vault) = pick_vault(&vaults)? else {
            return Ok(None);
        };
        match secrets::op_items(global, account, &vault.id) {
            Ok(items) if items.is_empty() => {
                println!("  {} holds no items", display(&vault.name));
            }
            Ok(items) => break (vault, items),
            Err(e) => {
                show_error(&e);
                return Ok(None);
            }
        }
    };
    let options: Vec<Choice<usize>> = items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let shown = item.shown();
            choice(i, shown.clone(), shown)
        })
        .collect();
    let Some(picked) = Select::new("Item:", options)
        .with_formatter(&short)
        .with_sorter(KEEP_ORDER)
        .with_page_size(PAGE)
        .prompt_skippable()?
    else {
        return Ok(None);
    };
    let item = &items[picked.value];
    loop {
        let Some(field) = item_field(item)? else {
            return Ok(None);
        };
        let r = match secrets::op_item_ref(account, &vault.id, item, &field) {
            Ok(r) => r,
            Err(e) => {
                show_error(&e);
                return Ok(None);
            }
        };
        match readable(global, &r, label) {
            Ok(()) => {
                println!("  reference: {r}");
                return Ok(Some(r));
            }
            Err(e) => show_error(&e),
        }
    }
}

/// Options a filter narrows keep the order they were given in (by name), rather than a score's.
const KEEP_ORDER: Sorter<'static> = &|o| o.sort_by_key(|&(i, _)| i);
const PAGE: usize = 12;

/// A vault of `vaults`, by name; `None` when skipped.
fn pick_vault(vaults: &[OpVault]) -> Result<Option<&OpVault>> {
    if vaults.is_empty() {
        bail!("no 1Password vaults to choose from: `op vault list` gave none");
    }
    let options: Vec<Choice<usize>> = vaults
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let name = display(&v.name);
            choice(i, name.clone(), name)
        })
        .collect();
    Ok(Select::new("1Password vault:", options)
        .with_formatter(&short)
        .with_sorter(KEEP_ORDER)
        .with_page_size(PAGE)
        .prompt_skippable()?
        .map(|c| &vaults[c.value]))
}

/// The field of `item` to read: the one its kind keeps a secret in, offered as the default, or
/// one typed. `None` when skipped.
fn item_field(item: &OpItem) -> Result<Option<String>> {
    let default = secrets::op_field(&item.category);
    let help = match default {
        Some(_) => format!(
            "where {} items keep their secret; Enter takes it, or type another field's name",
            display(&secrets::op_kind(&item.category))
        ),
        None => "the name of the field that holds it, as 1Password shows it".to_string(),
    };
    let mut prompt = Text::new("Field:")
        .with_help_message(&help)
        .with_validator(|s: &str| {
            Ok(match secrets::check_op_field(s.trim()) {
                Ok(()) => Validation::Valid,
                Err(e) => Validation::Invalid(format!("{e:#}").into()),
            })
        });
    if let Some(d) = default {
        prompt = prompt.with_default(d);
    }
    Ok(prompt.prompt_skippable()?.map(|s| s.trim().to_string()))
}

fn show_error(e: &anyhow::Error) {
    println!("  {}", crate::text::lines(&format!("{e:#}")));
}

/// Whether reference `r` reads, as the token `label` alone.
fn readable(global: &GlobalConfig, r: &str, label: &str) -> Result<()> {
    let value = secrets::resolve(global, r)?;
    match not_alone(&value, label) {
        Some(why) => bail!("{why}"),
        None => Ok(()),
    }
}

/// The 1Password accounts to choose from: none when the app has one, or `op` runs as a service
/// account, which is in one.
fn op_accounts(global: &GlobalConfig) -> Vec<OpAccount> {
    if secrets::op_service_account(global) {
        return Vec::new();
    }
    let accounts = secrets::op_accounts();
    if accounts.len() < 2 {
        return Vec::new();
    }
    accounts
}

/// The ID of the account picked from `accounts`; `none` names a last choice that picks none.
/// `None` too when skipped.
fn pick_op_account(
    question: &str,
    accounts: &[OpAccount],
    none: Option<&str>,
) -> Result<Option<String>> {
    let mut options: Vec<Choice<Option<String>>> = accounts
        .iter()
        .map(|a| {
            let shown = account_label(a, accounts);
            choice(Some(a.id.clone()), shown.clone(), shown)
        })
        .collect();
    if let Some(n) = none {
        options.push(choice(None, n, n));
    }
    Ok(Select::new(question, options)
        .with_formatter(&short)
        .prompt_skippable()?
        .and_then(|c| c.value))
}

/// An account as its address and email, and its ID when another of `all` has the same two
/// (a personal and a family account, say).
fn account_label(a: &OpAccount, all: &[OpAccount]) -> String {
    let twins = all
        .iter()
        .filter(|b| b.address == a.address && b.email == a.email)
        .count();
    if twins > 1 {
        format!("{} ({})", a.shown(), a.id)
    } else {
        a.shown()
    }
}

/// The field a token is in, by 1Password item type.
const OP_FIELDS: &str = "In 1Password: an API Credential item's field is `credential`, a \
                         Password's `password`, a Secure Note's text `notesPlain` (the token \
                         alone in it)";

/// Why `value`, read from a reference to a token (`label`), isn't the token alone: tokens
/// carry no spaces or line breaks, a note or a field with more text in it does.
fn not_alone(value: &str, label: &str) -> Option<String> {
    if value.is_empty() {
        return Some(format!("it is empty; the {label} isn't there"));
    }
    value.contains(char::is_whitespace).then(|| {
        format!(
            "it holds more than the {label}: spaces or line breaks; keep the {label} alone in \
             that field"
        )
    })
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
    fn a_referenced_token_is_alone_in_its_field() {
        assert_eq!(not_alone("sk-ant-oat01-abc", "token"), None);
        for v in [
            "",
            "sk-ant-oat01-abc\nexpires 2027",
            "Claude token: sk-ant-oat01-abc",
        ] {
            assert!(not_alone(v, "token").is_some(), "{v:?}");
        }
    }

    #[test]
    fn accounts_alike_but_for_their_id_show_it() {
        let account = |id: &str, address: &str| OpAccount {
            id: id.into(),
            address: address.into(),
            email: "eetu@example.com".into(),
        };
        let all = [
            account("VZ7CWAKJKFHWVHZ3UFZQ5GPNSU", "my.1password.com"),
            account("Q3RTX2UJWVE2TMXFPN6HVOIB3Y", "my.1password.com"),
            account("ZK4ONHBXKRHVBDDVX4L7QTCSDM", "acme.1password.com"),
        ];
        assert_eq!(
            account_label(&all[1], &all),
            "my.1password.com, eetu@example.com (Q3RTX2UJWVE2TMXFPN6HVOIB3Y)"
        );
        assert_eq!(
            account_label(&all[2], &all),
            "acme.1password.com, eetu@example.com"
        );
    }

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
