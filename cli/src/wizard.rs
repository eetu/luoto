//! Questions asked one at a time: the `luoto init` walk-through (`c` at its prompt), where each
//! starts from the current value and Esc keeps it, and the credential questions it shares with
//! `up`, `agent run` and `agent auth`, where Esc goes back a question.

use std::collections::HashMap;
use std::fmt;

use anyhow::{Context, Result, bail};
use inquire::list_option::ListOption;
use inquire::type_aliases::Sorter;
use inquire::validator::Validation;
use inquire::{MultiSelect, Password, Select, Text};
use luoto_shared::{presets, profiles};

use crate::agents::{self, Auth};
use crate::config::{EnvConfig, GlobalConfig, Isolation};
use crate::detect;
use crate::init::Proposal;
use crate::secrets::{self, OpAccount, OpItem, OpVault};
use crate::text::display;

#[derive(Clone)]
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

/// Walk the proposal's settings; the credential questions follow each agent that needs one.
pub fn customize(p: &mut Proposal, global: &GlobalConfig) -> Result<()> {
    println!();
    isolation(p)?;
    pick_presets(p)?;
    toolchains(p)?;
    pick_agents(&mut p.cfg)?;
    for name in p.cfg.agents.names().cloned().collect::<Vec<_>>() {
        let Some(a) = profiles::agent(&name) else {
            continue;
        };
        if agents::has_credential(&p.cfg, &a) {
            continue;
        }
        let now = match credential(&a, global, None, "later")? {
            Answer::Set(auth) => {
                let (key, value) = auth.entry();
                p.cfg
                    .credentials
                    .set_provider_kind(auth.provider(), key, &value)?;
                Some(auth)
            }
            Answer::Leave => None,
        };
        agents::settle(&p.name, &name, &a, now.as_ref());
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

/// An answer, or Esc: back to the question before.
pub enum Step<T> {
    Got(T),
    Back,
}

impl<T> From<Option<T>> for Step<T> {
    fn from(o: Option<T>) -> Self {
        o.map_or(Step::Back, Step::Got)
    }
}

/// Puts a menu to the user: the index picked, opening on the given one, or Esc.
trait Menu: FnMut(&str, Vec<Choice<usize>>, usize, &str) -> Result<Step<usize>> {}

impl<F: FnMut(&str, Vec<Choice<usize>>, usize, &str) -> Result<Step<usize>>> Menu for F {}

fn terminal_menu(
    question: &str,
    options: Vec<Choice<usize>>,
    at: usize,
    help: &str,
) -> Result<Step<usize>> {
    Ok(Select::new(question, options)
        .with_formatter(&short)
        .with_starting_cursor(at)
        .with_help_message(help)
        .prompt_skippable()?
        .map(|c| c.value)
        .into())
}

/// `options` put to `menu`, opening on `at`: the index and value picked.
fn pick<T: Clone>(
    menu: &mut impl Menu,
    question: &str,
    options: &[Choice<T>],
    at: usize,
    help: &str,
) -> Result<Step<(usize, T)>> {
    let indexed = options
        .iter()
        .enumerate()
        .map(|(i, o)| choice(i, o.short.clone(), o.label.clone()))
        .collect();
    let at = at.min(options.len().saturating_sub(1));
    Ok(match menu(question, indexed, at, help)? {
        Step::Got(i) => Step::Got((i, options[i].value.clone())),
        Step::Back => Step::Back,
    })
}

const MENU_HELP: &str = "↑↓ to move, Enter to pick, Esc: back";

/// A menu's help where Esc doesn't go back (`esc` says what it does), as at a walk's first
/// question.
pub fn menu_help(esc: &str) -> String {
    format!("↑↓ to move, Enter to pick, Esc: {esc}")
}

const LATER: &str = "later: luoto asks again at the next `up` or `agent run`";

/// What the credential questions settle on.
#[derive(Debug, PartialEq)]
pub enum Answer {
    Set(Auth),
    /// The config stays as it is: "later", Esc at the first question, or what it has, picked
    /// again.
    Leave,
}

/// An entry of the "Authenticate with:" menu.
#[derive(Clone, PartialEq)]
enum Pick {
    Kind(String),
    LoginInside,
    Later,
}

/// Where a credential of a known kind is kept.
#[derive(Clone, Copy, PartialEq)]
enum Source {
    /// The reference the config has for it now.
    Current,
    /// A reference the config has already, for another account (index into `known`).
    Known(usize),
    InKeychain,
    PasteKeychain,
    Paste1Password,
    Reference,
    Later,
}

/// What [`secret`] settles on.
pub enum Secret {
    Ref(String),
    Later,
}

/// What [`secret`] asks for.
pub struct SecretAsk<'a> {
    /// What it is, e.g. "GitHub token".
    pub label: &'a str,
    /// Its account under luoto's service in the OS keychain.
    pub acct: &'a str,
    /// The title of a new 1Password item for it.
    pub title: &'a str,
    /// The label of the "later" entry, last in the menu; `None` leaves it out.
    pub later: Option<&'a str>,
    /// References the config has for other accounts, as (what for, reference), offered first
    /// so one token can serve several.
    pub known: &'a [(String, String)],
    /// The reference the config has for it now: offered first, to keep, and where a typed
    /// reference starts.
    pub current: Option<&'a str>,
    /// The first menu's help, which says what Esc does there.
    pub help: &'a str,
}

/// Ask how agent `a` authenticates: the provider (when it has several), the kind, with where to
/// get one, then where it is kept. `current`, what the env's config has (`luoto agent auth`),
/// fixes the provider, and each question opens on it; `esc` says what Esc does at the first
/// question. A pasted secret is in the OS keychain or 1Password by the time this returns, and
/// only its reference goes in the config.
pub fn credential(
    a: &profiles::Agent,
    global: &GlobalConfig,
    current: Option<&Auth>,
    esc: &str,
) -> Result<Answer> {
    credential_with(
        a,
        current,
        esc,
        &mut terminal_menu,
        &mut |ask: &SecretAsk| secret(ask, global),
    )
}

/// [`credential`], its menus put through `menu` and where the secret is kept asked by `secret`.
fn credential_with(
    a: &profiles::Agent,
    current: Option<&Auth>,
    esc: &str,
    menu: &mut impl Menu,
    secret: &mut impl FnMut(&SecretAsk) -> Result<Step<Secret>>,
) -> Result<Answer> {
    let providers: Vec<String> = match current {
        Some(c) => vec![c.provider().to_string()],
        None => a.providers.clone(),
    };
    let first = menu_help(esc);
    let several = providers.len() > 1;
    let options: Vec<Choice<String>> = providers
        .iter()
        .filter_map(|n| {
            profiles::provider(n)
                .map(|p| choice(n.clone(), n, format!("{n:<11} {}", p.description)))
        })
        .collect();
    let mut at = 0;
    loop {
        let name = if several {
            let question = format!("Model provider for {}:", a.description);
            match pick(menu, &question, &options, at, &first)? {
                Step::Got((i, n)) => {
                    at = i;
                    n
                }
                Step::Back => return Ok(Answer::Leave),
            }
        } else if let Some(n) = providers.first() {
            n.clone()
        } else {
            return Ok(Answer::Leave);
        };
        let help = if several { MENU_HELP } else { &first };
        match provider_auth(a, &name, current, help, menu, secret)? {
            Step::Got(answer) => return Ok(answer),
            Step::Back if several => {}
            Step::Back => return Ok(Answer::Leave),
        }
    }
}

/// How agent `a` authenticates to `provider_name`: the kind, then where it is kept. `help` is
/// the first of these questions' help; `Back` is Esc there.
fn provider_auth(
    a: &profiles::Agent,
    provider_name: &str,
    current: Option<&Auth>,
    help: &str,
    menu: &mut impl Menu,
    secret: &mut impl FnMut(&SecretAsk) -> Result<Step<Secret>>,
) -> Result<Step<Answer>> {
    let p = profiles::provider(provider_name)
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
    let login = !p.login_hosts.is_empty();
    let is_current = |pick: &Pick| match (current, pick) {
        (Some(Auth::Kind { kind, .. }), Pick::Kind(k)) => kind == k,
        (Some(Auth::LoginInside { .. }), Pick::LoginInside) => true,
        _ => false,
    };
    let mut options: Vec<Choice<Pick>> = kinds
        .iter()
        .map(|k| {
            let label = &p.auth[k].label;
            choice(Pick::Kind(k.clone()), label, format!("{label} ({k})"))
        })
        .collect();
    if login {
        options.push(choice(
            Pick::LoginInside,
            "log in inside the sandbox",
            "log in inside the sandbox: the session lives in the env, readable by its code",
        ));
    }
    // With a setting to keep, Esc keeps it.
    if current.is_none() {
        options.push(choice(Pick::Later, "later", LATER));
    }
    if options.is_empty() {
        return Ok(Step::Got(Answer::Leave));
    }
    for o in options.iter_mut().filter(|o| is_current(&o.value)) {
        o.label.push_str(" (current)");
    }
    // One kind and no login: straight to where it is kept.
    let asks = kinds.len() != 1 || login;
    if asks {
        // Where each comes from, before the choice rather than after it.
        for k in &kinds {
            let how = &p.auth[k];
            println!("  {}: {}", how.label, how.how);
        }
    }
    let mut at = options
        .iter()
        .position(|o| is_current(&o.value))
        .unwrap_or(0);
    loop {
        let kind = if asks {
            match pick(menu, "Authenticate with:", &options, at, help)? {
                Step::Back => return Ok(Step::Back),
                Step::Got((i, pick)) => {
                    at = i;
                    match pick {
                        Pick::Later => return Ok(Step::Got(Answer::Leave)),
                        Pick::LoginInside => {
                            let auth = Auth::LoginInside {
                                provider: provider_name.to_string(),
                            };
                            return Ok(Step::Got(changed(current, auth)));
                        }
                        Pick::Kind(k) => k,
                    }
                }
            }
        } else {
            println!("  {}", p.auth[&kinds[0]].how);
            kinds[0].clone()
        };
        let kept = match current {
            Some(Auth::Kind {
                kind: k, reference, ..
            }) if *k == kind => Some(reference.as_str()),
            _ => None,
        };
        let title = format!("luoto {provider_name} {kind}");
        let acct = format!("{provider_name}.{kind}");
        let ask = SecretAsk {
            label: &p.auth[&kind].label,
            acct: &acct,
            title: &title,
            later: current.is_none().then_some(LATER),
            known: &[],
            current: kept,
            help: if asks { MENU_HELP } else { help },
        };
        match secret(&ask)? {
            Step::Got(Secret::Ref(reference)) => {
                let auth = Auth::Kind {
                    provider: provider_name.to_string(),
                    kind,
                    reference,
                };
                return Ok(Step::Got(changed(current, auth)));
            }
            Step::Got(Secret::Later) => return Ok(Step::Got(Answer::Leave)),
            Step::Back if asks => {}
            Step::Back => return Ok(Step::Back),
        }
    }
}

/// `auth`, unless the config has it already.
fn changed(current: Option<&Auth>, auth: Auth) -> Answer {
    if current == Some(&auth) {
        Answer::Leave
    } else {
        Answer::Set(auth)
    }
}

/// Where a secret is kept, as a reference the host resolves: the one the config has, one of
/// the `known` ones, the keychain entry `acct` of luoto's service, pasted into the keychain or
/// into 1Password, or a reference to where it is already. Esc goes back a question; `Back` is
/// Esc at the first.
pub fn secret(ask: &SecretAsk, global: &GlobalConfig) -> Result<Step<Secret>> {
    let svc = crate::names::instance();
    let in_keychain = format!("keyring:{svc}/{}", ask.acct);
    let mut options: Vec<Choice<Source>> = Vec::new();
    if let Some(r) = ask.current {
        options.push(choice(
            Source::Current,
            "the current one",
            format!("keep the current one ({})", secrets::shown_ref(r)),
        ));
    }
    options.extend(
        ask.known
            .iter()
            .enumerate()
            .filter(|(_, (_, r))| Some(r.as_str()) != ask.current)
            .map(|(i, (what, r))| {
                choice(
                    Source::Known(i),
                    format!("the one for {what}"),
                    format!("the same as for {what} ({})", secrets::shown_ref(r)),
                )
            }),
    );
    if ask.current != Some(in_keychain.as_str()) && keychain_has(ask.acct) {
        options.push(choice(
            Source::InKeychain,
            "the one in your keychain",
            format!("the one already in your keychain ({svc}/{})", ask.acct),
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
    options.push(choice(
        Source::Reference,
        "a secret reference",
        "a reference to where it already is: op://…, vault://…, keyring:…, env:…, file:…",
    ));
    if let Some(later) = ask.later {
        options.push(choice(Source::Later, "later", later));
    }
    let question = format!("The {}:", ask.label);
    let mut at = 0;
    loop {
        let source = match pick(&mut terminal_menu, &question, &options, at, ask.help)? {
            Step::Back => return Ok(Step::Back),
            Step::Got((i, s)) => {
                at = i;
                s
            }
        };
        let r = match source {
            Source::Current => ask.current.unwrap_or_default().to_string(),
            Source::Known(i) => ask.known[i].1.clone(),
            Source::Later => return Ok(Step::Got(Secret::Later)),
            Source::InKeychain => in_keychain.clone(),
            Source::PasteKeychain => {
                let Step::Got(secret) = paste(ask.label)? else {
                    continue;
                };
                let free = free_account(ask.acct, keychain_taken)?;
                keyring::Entry::new(svc, &free)
                    .and_then(|e| e.set_password(&secret))
                    .context("store the secret in the OS keychain")?;
                if free == ask.acct {
                    println!("stored in your keychain as {svc}/{free}");
                } else {
                    println!(
                        "stored in your keychain as {svc}/{free} \
                         ({svc}/{} holds another one, kept as it is)",
                        ask.acct
                    );
                }
                format!("keyring:{svc}/{free}")
            }
            Source::Paste1Password => match op_paste(global, ask.label, ask.title)? {
                Step::Got(r) => r,
                Step::Back => continue,
            },
            Source::Reference => match reference(global, ask.label, ask.current)? {
                Step::Got(r) => r,
                Step::Back => continue,
            },
        };
        return Ok(Step::Got(Secret::Ref(r)));
    }
}

/// A secret pasted into a new 1Password item (`title`), in the account (when the app has
/// several) and vault picked before it: the paste is the last question, so going back never
/// drops one. Its reference; `Back` is Esc at the first question.
fn op_paste(global: &GlobalConfig, label: &str, title: &str) -> Result<Step<String>> {
    let accounts = op_accounts(global);
    let mut vaults: HashMap<Option<String>, Vec<OpVault>> = HashMap::new();
    let mut at_vault = 0;
    loop {
        let account = if accounts.is_empty() {
            None
        } else {
            match pick_op_account("1Password account to save it in:", &accounts, None)? {
                Step::Got(a) => a,
                Step::Back => return Ok(Step::Back),
            }
        };
        let list = match vaults.entry(account.clone()) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(e) => {
                at_vault = 0;
                e.insert(secrets::op_vaults(global, account.as_deref())?)
            }
        };
        if list.is_empty() {
            bail!("no 1Password vaults to choose from: `op vault list` gave none");
        }
        loop {
            let names = list.iter().map(|v| display(&v.name)).collect();
            let Step::Got(i) = pick_index("1Password vault:", names, at_vault)? else {
                break;
            };
            at_vault = i;
            let Step::Got(secret) = paste(label)? else {
                continue;
            };
            let vault = &list[i];
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
            return Ok(Step::Got(r));
        }
        if accounts.is_empty() {
            return Ok(Step::Back);
        }
    }
}

#[derive(Clone)]
enum How {
    Type,
    Browse,
}

/// A reference to the `label`: typed (starting from `current`), or found by browsing
/// 1Password when `op` can list its vaults.
fn reference(global: &GlobalConfig, label: &str, current: Option<&str>) -> Result<Step<String>> {
    let browsing = can_browse(global);
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
    let question = format!("Reference to the {label}:");
    let mut at = 0;
    loop {
        if browsing {
            match pick(&mut terminal_menu, &question, &options, at, MENU_HELP)? {
                Step::Back => return Ok(Step::Back),
                Step::Got((i, how)) => {
                    at = i;
                    if let How::Browse = how {
                        if let Step::Got(r) = browse(global, label)? {
                            return Ok(Step::Got(r));
                        }
                        continue;
                    }
                }
            }
        }
        match typed_reference(global, label, current)? {
            Step::Got(r) => return Ok(Step::Got(r)),
            Step::Back if browsing => {}
            Step::Back => return Ok(Step::Back),
        }
    }
}

/// Whether browsing 1Password can work: `op` is installed, and as a service account, may list
/// vaults.
fn can_browse(global: &GlobalConfig) -> bool {
    secrets::op_available()
        && (!secrets::op_service_account(global) || secrets::op_vaults(global, None).is_ok())
}

/// A reference typed, starting from `start`, and read once it is entered; with several
/// 1Password accounts, an `op://` one that didn't read is tried in the account picked.
fn typed_reference(
    global: &GlobalConfig,
    label: &str,
    start: Option<&str>,
) -> Result<Step<String>> {
    println!("  {OP_FIELDS}");
    let mut last = start.unwrap_or_default().to_string();
    loop {
        // The prompt checks only the form: reading the ref runs `op`, which may ask on the
        // terminal, so it runs after the prompt has given the terminal back.
        let Some(r) = Text::new(&format!("Reference to the {label}:"))
            .with_initial_value(&last)
            .with_placeholder("op://<vault>/<item>/<field>")
            .with_help_message("read from your secret store on Enter; Esc: back")
            .with_validator(|s: &str| {
                Ok(match secrets::check_ref(s.trim()) {
                    Ok(()) => Validation::Valid,
                    Err(e) => Validation::Invalid(format!("{e:#}").into()),
                })
            })
            .prompt_skippable()?
        else {
            return Ok(Step::Back);
        };
        let r = r.trim().to_string();
        // Read once here (the value is dropped), so a typo shows now rather than as a
        // locked credential at `up`.
        match readable(global, &r, label) {
            Ok(()) => return Ok(Step::Got(r)),
            Err(e) => show_error(&e),
        }
        last = r;
        // A ref naming no account is read from op's default; the token may be in another.
        if last.starts_with("op://") && secrets::op_parts(&last).1.is_none() {
            let accounts = op_accounts(global);
            if !accounts.is_empty()
                && let Step::Got(Some(a)) = pick_op_account(
                    "Which 1Password account holds it?",
                    &accounts,
                    Some("none of these: edit the reference"),
                )?
            {
                let with = secrets::op_with_account(&last, &a);
                match readable(global, &with, label) {
                    Ok(()) => return Ok(Step::Got(with)),
                    Err(e) => show_error(&e),
                }
                last = with;
            }
        }
    }
}

/// A reference found in 1Password: the account (when the app has several), vault, item, and
/// the field. It names them by ID, and that field is the only value read. Esc goes back a step,
/// to the earlier choice; past the first step, `Back`. Each list comes from `op` once: going
/// back asks 1Password for nothing, so no new unlock prompt.
fn browse(global: &GlobalConfig, label: &str) -> Result<Step<String>> {
    #[derive(Clone, Copy)]
    enum At {
        Account,
        Vault,
        Item,
        Field,
    }
    let accounts = op_accounts(global);
    let mut account: Option<String> = None;
    let mut vaults: HashMap<Option<String>, Vec<OpVault>> = HashMap::new();
    let mut items: HashMap<(Option<String>, String), Vec<OpItem>> = HashMap::new();
    // Where each list was left, to reopen it there.
    let (mut at_account, mut at_vault, mut at_item) = (0usize, 0usize, 0usize);
    let (mut vault, mut item): (Option<OpVault>, Option<OpItem>) = (None, None);
    let mut at = if accounts.is_empty() {
        At::Vault
    } else {
        At::Account
    };
    loop {
        match at {
            At::Account => {
                let Step::Got(i) = pick_index(
                    "1Password account:",
                    accounts
                        .iter()
                        .map(|a| account_label(a, &accounts))
                        .collect(),
                    at_account,
                )?
                else {
                    return Ok(Step::Back);
                };
                at_account = i;
                account = Some(accounts[i].id.clone());
                at = At::Vault;
            }
            At::Vault => {
                let list = match vaults.entry(account.clone()) {
                    std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                    std::collections::hash_map::Entry::Vacant(e) => {
                        match secrets::op_vaults(global, account.as_deref()) {
                            Ok(v) => e.insert(v),
                            Err(err) => {
                                show_error(&err);
                                return Ok(Step::Back);
                            }
                        }
                    }
                };
                if list.is_empty() {
                    println!("  no vaults in this account to choose from");
                    if accounts.is_empty() {
                        return Ok(Step::Back);
                    }
                    at = At::Account;
                    continue;
                }
                let names = list.iter().map(|v| display(&v.name)).collect();
                match pick_index("1Password vault:", names, at_vault)? {
                    Step::Got(i) => {
                        at_vault = i;
                        vault = Some(list[i].clone());
                        at_item = 0;
                        at = At::Item;
                    }
                    Step::Back if accounts.is_empty() => return Ok(Step::Back),
                    Step::Back => at = At::Account,
                }
            }
            At::Item => {
                let v = vault.clone().context("a vault is picked first")?;
                let list = match items.entry((account.clone(), v.id.clone())) {
                    std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                    std::collections::hash_map::Entry::Vacant(e) => {
                        match secrets::op_items(global, account.as_deref(), &v.id) {
                            Ok(i) => e.insert(i),
                            Err(err) => {
                                show_error(&err);
                                return Ok(Step::Back);
                            }
                        }
                    }
                };
                if list.is_empty() {
                    println!("  {} holds no items", display(&v.name));
                    at = At::Vault;
                    continue;
                }
                let shown = list.iter().map(OpItem::shown).collect();
                match pick_index("Item:", shown, at_item)? {
                    Step::Got(i) => {
                        at_item = i;
                        item = Some(list[i].clone());
                        at = At::Field;
                    }
                    Step::Back => at = At::Vault,
                }
            }
            At::Field => {
                let (v, it) = (
                    vault.clone().context("a vault is picked first")?,
                    item.clone().context("an item is picked first")?,
                );
                let Step::Got(field) = item_field(&it)? else {
                    at = At::Item;
                    continue;
                };
                let r = match secrets::op_item_ref(account.as_deref(), &v.id, &it, &field) {
                    Ok(r) => r,
                    Err(e) => {
                        show_error(&e);
                        continue;
                    }
                };
                match readable(global, &r, label) {
                    Ok(()) => {
                        println!("  reference: {}", secrets::shown_ref(&r));
                        return Ok(Step::Got(r));
                    }
                    Err(e) => show_error(&e),
                }
            }
        }
    }
}

/// Options a filter narrows keep the order they were given in (by name), rather than a score's.
const KEEP_ORDER: Sorter<'static> = &|o| o.sort_by_key(|&(i, _)| i);
const PAGE: usize = 12;
const BROWSE_HELP: &str = "type to filter, Enter to pick, Esc: back";

/// The index of the option picked from `shown` (escaped already), opening on `at`.
fn pick_index(question: &str, shown: Vec<String>, at: usize) -> Result<Step<usize>> {
    let at = at.min(shown.len().saturating_sub(1));
    let options: Vec<Choice<usize>> = shown
        .into_iter()
        .enumerate()
        .map(|(i, s)| choice(i, s.clone(), s))
        .collect();
    Ok(Select::new(question, options)
        .with_formatter(&short)
        .with_sorter(KEEP_ORDER)
        .with_page_size(PAGE)
        .with_starting_cursor(at)
        .with_help_message(BROWSE_HELP)
        .prompt_skippable()?
        .map(|c| c.value)
        .into())
}

/// The field of `item` to read: one of the fields its kind has (the secret's first), or one
/// typed.
fn item_field(item: &OpItem) -> Result<Step<String>> {
    const ANOTHER: &str = "another field (type its name)";
    let fields = secrets::op_kind_fields(&item.category);
    let default = secrets::op_field(&item.category);
    let mut shown: Vec<String> = fields.iter().map(|f| f.to_string()).collect();
    shown.push(ANOTHER.into());
    let at = default
        .and_then(|d| fields.iter().position(|f| *f == d))
        .unwrap_or(0);
    let question = format!(
        "Field of the {} item:",
        display(&secrets::op_kind(&item.category))
    );
    let Step::Got(i) = pick_index(&question, shown, at)? else {
        return Ok(Step::Back);
    };
    if let Some(f) = fields.get(i) {
        return Ok(Step::Got(f.to_string()));
    }
    let typed = Text::new("Field:")
        .with_help_message("the field's name as 1Password shows it; Esc: back")
        .with_validator(|s: &str| {
            Ok(match secrets::check_op_field(s.trim()) {
                Ok(()) => Validation::Valid,
                Err(e) => Validation::Invalid(format!("{e:#}").into()),
            })
        })
        .prompt_skippable()?;
    Ok(typed.map(|s| s.trim().to_string()).into())
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
fn pick_op_account(
    question: &str,
    accounts: &[OpAccount],
    none: Option<&str>,
) -> Result<Step<Option<String>>> {
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
    Ok(
        match pick(&mut terminal_menu, question, &options, 0, MENU_HELP)? {
            Step::Got((_, id)) => Step::Got(id),
            Step::Back => Step::Back,
        },
    )
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

/// A hidden paste, trimmed.
fn paste(label: &str) -> Result<Step<String>> {
    Ok(Password::new(&format!("Paste the {label}:"))
        .without_confirmation()
        .with_help_message("hidden, never written to a file; Esc: back")
        .with_validator(|s: &str| {
            Ok(if s.trim().is_empty() {
                Validation::Invalid("empty".into())
            } else {
                Validation::Valid
            })
        })
        .prompt_skippable()?
        .map(|s| s.trim().to_string())
        .into())
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
    use std::collections::VecDeque;

    /// A menu as it was put to the user.
    struct Asked {
        question: String,
        labels: Vec<String>,
        at: usize,
        help: String,
    }

    /// What the questions of where a secret is kept were asked with.
    struct Kept {
        later: Option<String>,
        current: Option<String>,
        help: String,
    }

    struct Run {
        answer: Answer,
        menus: Vec<Asked>,
        kept: Vec<Kept>,
    }

    /// The credential questions for `agent`, answered in turn: a menu by its entry's short
    /// label, Esc as `None`; where the secret is kept by `secrets`. Every answer is used.
    fn run(
        agent: &str,
        current: Option<&Auth>,
        esc: &str,
        answers: &[Option<&str>],
        secrets: Vec<Step<Secret>>,
    ) -> Run {
        let a = profiles::agent(agent).unwrap();
        let mut answers: VecDeque<Option<&str>> = answers.iter().copied().collect();
        let mut secrets: VecDeque<Step<Secret>> = secrets.into();
        let (mut menus, mut kept) = (Vec::new(), Vec::new());
        let answer = credential_with(
            &a,
            current,
            esc,
            &mut |question: &str, options: Vec<Choice<usize>>, at: usize, help: &str| {
                menus.push(Asked {
                    question: question.into(),
                    labels: options.iter().map(|o| o.label.clone()).collect(),
                    at,
                    help: help.into(),
                });
                Ok(
                    match answers.pop_front().expect("a menu no answer was left for") {
                        None => Step::Back,
                        Some(s) => Step::Got(options.iter().position(|o| o.short == s).unwrap()),
                    },
                )
            },
            &mut |ask: &SecretAsk| {
                kept.push(Kept {
                    later: ask.later.map(str::to_string),
                    current: ask.current.map(str::to_string),
                    help: ask.help.into(),
                });
                Ok(secrets
                    .pop_front()
                    .expect("a secret no answer was left for"))
            },
        )
        .unwrap();
        assert!(
            answers.is_empty() && secrets.is_empty(),
            "answers left over"
        );
        Run {
            answer,
            menus,
            kept,
        }
    }

    fn kind(provider: &str, kind: &str, reference: &str) -> Auth {
        Auth::Kind {
            provider: provider.into(),
            kind: kind.into(),
            reference: reference.into(),
        }
    }

    fn inside(provider: &str) -> Auth {
        Auth::LoginInside {
            provider: provider.into(),
        }
    }

    const TOKEN: &str = "Claude subscription token";
    const API_KEY: &str = "Anthropic API key (billed per use)";
    const LOGIN: &str = "log in inside the sandbox";

    #[test]
    fn esc_or_later_at_the_first_question_writes_nothing() {
        for answer in [None, Some("later")] {
            let r = run("claude", None, "later", &[answer], vec![]);
            assert_eq!(r.answer, Answer::Leave);
            assert_eq!(r.menus[0].question, "Authenticate with:");
            assert_eq!(r.menus[0].help, "↑↓ to move, Enter to pick, Esc: later");
            assert_eq!(r.menus[0].labels.last().unwrap(), LATER);
        }
    }

    #[test]
    fn a_login_inside_only_when_picked() {
        let r = run("claude", None, "later", &[Some(LOGIN)], vec![]);
        assert_eq!(r.answer, Answer::Set(inside("anthropic")));
        // A provider with no other way in still asks.
        let r = run("agy", None, "later", &[None], vec![]);
        assert_eq!(r.answer, Answer::Leave);
        assert_eq!(r.menus[0].labels.len(), 2);
        let r = run("agy", None, "later", &[Some(LOGIN)], vec![]);
        assert_eq!(r.answer, Answer::Set(inside("antigravity")));
    }

    #[test]
    fn esc_where_it_is_kept_goes_back_to_the_kind() {
        let r = run(
            "claude",
            None,
            "later",
            &[Some(API_KEY), Some(TOKEN)],
            vec![Step::Back, Step::Got(Secret::Ref("env:T".into()))],
        );
        assert_eq!(
            r.answer,
            Answer::Set(kind("anthropic", "oauth_token", "env:T"))
        );
        // The suggested kind first; back, the menu opens where it was left.
        assert_eq!((r.menus[0].at, r.menus[1].at), (0, 1));
        assert_eq!(r.kept[0].help, MENU_HELP);
        assert_eq!(r.kept[0].later.as_deref(), Some(LATER));
        let r = run(
            "claude",
            None,
            "later",
            &[Some(TOKEN)],
            vec![Step::Got(Secret::Later)],
        );
        assert_eq!(r.answer, Answer::Leave);
    }

    #[test]
    fn one_kind_and_no_login_starts_where_it_is_kept() {
        let r = run("copilot", None, "later", &[], vec![Step::Back]);
        assert_eq!(r.answer, Answer::Leave);
        assert!(r.menus.is_empty());
        assert_eq!(r.kept[0].help, menu_help("later"));
    }

    #[test]
    fn several_providers_go_back_to_the_provider() {
        let r = run(
            "opencode",
            None,
            "later",
            &[Some("openai"), None, None],
            vec![],
        );
        assert_eq!(r.answer, Answer::Leave);
        let asked: Vec<(&str, &str)> = r
            .menus
            .iter()
            .map(|m| (m.question.as_str(), m.help.as_str()))
            .collect();
        assert_eq!(
            asked,
            [
                (
                    "Model provider for OpenCode:",
                    "↑↓ to move, Enter to pick, Esc: later"
                ),
                ("Authenticate with:", MENU_HELP),
                (
                    "Model provider for OpenCode:",
                    "↑↓ to move, Enter to pick, Esc: later"
                ),
            ]
        );
        assert_eq!(r.menus[2].at, 1);
    }

    #[test]
    fn a_change_opens_on_what_the_env_has() {
        let now = kind(
            "anthropic",
            "oauth_token",
            "keyring:luoto/anthropic.oauth_token",
        );
        // Enter, Enter: the current one kept.
        let kept = Step::Got(Secret::Ref("keyring:luoto/anthropic.oauth_token".into()));
        let r = run(
            "claude",
            Some(&now),
            "unchanged",
            &[Some(TOKEN)],
            vec![kept],
        );
        assert_eq!(r.answer, Answer::Leave);
        let m = &r.menus[0];
        assert_eq!(m.help, "↑↓ to move, Enter to pick, Esc: unchanged");
        assert_eq!(m.labels[m.at], format!("{TOKEN} (oauth_token) (current)"));
        assert!(!m.labels.iter().any(|l| l == LATER));
        assert_eq!(
            r.kept[0].current.as_deref(),
            Some("keyring:luoto/anthropic.oauth_token")
        );
        assert_eq!(r.kept[0].later, None);

        let r = run(
            "claude",
            Some(&now),
            "unchanged",
            &[Some(API_KEY)],
            vec![Step::Got(Secret::Ref("env:KEY".into()))],
        );
        assert_eq!(
            r.answer,
            Answer::Set(kind("anthropic", "api_key", "env:KEY"))
        );
        assert_eq!(r.kept[0].current, None);

        let r = run(
            "claude",
            Some(&inside("anthropic")),
            "unchanged",
            &[None],
            vec![],
        );
        assert_eq!(r.answer, Answer::Leave);
        let m = &r.menus[0];
        assert_eq!(
            m.labels[m.at],
            format!(
                "{}: the session lives in the env, readable by its code (current)",
                LOGIN
            )
        );
    }

    #[test]
    fn a_change_keeps_the_provider_the_env_has() {
        let now = kind("openai", "api_key", "env:KEY");
        let r = run("opencode", Some(&now), "unchanged", &[None], vec![]);
        assert_eq!(r.answer, Answer::Leave);
        assert_eq!(r.menus.len(), 1);
        assert_eq!(r.menus[0].question, "Authenticate with:");
    }

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
