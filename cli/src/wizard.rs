//! Questions asked one at a time: the `luoto init` walk-through (`c` at its prompt), where each
//! starts from the current value and Esc keeps it, and the credential questions of `up`,
//! `agent run`, `agent auth` and `repo auth`, where Esc goes back a question.

use std::collections::HashMap;
use std::fmt;

use anyhow::{Context, Result, bail};
use inquire::list_option::ListOption;
use inquire::type_aliases::Sorter;
use inquire::validator::Validation;
use inquire::{MultiSelect, Password, Select, Text};
use luoto_shared::{presets, profiles};

use crate::agents::Auth;
use crate::config::{EnvConfig, GlobalConfig, Isolation};
use crate::detect;
use crate::init::Proposal;
use crate::prompt::{Ask, menu_help, menu_rows};
use crate::runtime::Flavor;
use crate::secrets::{self, OpAccount, OpItem, OpVault};
use crate::text::{self, display};

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

/// Choices whose labels are a label and a description in two columns ([`menu_rows`]), each
/// echoed as its label; `width` leaves room for what inquire draws before an entry.
fn table<T>(rows: Vec<(T, String, String)>, width: usize) -> Vec<Choice<T>> {
    let shown = menu_rows(
        &rows
            .iter()
            .map(|(_, l, d)| (l.clone(), d.clone()))
            .collect::<Vec<_>>(),
        width,
    );
    rows.into_iter()
        .zip(shown)
        .map(|((value, label, _), shown)| choice(value, plain(&label), shown))
        .collect()
}

/// A label as the answered prompt echoes it: without its `(recommended)` or `(current)`.
fn plain(label: &str) -> String {
    label
        .trim_end_matches(" (recommended)")
        .trim_end_matches(" (current)")
        .to_string()
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

/// Walk the proposal's settings. Credentials wait for the env's first `up`, so nothing is
/// kept in a keychain or 1Password for an env that is never created.
pub fn customize(p: &mut Proposal) -> Result<()> {
    println!("\nEsc keeps the current value.");
    isolation(p)?;
    pick_presets(p)?;
    toolchains(p)?;
    pick_agents(&mut p.cfg)?;
    ports(&mut p.cfg)?;
    Ok(())
}

/// `luoto setup`'s runtime on a Mac that runs Apple's `container`, starting at `current`;
/// `None` for Esc.
pub fn pick_runtime(current: Option<Flavor>) -> Result<Option<Flavor>> {
    let offered = crate::setup::runtime_options(current);
    let start = offered.iter().position(|o| o.selected).unwrap_or(0);
    let rows = offered
        .into_iter()
        .map(|o| {
            // What the machine runs on now is the more useful mark when it is both.
            let label = if o.current {
                format!("{} (current)", o.label)
            } else if o.recommended {
                format!("{} (recommended)", o.label)
            } else {
                o.label
            };
            (o.runtime.flavor(), label, o.description)
        })
        .collect();
    let options = table(rows, text::columns());
    let help = menu_help(if current.is_some() {
        "unchanged"
    } else {
        "later"
    });
    Ok(Select::new("Run envs on:", options)
        .with_starting_cursor(start)
        .with_formatter(&short)
        .with_help_message(&help)
        .without_filtering()
        .ask()?
        .map(|c| c.value))
}

fn isolation(p: &mut Proposal) -> Result<()> {
    if !p.gvisor {
        return Ok(());
    }
    let options = table(
        vec![
            (
                Isolation::Gvisor,
                "gVisor (recommended)".into(),
                "its own kernel: exploits stay in the env, 1.6× slower".into(),
            ),
            (
                Isolation::Container,
                "container".into(),
                "shares the VM's kernel: 1.6× faster, weaker".into(),
            ),
        ],
        text::columns(),
    );
    let current = usize::from(p.cfg.isolation == Some(Isolation::Container));
    let help = menu_help("keep it");
    if let Some(c) = Select::new("Isolation:", options)
        .with_starting_cursor(current)
        .with_formatter(&short)
        .with_help_message(&help)
        .without_filtering()
        .ask()?
    {
        // gVisor is the default, so only the opt-out is written.
        p.cfg.isolation = (c.value == Isolation::Container).then_some(Isolation::Container);
    }
    Ok(())
}

/// A multi-select's entries: what inquire draws before one (`> [x] `) takes four more columns.
fn checklist(rows: Vec<(String, String)>) -> Vec<Choice<String>> {
    table(
        rows.into_iter().map(|(n, d)| (n.clone(), n, d)).collect(),
        text::columns() - 4,
    )
}

fn pick_presets(p: &mut Proposal) -> Result<()> {
    let options = checklist(
        presets::names()
            .map(|n| {
                let desc = presets::get(n).map(|p| p.description).unwrap_or_default();
                let found = p
                    .found
                    .presets
                    .iter()
                    .find(|(f, _)| f == n)
                    .map(|(_, file)| format!("[{file}] "))
                    .unwrap_or_default();
                (n.to_string(), format!("{found}{desc}"))
            })
            .collect(),
    );
    let selected: Vec<usize> = options
        .iter()
        .enumerate()
        .filter(|(_, o)| p.cfg.presets.contains(&o.value))
        .map(|(i, _)| i)
        .collect();
    if let Some(chosen) =
        MultiSelect::new("Egress presets (read access to these registries):", options)
            .with_default(&selected)
            .with_help_message("space toggles, Enter confirms; [file] = suggested by the folder")
            .with_formatter(&shorts)
            .ask()?
    {
        p.cfg.presets = chosen.into_iter().map(|c| c.value).collect();
    }
    Ok(())
}

/// What `luoto egress keep` keeps of `rows` (label, description, checked at first): the
/// indexes picked, or `None` for Esc, which keeps nothing.
pub fn pick_kept(rows: &[(String, String, bool)]) -> Result<Option<Vec<usize>>> {
    let selected: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, r)| r.2)
        .map(|(i, _)| i)
        .collect();
    let options = table(
        rows.iter()
            .enumerate()
            .map(|(i, (label, desc, _))| (i, label.clone(), desc.clone()))
            .collect(),
        text::columns() - 4,
    );
    Ok(MultiSelect::new("Keep in the env's config:", options)
        .with_default(&selected)
        .with_help_message("space toggles, Enter keeps what is checked, Esc: nothing")
        .with_formatter(&shorts)
        .ask()?
        .map(|chosen| chosen.into_iter().map(|c| c.value).collect()))
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
        .ask()?
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
    let options = checklist(
        profiles::agent_names()
            .map(|n| {
                let desc = profiles::agent(n)
                    .map(|a| a.description)
                    .unwrap_or_default();
                (n.to_string(), desc)
            })
            .collect(),
    );
    let selected: Vec<usize> = options
        .iter()
        .enumerate()
        .filter(|(_, o)| cfg.agents.contains(&o.value))
        .map(|(i, _)| i)
        .collect();
    if let Some(chosen) = MultiSelect::new("Coding agents:", options)
        .with_default(&selected)
        .with_help_message("space toggles, Enter confirms; the first `up` asks how each signs in")
        .with_formatter(&shorts)
        .ask()?
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
        .ask()?
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
    let page = options.len().max(1);
    Ok(Select::new(question, options)
        .with_formatter(&short)
        .with_starting_cursor(at)
        .with_help_message(help)
        .with_page_size(page)
        .without_filtering()
        .ask()?
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

/// A question put by [`ask_menu`]: its menu's labels and descriptions, and the one it opens on.
pub struct Question<T> {
    pub text: String,
    pub rows: Vec<(T, String, String)>,
    pub at: usize,
    pub help: String,
}

/// Ask `q` on the terminal: the value picked, or `None` for Esc.
pub fn ask_menu<T: Clone>(q: Question<T>) -> Result<Option<T>> {
    let options = table(q.rows, text::columns());
    Ok(
        match pick(&mut terminal_menu, &q.text, &options, q.at, &q.help)? {
            Step::Got((_, v)) => Some(v),
            Step::Back => None,
        },
    )
}

/// Whether the questions give a credential the env lacks, or another for one it has.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Mode {
    /// `up`, `agent run`, `agent add`: the first question offers "Later", and Esc there
    /// writes nothing; the next `up` asks again.
    Missing,
    /// `agent auth`, `repo auth`: each question opens on what the env has, marked
    /// `(current)`, and Esc at the first leaves it unchanged.
    Change,
}

impl Mode {
    /// What Esc does at the first question.
    pub fn esc(self) -> &'static str {
        match self {
            Mode::Missing => "later",
            Mode::Change => "unchanged",
        }
    }
}

/// What the credential questions settle on.
#[derive(Debug, PartialEq)]
pub enum Answer {
    Set(Auth),
    /// A model server: its own questions follow (`model_servers::ask`).
    ModelServer,
    /// The config stays as it is: "Later", Esc at the first question, or what it has, picked
    /// again.
    Leave,
}

/// An entry of the kind menu.
#[derive(Clone, PartialEq)]
enum Pick {
    Kind(String),
    ModelServer,
    LoginInside,
    Later,
}

/// A model server, as the first menu offers it beside the cloud's ways in.
const SERVER: &str = "A model server";
const SERVER_SHORT: &str = "yours, on this or another machine";

/// The login inside, as the kind menu offers it.
const LOGIN: &str = "Log in inside the env";
const LOGIN_SHORT: &str = "weaker: code in the env can read it";
const LATER: &str = "Later";
const LATER_SHORT: &str = "the agent can't connect without one";

/// Ask how agent `a` signs in: the provider (when it has several), the kind, then where it is
/// kept. `have` is what the env has, one per provider. A pasted secret is in the OS keychain or
/// 1Password by the time this returns, and only its reference goes in the config.
pub fn credential(
    a: &profiles::Agent,
    global: &GlobalConfig,
    have: &[Auth],
    on_server: bool,
    mode: Mode,
) -> Result<Answer> {
    credential_with(
        a,
        have,
        on_server,
        mode,
        &mut terminal_menu,
        &mut |ask: &SecretAsk| secret(ask, global),
    )
}

/// [`credential`], its menus put through `menu` and where the secret is kept asked by `secret`.
fn credential_with(
    a: &profiles::Agent,
    have: &[Auth],
    on_server: bool,
    mode: Mode,
    menu: &mut impl Menu,
    secret: &mut impl FnMut(&SecretAsk) -> Result<Step<Secret>>,
) -> Result<Answer> {
    let providers: Vec<profiles::Provider> = a
        .providers
        .iter()
        .filter_map(|n| profiles::provider(n))
        .collect();
    let intro = if providers.iter().any(|p| !p.auth.is_empty()) {
        format!(
            "{} needs a credential. The gate adds it to requests; the sandbox only sees a \
             placeholder.",
            a.title()
        )
    } else {
        format!(
            "{} logs in inside the env, with your own account.",
            a.title()
        )
    };
    println!("{}", text::wrap(&intro, "", text::columns()));
    // What the agent starts on is current: a model server, else the cloud's.
    let current = |n: &str| {
        have.iter()
            .find(|h| h.provider() == n)
            .filter(|_| !on_server)
    };
    let several = providers.len() > 1;
    let mut rows: Vec<(Option<Pick>, String, String)> = providers
        .iter()
        .map(|p| {
            let note = p.description[p.title().len()..]
                .trim()
                .trim_start_matches('(')
                .trim_end_matches(')');
            let mark = if current(&p.name).is_some() {
                " (current)"
            } else {
                ""
            };
            (
                Some(Pick::Kind(p.name.clone())),
                format!("{}{mark}", p.title()),
                note.to_string(),
            )
        })
        .collect();
    if a.model_server.is_some() {
        let mark = if on_server { " (current)" } else { "" };
        rows.push((
            Some(Pick::ModelServer),
            format!("{SERVER}{mark}"),
            SERVER_SHORT.into(),
        ));
    }
    if mode == Mode::Missing {
        rows.push((None, LATER.into(), LATER_SHORT.into()));
    }
    let mut at = rows
        .iter()
        .position(|(_, l, _)| l.ends_with(" (current)"))
        .unwrap_or(0);
    let options = table(rows, text::columns());
    let question = format!("Which provider should {} use?", a.title());
    let first = menu_help(mode.esc());
    loop {
        let p = if several {
            match pick(menu, &question, &options, at, &first)? {
                Step::Got((i, Some(Pick::Kind(n)))) => {
                    at = i;
                    providers
                        .iter()
                        .find(|p| p.name == n)
                        .context("a provider of the agent")?
                }
                Step::Got((_, Some(Pick::ModelServer))) => return Ok(Answer::ModelServer),
                Step::Got(_) | Step::Back => return Ok(Answer::Leave),
            }
        } else if let Some(p) = providers.first() {
            p
        } else {
            return Ok(Answer::Leave);
        };
        let how = How {
            who: a.title(),
            servers: a.model_server.is_some(),
            login: true,
            names_provider: false,
            provider: p,
            current: current(&p.name),
            stored: have.iter().find(|h| h.provider() == p.name),
            first: !several,
            on_server,
            mode,
        };
        match provider_auth(&how, menu, secret)? {
            Step::Got(answer) => return Ok(answer),
            Step::Back if several => {}
            Step::Back => return Ok(Answer::Leave),
        }
    }
}

/// How the env signs in to provider `p` for a project's `[needs]`, no agent's: the kind, then
/// where it is kept. `have`: what the env has for it now.
pub fn provider_credential(
    p: &profiles::Provider,
    global: &GlobalConfig,
    have: Option<&Auth>,
    mode: Mode,
) -> Result<Answer> {
    let how = How {
        who: "the env",
        servers: false,
        login: false,
        names_provider: true,
        provider: p,
        current: have,
        stored: have,
        first: true,
        on_server: false,
        mode,
    };
    Ok(
        match provider_auth(&how, &mut terminal_menu, &mut |ask: &SecretAsk| {
            secret(ask, global)
        })? {
            Step::Got(answer) => answer,
            Step::Back => Answer::Leave,
        },
    )
}

/// What [`provider_auth`] asks about.
struct How<'a> {
    /// Who signs in: an agent's name, or "the env".
    who: &'a str,
    /// "A model server" is offered beside the kinds (an agent that can use one).
    servers: bool,
    /// A login inside is offered where the provider allows one (an agent logs in).
    login: bool,
    /// The first question names the provider (no agent to name).
    names_provider: bool,
    provider: &'a profiles::Provider,
    /// What the env has for the provider, where the agent starts on it.
    current: Option<&'a Auth>,
    /// What the env has for the provider, a model server or not: offered to keep.
    stored: Option<&'a Auth>,
    /// Its first question is the step's first.
    first: bool,
    /// The agent starts on a model server.
    on_server: bool,
    mode: Mode,
}

/// The kind menu's entries: each kind, suggested first, with what sets it apart; a login
/// inside where the provider allows one; "Later" where this is the first question of a step
/// that may wait. What the env has is marked `(current)`, else the suggested kind
/// `(recommended)`.
fn kind_rows(h: &How) -> Vec<(Pick, String, String)> {
    let p = h.provider;
    let is_current = |pick: &Pick| match (h.current, pick) {
        (Some(Auth::Kind { kind, .. }), Pick::Kind(k)) => kind == k,
        (Some(Auth::LoginInside { .. }), Pick::LoginInside) => true,
        _ => false,
    };
    let mark = |pick: &Pick| {
        if is_current(pick) {
            " (current)"
        } else if h.current.is_none()
            && matches!(pick, Pick::Kind(k) if p.suggested.as_ref() == Some(k))
        {
            " (recommended)"
        } else {
            ""
        }
    };
    let mut rows: Vec<(Pick, String, String)> = p
        .kinds()
        .into_iter()
        .map(|k| {
            let pick = Pick::Kind(k.to_string());
            let label = format!("{}{}", p.auth[k].label, mark(&pick));
            (pick, label, p.auth[k].short.clone())
        })
        .collect();
    if h.first && h.servers {
        let mark = if h.on_server { " (current)" } else { "" };
        rows.push((
            Pick::ModelServer,
            format!("{SERVER}{mark}"),
            SERVER_SHORT.into(),
        ));
    }
    if h.login && !p.login_hosts.is_empty() {
        let label = format!("{LOGIN}{}", mark(&Pick::LoginInside));
        rows.push((Pick::LoginInside, label, LOGIN_SHORT.into()));
    }
    if h.first && h.mode == Mode::Missing {
        rows.push((Pick::Later, LATER.into(), LATER_SHORT.into()));
    }
    rows
}

/// How the agent signs in to one provider: the kind, its how-to, then where it is kept. `Back`
/// is Esc at the first of these questions.
fn provider_auth(
    h: &How,
    menu: &mut impl Menu,
    secret: &mut impl FnMut(&SecretAsk) -> Result<Step<Secret>>,
) -> Result<Step<Answer>> {
    let p = h.provider;
    let kinds = p.kinds();
    let rows = kind_rows(h);
    let inside = Auth::LoginInside {
        provider: p.name.clone(),
    };
    // Nothing to choose: the env has the provider's only way in.
    if kinds.is_empty() && rows.len() == 1 && h.current == Some(&inside) {
        return Ok(Step::Got(Answer::Leave));
    }
    // One kind and no login: no question of the kind.
    let asks = kinds.len() != 1 || (h.login && !p.login_hosts.is_empty());
    let first = menu_help(h.mode.esc());
    let back = menu_help("back");
    let help: &str = if h.first { &first } else { &back };
    let question = if h.first && !h.names_provider {
        format!("How should {} sign in?", h.who)
    } else {
        format!("How should {} sign in to {}?", h.who, p.title())
    };
    let mut at = rows
        .iter()
        .position(|(_, l, _)| l.ends_with(" (current)"))
        .unwrap_or(0);
    let options = table(rows, text::columns());
    loop {
        let kind = if asks {
            match pick(menu, &question, &options, at, help)? {
                Step::Back => return Ok(Step::Back),
                Step::Got((i, pick)) => {
                    at = i;
                    match pick {
                        Pick::Later => return Ok(Step::Got(Answer::Leave)),
                        Pick::ModelServer => return Ok(Step::Got(Answer::ModelServer)),
                        Pick::LoginInside => {
                            return Ok(Step::Got(changed(h.current, inside)));
                        }
                        Pick::Kind(k) => k,
                    }
                }
            }
        } else {
            kinds[0].to_string()
        };
        let auth = &p.auth[&kind];
        println!("{}", text::wrap(&auth.how, "  ", text::columns()));
        let kept = match h.stored {
            Some(Auth::Kind {
                kind: k, reference, ..
            }) if *k == kind => Some(reference.as_str()),
            _ => None,
        };
        let title = format!("luoto {} {kind}", p.name);
        let acct = format!("{}.{kind}", p.name);
        let ask = SecretAsk {
            label: &auth.label,
            acct: &acct,
            title: &title,
            later: !asks && h.first && h.mode == Mode::Missing,
            known: &[],
            current: kept,
            help: if asks { &back } else { help },
            kind: Some((&p.name, &kind)),
            how: None,
            shape: None,
        };
        match secret(&ask)? {
            Step::Got(Secret::Ref(reference)) => {
                let auth = Auth::Kind {
                    provider: p.name.clone(),
                    kind,
                    reference,
                };
                return Ok(Step::Got(changed(h.current, auth)));
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

/// What [`secret`] settles on.
pub enum Secret {
    Ref(String),
    Later,
}

/// What [`secret`] asks for.
pub struct SecretAsk<'a> {
    /// What it is, e.g. "GitHub token for acme".
    pub label: &'a str,
    /// Its account under luoto's service in the OS keychain.
    pub acct: &'a str,
    /// The title of a new 1Password item for it.
    pub title: &'a str,
    /// A "Later" entry, last: where this is the first question of a step that may wait.
    pub later: bool,
    /// References the config has for other accounts, as (what for, reference), offered first
    /// so one token can serve several.
    pub known: &'a [(String, String)],
    /// The reference the config has for it now: offered first, to keep, and where a typed
    /// reference starts.
    pub current: Option<&'a str>,
    /// The menu's help, which says what Esc does there.
    pub help: &'a str,
    /// The provider and auth kind it is: a value is checked against the kind's prefix.
    pub kind: Option<(&'a str, &'a str)>,
    /// How to make one, printed as it is once a source that takes a new one is picked.
    pub how: Option<&'a str>,
    /// The prefixes its issuer documents: a value without one is asked about.
    pub shape: Option<Shape<'a>>,
}

/// A token's documented prefixes, checked softly: a value without one may still be it (an
/// issuer adds kinds), so it is asked about rather than refused.
#[derive(Clone, Copy)]
pub struct Shape<'a> {
    /// What it is, with its article: "a GitHub token".
    pub what: &'a str,
    pub prefixes: &'a [&'a str],
    /// The prefixes named in the question.
    pub hint: &'a str,
}

impl Shape<'_> {
    pub fn fits(&self, value: &str) -> bool {
        self.prefixes.iter().any(|p| value.starts_with(p))
    }

    fn question(&self) -> String {
        format!(
            "It doesn't look like {} (they start with {}). Use it anyway?",
            self.what, self.hint
        )
    }
}

/// Whether `value` may be kept as `ask`'s secret: it has a prefix of its shape, or the user
/// says so (no without a terminal). Never shows the value.
fn shape_ok(ask: &SecretAsk, value: &str) -> bool {
    match ask.shape {
        Some(s) if !s.fits(value) => crate::prompt::confirm(&s.question()),
        _ => true,
    }
}

/// The 1Password items picked by browsing in this command, by ref, as browse listed them: a
/// ref names IDs only, so what the command prints after names the item instead.
static PICKED: std::sync::Mutex<Vec<(String, String)>> = std::sync::Mutex::new(Vec::new());

/// `r` as people see it: the 1Password item browsed for it in this command, else
/// [`secrets::shown_ref`].
pub fn shown_ref(r: &str) -> String {
    PICKED
        .lock()
        .ok()
        .and_then(|p| p.iter().find(|(k, _)| k == r).map(|(_, v)| v.clone()))
        .unwrap_or_else(|| secrets::shown_ref(r))
}

fn remember_pick(r: &str, item: &OpItem, vault: &OpVault) -> String {
    let shown = format!(
        "1Password item \"{}\" (vault {})",
        display(&item.title),
        display(&vault.name)
    );
    if let Ok(mut p) = PICKED.lock() {
        p.retain(|(k, _)| k != r);
        p.push((r.to_string(), shown.clone()));
    }
    shown
}

/// Where a secret is kept, as the source menu offers it.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Source {
    /// The reference the config has for it now.
    Current,
    /// A reference the config has already, for another account (index into `known`).
    Known(usize),
    InKeychain,
    PasteKeychain,
    Paste1Password,
    Browse,
    Reference,
    Later,
}

/// What this machine offers to keep a secret in.
struct Stores {
    /// luoto's keychain entry for it holds one already.
    in_keychain: bool,
    /// `op` works: paste into 1Password.
    op: bool,
    /// `op` can list vaults: browse 1Password.
    browse: bool,
}

/// The OS keychain, as its OS names it.
pub fn keychain() -> &'static str {
    if cfg!(target_os = "macos") {
        "your macOS Keychain"
    } else if cfg!(windows) {
        "Windows Credential Manager"
    } else {
        "the Secret Service keyring"
    }
}

/// The source menu: what the config has first, then the keychain, 1Password where `op`
/// works, any other reference, another account's token (a reuse, never preselected), and
/// "Later" where it is the step's first question.
fn sources(ask: &SecretAsk, stores: &Stores) -> Vec<Choice<Source>> {
    let svc = crate::names::instance();
    let kc = keychain();
    let mut options: Vec<Choice<Source>> = Vec::new();
    if let Some(r) = ask.current {
        options.push(choice(
            Source::Current,
            "the current one",
            format!("Keep the current one ({})", shown_ref(r)),
        ));
    }
    if stores.in_keychain {
        options.push(choice(
            Source::InKeychain,
            format!("the one in {kc}"),
            format!("Already in {kc} ({svc}/{})", ask.acct),
        ));
    }
    options.push(choice(
        Source::PasteKeychain,
        format!("pasted into {kc}"),
        format!("Paste it now (stored in {kc})"),
    ));
    if stores.op {
        options.push(choice(
            Source::Paste1Password,
            "pasted into 1Password",
            "Paste it now (stored in 1Password)",
        ));
    }
    if stores.browse {
        options.push(choice(
            Source::Browse,
            "in 1Password",
            "It's already in 1Password (browse)",
        ));
    }
    options.push(choice(
        Source::Reference,
        "somewhere else",
        "It's somewhere else (op://, env:, file:, keyring:)",
    ));
    options.extend(
        ask.known
            .iter()
            .enumerate()
            .filter(|(_, (_, r))| Some(r.as_str()) != ask.current)
            .map(|(i, (what, r))| {
                choice(
                    Source::Known(i),
                    format!("{what}'s token"),
                    format!("Reuse {what}'s token ({})", shown_ref(r)),
                )
            }),
    );
    if ask.later {
        options.push(choice(Source::Later, "later", LATER));
    }
    // A long reference is cut, never the menu's width.
    let room = text::columns() - 2;
    for o in &mut options {
        o.label = text::fit(&o.label, room, true);
    }
    options
}

/// Where a secret is kept, as a reference the host resolves: the one the config has, one of
/// the `known` ones, the keychain entry `acct` of luoto's service, pasted into the keychain or
/// into 1Password, found in 1Password, or a reference to where it is. Esc goes back a
/// question; `Back` is Esc at the first.
pub fn secret(ask: &SecretAsk, global: &GlobalConfig) -> Result<Step<Secret>> {
    let svc = crate::names::instance();
    let in_keychain = format!("keyring:{svc}/{}", ask.acct);
    let op = secrets::op_available();
    let stores = Stores {
        in_keychain: ask.current != Some(in_keychain.as_str()) && keychain_has(ask.acct),
        op,
        browse: op
            && (!secrets::op_service_account(global) || secrets::op_vaults(global, None).is_ok()),
    };
    let options = sources(ask, &stores);
    let question = format!("Where is the {} kept?", ask.label);
    let mut at = 0;
    let mut how = ask.how;
    loop {
        let source = match pick(&mut terminal_menu, &question, &options, at, ask.help)? {
            Step::Back => return Ok(Step::Back),
            Step::Got((i, s)) => {
                at = i;
                s
            }
        };
        // How to make one matters only for a new one, and is said once.
        if matches!(
            source,
            Source::PasteKeychain | Source::Paste1Password | Source::Browse | Source::Reference
        ) && let Some(h) = how.take()
        {
            println!("{h}");
        }
        let r = match source {
            Source::Current => ask.current.unwrap_or_default().to_string(),
            Source::Known(i) => ask.known[i].1.clone(),
            Source::Later => return Ok(Step::Got(Secret::Later)),
            Source::InKeychain => in_keychain.clone(),
            Source::PasteKeychain => {
                let Step::Got(secret) = paste(ask)? else {
                    continue;
                };
                if !shape_ok(ask, &secret) {
                    continue;
                }
                let free = free_account(ask.acct, keychain_taken)?;
                keyring::Entry::new(svc, &free)
                    .and_then(|e| e.set_password(&secret))
                    .context("store the secret in the OS keychain")?;
                if free == ask.acct {
                    println!("stored in {} as {svc}/{free}", keychain());
                } else {
                    println!(
                        "stored in {} as {svc}/{free} ({svc}/{} holds another one, kept as it is)",
                        keychain(),
                        ask.acct
                    );
                }
                format!("keyring:{svc}/{free}")
            }
            Source::Paste1Password => match op_paste(global, ask)? {
                Step::Got(r) => r,
                Step::Back => continue,
            },
            Source::Browse => match browse(global, ask)? {
                Step::Got(r) => r,
                Step::Back => continue,
            },
            Source::Reference => match typed_reference(global, ask)? {
                Step::Got(r) => r,
                Step::Back => continue,
            },
        };
        return Ok(Step::Got(Secret::Ref(r)));
    }
}

/// A secret pasted into a new 1Password item, in the account (when the app has several) and
/// vault (when the account has several) picked before it: the paste is the last question, so
/// going back never drops one. Its reference; `Back` is Esc at the first question.
fn op_paste(global: &GlobalConfig, ask: &SecretAsk) -> Result<Step<String>> {
    let accounts = op_accounts(global);
    let mut vaults: HashMap<Option<String>, Vec<OpVault>> = HashMap::new();
    let mut at_vault = 0;
    loop {
        let account = if accounts.is_empty() {
            None
        } else {
            let q = format!("1Password account to save the {} in:", ask.label);
            match pick_op_account(&q, &accounts, None)? {
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
        let only = list.len() == 1;
        if only {
            println!("  1Password vault: {}", display(&list[0].name));
        }
        loop {
            let i = if only {
                0
            } else {
                let names = list.iter().map(|v| display(&v.name)).collect();
                let q = format!("1Password vault to save the {} in:", ask.label);
                let Step::Got(i) = pick_index(&q, names, at_vault)? else {
                    break;
                };
                i
            };
            at_vault = i;
            let Step::Got(secret) = paste(ask)? else {
                if only {
                    break;
                }
                continue;
            };
            if !shape_ok(ask, &secret) {
                return Ok(Step::Back);
            }
            let vault = &list[i];
            let note = format!(
                "{}. luoto hands it to its gate, which adds it to requests; the sandbox never \
                 sees it.",
                ask.label
            );
            let r = secrets::op_save(
                global,
                account.as_deref(),
                &vault.id,
                ask.title,
                &secret,
                &note,
            )?;
            println!(
                "saved in 1Password ({}) as \"{}\": {}",
                display(&vault.name),
                ask.title,
                secrets::shown_ref(&r)
            );
            return Ok(Step::Got(r));
        }
        if accounts.is_empty() {
            return Ok(Step::Back);
        }
    }
}

/// A reference typed, starting from the current one, and read once it is entered: a ref that
/// doesn't read gives its error on one line and comes back to edit. With several 1Password
/// accounts, an `op://` one that didn't read is tried in the account picked.
fn typed_reference(global: &GlobalConfig, ask: &SecretAsk) -> Result<Step<String>> {
    let mut last = ask.current.unwrap_or_default().to_string();
    loop {
        // The prompt checks only the form: reading the ref runs `op`, which may ask on the
        // terminal, so it runs after the prompt has given the terminal back.
        let Some(r) = Text::new("Reference:")
            .with_initial_value(&last)
            .with_placeholder("op://vault/item/field, env:NAME, file:/path")
            .with_help_message("read from your secret store on Enter; Esc: back")
            .with_validator(|s: &str| {
                Ok(match secrets::check_ref(s.trim()) {
                    Ok(()) => Validation::Valid,
                    Err(e) => Validation::Invalid(format!("{e:#}").into()),
                })
            })
            .ask()?
        else {
            return Ok(Step::Back);
        };
        let r = r.trim().to_string();
        // Read once here (the value is dropped), so a typo shows now rather than as a
        // locked credential at `up`.
        match readable(global, &r, ask) {
            Ok(true) => return Ok(Step::Got(r)),
            Ok(false) => return Ok(Step::Back),
            Err(e) => ref_error(&r, &e),
        }
        last = r;
        if !last.starts_with("op://") {
            continue;
        }
        println!("{}", text::wrap(OP_FIELDS, "  ", text::columns()));
        // A ref naming no account is read from op's default; the token may be in another.
        if secrets::op_parts(&last).1.is_none() {
            let accounts = op_accounts(global);
            if !accounts.is_empty()
                && let Step::Got(Some(a)) = pick_op_account(
                    "Which 1Password account holds it?",
                    &accounts,
                    Some("none of these: edit the reference"),
                )?
            {
                let with = secrets::op_with_account(&last, &a);
                match readable(global, &with, ask) {
                    Ok(true) => return Ok(Step::Got(with)),
                    Ok(false) => return Ok(Step::Back),
                    Err(e) => ref_error(&with, &e),
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
fn browse(global: &GlobalConfig, ask: &SecretAsk) -> Result<Step<String>> {
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
    // Coming back to a vault from its items: an account's only vault isn't a question, so
    // Esc goes on back past it.
    let mut backing = false;
    let mut at = if accounts.is_empty() {
        At::Vault
    } else {
        At::Account
    };
    loop {
        match at {
            At::Account => {
                let Step::Got(i) = pick_index(
                    &format!("1Password account holding the {}:", ask.label),
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
                backing = false;
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
                if let [only] = &list[..] {
                    if std::mem::take(&mut backing) {
                        if accounts.is_empty() {
                            return Ok(Step::Back);
                        }
                        at = At::Account;
                    } else {
                        println!("  1Password vault: {}", display(&only.name));
                        vault = Some(only.clone());
                        at_item = 0;
                        at = At::Item;
                    }
                    continue;
                }
                let names = list.iter().map(|v| display(&v.name)).collect();
                let q = format!("Vault holding the {}:", ask.label);
                match pick_index(&q, names, at_vault)? {
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
                    backing = true;
                    at = At::Vault;
                    continue;
                }
                let shown = list.iter().map(OpItem::shown).collect();
                let q = format!("Item holding the {}:", ask.label);
                match pick_index(&q, shown, at_item)? {
                    Step::Got(i) => {
                        at_item = i;
                        item = Some(list[i].clone());
                        at = At::Field;
                    }
                    Step::Back => {
                        backing = true;
                        at = At::Vault;
                    }
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
                match readable(global, &r, ask) {
                    Ok(true) => {
                        println!("  {}", remember_pick(&r, &it, &v));
                        return Ok(Step::Got(r));
                    }
                    Ok(false) => return Ok(Step::Back),
                    Err(e) => ref_error(&r, &e),
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
        .ask()?
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
        .ask()?;
    Ok(typed.map(|s| s.trim().to_string()).into())
}

fn show_error(e: &anyhow::Error) {
    println!("  {}", crate::text::lines(&format!("{e:#}")));
}

/// Why reference `r` didn't do, after it: one line, broken only where the terminal is
/// narrower.
fn ref_error(r: &str, e: &anyhow::Error) {
    let why = format!(
        "{}: {}",
        secrets::shown_ref(r),
        display(&format!("{e:#}").replace('\n', " "))
    );
    println!("{}", text::wrap(&why, "  ", text::columns()));
}

/// Whether reference `r` reads, as the secret `ask` is for alone: an error when it doesn't,
/// false when its value lacks `ask`'s shape and the user won't use it anyway.
fn readable(global: &GlobalConfig, r: &str, ask: &SecretAsk) -> Result<bool> {
    let value = secrets::resolve(global, r)?;
    match not_alone(&value, ask.label).or_else(|| mismatch(ask.kind, &value)) {
        Some(why) => bail!("{why}"),
        None => Ok(shape_ok(ask, &value)),
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
        match pick(
            &mut terminal_menu,
            question,
            &options,
            0,
            &menu_help("back"),
        )? {
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
const OP_FIELDS: &str = "In 1Password the field is `credential` (API Credential), `password` \
                         (Password) or `notesPlain` (a Secure Note with the token alone in it).";

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

/// Why `value` isn't the credential `kind` (provider, auth kind) names, when the prefixes its
/// issuers document say so. Never the value itself.
fn mismatch(kind: Option<(&str, &str)>, value: &str) -> Option<String> {
    let (provider, kind) = kind?;
    let want = profiles::provider(provider)?.auth.remove(kind)?;
    let known: Vec<(String, String)> = profiles::provider_names()
        .filter_map(profiles::provider)
        .flat_map(|p| p.auth.into_values())
        .filter_map(|a| Some((a.label, a.prefix?)))
        .collect();
    prefix_mismatch(&want.label, want.prefix.as_deref()?, &known, value)
}

/// [`mismatch`] against the (label, prefix) of every kind: `value` lacks `prefix`, or has a
/// longer one of another kind, which it then looks like.
fn prefix_mismatch(
    label: &str,
    prefix: &str,
    known: &[(String, String)],
    value: &str,
) -> Option<String> {
    let like = known
        .iter()
        .filter(|(l, p)| l != label && value.starts_with(p.as_str()))
        .max_by_key(|(_, p)| p.len());
    let has = value.starts_with(prefix);
    match like {
        Some((other, p)) if !has || p.len() > prefix.len() => Some(format!(
            "it looks like {} {other}, not {} {label}",
            article(other),
            article(label)
        )),
        _ if !has => Some(format!(
            "it doesn't look like {} {label}, which starts with {prefix}",
            article(label)
        )),
        _ => None,
    }
}

fn article(word: &str) -> &'static str {
    match word.chars().next().map(|c| c.to_ascii_lowercase()) {
        Some('a' | 'e' | 'i' | 'o' | 'u') => "an",
        _ => "a",
    }
}

/// A hidden paste, trimmed, checked against its kind's prefix: one that doesn't fit is asked
/// for again.
fn paste(ask: &SecretAsk) -> Result<Step<String>> {
    let kind = ask.kind.map(|(p, k)| (p.to_string(), k.to_string()));
    Ok(Password::new(&format!("Paste the {}:", ask.label))
        .without_confirmation()
        .with_help_message("hidden, never written to a file; Esc: back")
        .with_validator(move |s: &str| {
            let s = s.trim();
            let kind = kind.as_ref().map(|(p, k)| (p.as_str(), k.as_str()));
            Ok(if s.is_empty() {
                Validation::Invalid("empty".into())
            } else if let Some(why) = mismatch(kind, s) {
                Validation::Invalid(why.into())
            } else {
                Validation::Valid
            })
        })
        .ask()?
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

    /// What the question of where a secret is kept was asked with.
    struct Kept {
        label: String,
        later: bool,
        current: Option<String>,
        help: String,
    }

    struct Run {
        answer: Answer,
        menus: Vec<Asked>,
        kept: Vec<Kept>,
    }

    /// The credential questions for `agent`, answered in turn: a menu by its entry's echo,
    /// Esc as `None`; where the secret is kept by `secrets`. Every answer is used.
    fn run(
        agent: &str,
        have: &[Auth],
        mode: Mode,
        answers: &[Option<&str>],
        secrets: Vec<Step<Secret>>,
    ) -> Run {
        let a = profiles::agent(agent).unwrap();
        let mut answers: VecDeque<Option<&str>> = answers.iter().copied().collect();
        let mut secrets: VecDeque<Step<Secret>> = secrets.into();
        let (mut menus, mut kept) = (Vec::new(), Vec::new());
        let answer = credential_with(
            &a,
            have,
            false,
            mode,
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
                        Some(s) => Step::Got(
                            options
                                .iter()
                                .position(|o| o.short == s)
                                .unwrap_or_else(|| panic!("no entry {s}")),
                        ),
                    },
                )
            },
            &mut |ask: &SecretAsk| {
                kept.push(Kept {
                    label: ask.label.into(),
                    later: ask.later,
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
    const API_KEY: &str = "Anthropic API key";

    #[test]
    fn the_kind_menu_names_kinds_plainly_suggested_first_within_80_columns() {
        let r = run("claude", &[], Mode::Missing, &[None], vec![]);
        assert_eq!(r.answer, Answer::Leave);
        let m = &r.menus[0];
        assert_eq!(m.question, "How should Claude Code sign in?");
        assert_eq!(m.help, "↑↓ to move, Enter to pick, Esc: later");
        assert_eq!(
            m.labels,
            [
                "Claude subscription token (recommended)  `claude setup-token` on this machine",
                "Anthropic API key                        billed per use (platform.claude.com)",
                "A model server                           yours, on this or another machine",
                "Log in inside the env                    weaker: code in the env can read it",
                "Later                                    the agent can't connect without one",
            ]
        );
        assert!(!m.labels.iter().any(|l| l.contains("oauth_token")));
        // Every agent's first menu fits, its descriptions cut if need be, never a label.
        for name in profiles::agent_names() {
            // Copilot's one kind starts where it is kept.
            let (answers, secrets) = if name == "copilot" {
                (vec![], vec![Step::Back])
            } else {
                (vec![None], vec![])
            };
            let r = run(name, &[], Mode::Missing, &answers, secrets);
            for l in r.menus.iter().flat_map(|m| &m.labels) {
                assert!(l.chars().count() + 2 < 80, "{name}: {l}");
            }
        }
    }

    #[test]
    fn esc_or_later_at_the_first_question_writes_nothing() {
        for answer in [None, Some("Later")] {
            let r = run("claude", &[], Mode::Missing, &[answer], vec![]);
            assert_eq!(r.answer, Answer::Leave);
        }
    }

    #[test]
    fn a_login_inside_only_when_picked() {
        let r = run(
            "claude",
            &[],
            Mode::Missing,
            &[Some("Log in inside the env")],
            vec![],
        );
        assert_eq!(r.answer, Answer::Set(inside("anthropic")));
        // A provider with no other way in still asks.
        let r = run("agy", &[], Mode::Missing, &[None], vec![]);
        assert_eq!(r.answer, Answer::Leave);
        assert_eq!(r.menus[0].labels.len(), 2);
        // With it set already, there is nothing to choose: no question.
        let r = run("agy", &[inside("antigravity")], Mode::Change, &[], vec![]);
        assert_eq!(r.answer, Answer::Leave);
        assert!(r.menus.is_empty());
    }

    #[test]
    fn esc_where_it_is_kept_goes_back_to_the_kind() {
        let r = run(
            "claude",
            &[],
            Mode::Missing,
            &[Some(API_KEY), Some(TOKEN)],
            vec![Step::Back, Step::Got(Secret::Ref("env:T".into()))],
        );
        assert_eq!(
            r.answer,
            Answer::Set(kind("anthropic", "oauth_token", "env:T"))
        );
        // Back, the menu opens where it was left.
        assert_eq!((r.menus[0].at, r.menus[1].at), (0, 1));
        // "Later" only at the first question.
        assert_eq!(r.kept[0].help, menu_help("back"));
        assert!(!r.kept[0].later);
        assert_eq!(r.kept[1].label, TOKEN);
    }

    #[test]
    fn one_kind_and_no_login_starts_where_it_is_kept() {
        let r = run("copilot", &[], Mode::Missing, &[], vec![Step::Back]);
        assert_eq!(r.answer, Answer::Leave);
        assert!(r.menus.is_empty());
        assert_eq!(r.kept[0].help, menu_help("later"));
        assert!(r.kept[0].later, "the first question offers Later");
        let r = run(
            "copilot",
            &[],
            Mode::Missing,
            &[],
            vec![Step::Got(Secret::Later)],
        );
        assert_eq!(r.answer, Answer::Leave);
    }

    #[test]
    fn several_providers_go_back_to_the_provider() {
        let r = run(
            "opencode",
            &[],
            Mode::Missing,
            &[Some("OpenAI API"), None, None],
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
                    "Which provider should OpenCode use?",
                    "↑↓ to move, Enter to pick, Esc: later"
                ),
                (
                    "How should OpenCode sign in to OpenAI API?",
                    "↑↓ to move, Enter to pick, Esc: back"
                ),
                (
                    "Which provider should OpenCode use?",
                    "↑↓ to move, Enter to pick, Esc: later"
                ),
            ]
        );
        assert_eq!(r.menus[2].at, 1);
        assert!(r.menus[0].labels.last().unwrap().starts_with("Later"));
        // The kind menu after the provider's offers no Later of its own.
        assert!(!r.menus[1].labels.iter().any(|l| l.starts_with("Later")));
    }

    #[test]
    fn a_change_opens_on_what_the_env_has() {
        let now = kind(
            "anthropic",
            "oauth_token",
            "keyring:luoto/anthropic.oauth_token",
        );
        let kept = Step::Got(Secret::Ref("keyring:luoto/anthropic.oauth_token".into()));
        let r = run(
            "claude",
            std::slice::from_ref(&now),
            Mode::Change,
            &[Some(TOKEN)],
            vec![kept],
        );
        assert_eq!(r.answer, Answer::Leave);
        let m = &r.menus[0];
        assert_eq!(m.help, "↑↓ to move, Enter to pick, Esc: unchanged");
        assert!(m.labels[m.at].starts_with("Claude subscription token (current)  "));
        assert!(!m.labels.iter().any(|l| l.contains("(recommended)")));
        assert!(!m.labels.iter().any(|l| l.starts_with("Later")));
        assert_eq!(
            r.kept[0].current.as_deref(),
            Some("keyring:luoto/anthropic.oauth_token")
        );
        assert!(!r.kept[0].later);

        let r = run(
            "claude",
            std::slice::from_ref(&now),
            Mode::Change,
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
            &[inside("anthropic")],
            Mode::Change,
            &[None],
            vec![],
        );
        assert_eq!(r.answer, Answer::Leave);
        let m = &r.menus[0];
        assert!(m.labels[m.at].starts_with("Log in inside the env (current)"));
    }

    #[test]
    fn a_change_offers_every_provider_its_own_marked() {
        let now = kind("openai", "api_key", "env:KEY");
        let r = run(
            "opencode",
            std::slice::from_ref(&now),
            Mode::Change,
            &[Some("Anthropic API"), None, None],
            vec![],
        );
        assert_eq!(r.answer, Answer::Leave);
        let providers = &r.menus[0];
        assert_eq!(providers.at, 1);
        assert!(providers.labels[1].starts_with("OpenAI API (current)"));
        assert!(!providers.labels.iter().any(|l| l.starts_with("Later")));
        // A provider it hasn't yet: its suggested kind is recommended.
        assert!(r.menus[1].labels[0].contains("(recommended)"));
    }

    #[test]
    fn the_source_menu_keeps_the_current_first_and_later_last() {
        let known = [("beta".to_string(), "env:A".to_string())];
        let ask = SecretAsk {
            label: "GitHub token for acme",
            acct: "github.acme",
            title: "luoto GitHub token for acme",
            later: true,
            known: &known,
            current: Some("env:NOW"),
            help: "",
            kind: None,
            how: None,
            shape: None,
        };
        let all = Stores {
            in_keychain: true,
            op: true,
            browse: true,
        };
        let kc = keychain();
        let labels: Vec<String> = sources(&ask, &all).into_iter().map(|c| c.label).collect();
        let svc = crate::names::instance();
        // Another account's token is a reuse: after the new ones, never preselected.
        assert_eq!(
            labels,
            [
                "Keep the current one (env:NOW)".to_string(),
                format!("Already in {kc} ({svc}/github.acme)"),
                format!("Paste it now (stored in {kc})"),
                "Paste it now (stored in 1Password)".into(),
                "It's already in 1Password (browse)".into(),
                "It's somewhere else (op://, env:, file:, keyring:)".into(),
                "Reuse beta's token (env:A)".into(),
                "Later".into(),
            ]
        );
        let fresh = SecretAsk {
            current: None,
            ..ask
        };
        let values: Vec<Source> = sources(&fresh, &all).into_iter().map(|c| c.value).collect();
        assert_eq!(
            values,
            [
                Source::InKeychain,
                Source::PasteKeychain,
                Source::Paste1Password,
                Source::Browse,
                Source::Reference,
                Source::Known(0),
                Source::Later,
            ]
        );
        let none = Stores {
            in_keychain: false,
            op: false,
            browse: false,
        };
        let first = SecretAsk {
            current: None,
            known: &[],
            later: false,
            ..ask
        };
        let values: Vec<Source> = sources(&first, &none)
            .into_iter()
            .map(|c| c.value)
            .collect();
        assert_eq!(values, [Source::PasteKeychain, Source::Reference]);
    }

    #[test]
    fn a_token_without_its_prefix_is_asked_about() {
        let shape = Shape {
            what: "a GitHub token",
            prefixes: &["github_pat_", "ghp_"],
            hint: "github_pat_ or ghp_",
        };
        assert!(shape.fits("ghp_abc"));
        assert!(!shape.fits("abc"));
        assert_eq!(
            shape.question(),
            "It doesn't look like a GitHub token (they start with github_pat_ or ghp_). Use it \
             anyway?"
        );
    }

    #[test]
    fn a_value_with_another_kinds_prefix_is_asked_for_again() {
        let check = |provider, k, v| mismatch(Some((provider, k)), v);
        assert_eq!(check("anthropic", "oauth_token", "sk-ant-oat01-abc"), None);
        assert_eq!(
            check("anthropic", "oauth_token", "sk-ant-api03-abc").as_deref(),
            Some("it looks like an Anthropic API key, not a Claude subscription token")
        );
        assert_eq!(
            check("anthropic", "api_key", "hello").as_deref(),
            Some("it doesn't look like an Anthropic API key, which starts with sk-ant-api")
        );
        // OpenAI's `sk-` holds others' longer prefixes: those are told apart.
        assert_eq!(check("openai", "api_key", "sk-proj-abc"), None);
        assert_eq!(
            check("openai", "api_key", "sk-ant-oat01-abc").as_deref(),
            Some("it looks like a Claude subscription token, not an OpenAI API key")
        );
        assert_eq!(
            check("openai", "api_key", "sk-or-v1-abc").as_deref(),
            Some("it looks like an OpenRouter API key, not an OpenAI API key")
        );
        // No documented prefix, no check.
        assert_eq!(check("mistral", "api_key", "anything"), None);
        assert_eq!(mismatch(None, "anything"), None);
        // The value never shows.
        let said = check("anthropic", "oauth_token", "secret-value-123").unwrap();
        assert!(!said.contains("secret-value"));
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
            email: "you@example.com".into(),
        };
        let all = [
            account("VZ7CWAKJKFHWVHZ3UFZQ5GPNSU", "my.1password.com"),
            account("Q3RTX2UJWVE2TMXFPN6HVOIB3Y", "my.1password.com"),
            account("ZK4ONHBXKRHVBDDVX4L7QTCSDM", "acme.1password.com"),
        ];
        assert_eq!(
            account_label(&all[1], &all),
            "my.1password.com, you@example.com (Q3RTX2UJWVE2TMXFPN6HVOIB3Y)"
        );
        assert_eq!(
            account_label(&all[2], &all),
            "acme.1password.com, you@example.com"
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
