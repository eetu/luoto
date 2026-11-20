//! `luoto prune --envs`: remove the envs nobody has used for a while (`used.rs`), as `luoto
//! rm` removes one. Never a running env, and never, unasked, one holding work that is
//! nowhere else: what its repos held as it stopped (`used::work`), and what its volume holds
//! that its folders lack (`autopull::unpulled_stopped`). An env that can't be checked holds
//! work.

use std::io::IsTerminal;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, TimeDelta, Utc};

use crate::config::{self, EnvFile, GlobalConfig, Workspace};
use crate::env::{self, Ctx};
use crate::state::EnvState;
use crate::used::{self, Used, Work};
use crate::workspace::Unpulled;
use crate::{autopull, disk, machine, names, text};

/// How long an env goes unused before `luoto prune --envs` takes it, unless `prune_after`
/// or `--older-than` says.
pub const DEFAULT: &str = "30d";

/// The rows of each list a terminal shows; a pipe gets them all.
const SHOWN: usize = 40;
/// The lines of work shown under one env.
const HELD_SHOWN: usize = 4;

pub struct Opts {
    pub older_than: Option<String>,
    pub matching: Option<String>,
    pub with_work: bool,
    pub yes: bool,
}

/// The age `luoto prune --envs` takes envs from, as written and as a duration:
/// `--older-than`, else `prune_after` in config.toml, else [`DEFAULT`].
pub fn limit(global: &GlobalConfig, older_than: Option<&str>) -> Result<(String, TimeDelta)> {
    let (text, from) = match (older_than, global.prune_after.as_deref()) {
        (Some(s), _) => (s, "--older-than"),
        (None, Some(s)) => (s, "`prune_after` in config.toml"),
        (None, None) => (DEFAULT, "the default"),
    };
    let d = crate::rules::parse_ttl(text).with_context(|| from.to_string())?;
    Ok((text.trim().to_string(), d))
}

/// A shell-style pattern for env names: `*`, `?` and `[a-z]` (`[!a-z]` for none of them),
/// case-sensitive, matching the whole name.
#[derive(Debug)]
pub struct Glob(Vec<Tok>);

#[derive(Debug)]
enum Tok {
    Char(char),
    One,
    Many,
    Class {
        not: bool,
        ranges: Vec<(char, char)>,
    },
}

impl Glob {
    pub fn new(pattern: &str) -> Result<Glob> {
        if pattern.is_empty() {
            bail!("--match takes a pattern such as `job-*`");
        }
        let mut toks = Vec::new();
        let mut chars = pattern.chars().peekable();
        while let Some(c) = chars.next() {
            toks.push(match c {
                '*' => Tok::Many,
                '?' => Tok::One,
                '[' => {
                    let not = chars.next_if(|c| matches!(c, '!' | '^')).is_some();
                    let mut ranges = Vec::new();
                    loop {
                        let Some(lo) = chars.next() else {
                            bail!("bad pattern `{pattern}`: a `[` without its `]`");
                        };
                        // A `]` right after the `[` is one of the characters.
                        if lo == ']' && !ranges.is_empty() {
                            break;
                        }
                        let mut hi = lo;
                        if chars.peek() == Some(&'-') {
                            chars.next();
                            match chars.next_if(|c| *c != ']') {
                                Some(c) => hi = c,
                                // A `-` before the `]` is one of the characters.
                                None => ranges.push(('-', '-')),
                            }
                        }
                        if hi < lo {
                            bail!("bad pattern `{pattern}`: `{lo}-{hi}` runs backwards");
                        }
                        ranges.push((lo, hi));
                    }
                    Tok::Class { not, ranges }
                }
                c => Tok::Char(c),
            });
        }
        Ok(Glob(toks))
    }

    pub fn matches(&self, name: &str) -> bool {
        let name: Vec<char> = name.chars().collect();
        matches(&self.0, &name)
    }
}

fn matches(toks: &[Tok], name: &[char]) -> bool {
    let Some((tok, rest)) = toks.split_first() else {
        return name.is_empty();
    };
    if let Tok::Many = tok {
        return (0..=name.len()).any(|skip| matches(rest, &name[skip..]));
    }
    let Some((c, name)) = name.split_first() else {
        return false;
    };
    let fits = match tok {
        Tok::Char(t) => t == c,
        Tok::One | Tok::Many => true,
        Tok::Class { not, ranges } => ranges.iter().any(|(lo, hi)| lo <= c && c <= hi) != *not,
    };
    fits && matches(rest, name)
}

/// What `luoto prune --envs` makes of an env before looking at its work.
#[derive(Debug, PartialEq, Eq)]
enum Fate {
    /// `--match` names others.
    Unmatched,
    Running,
    /// Used within the limit, or (unrecorded, with nothing to date it by) not known to be
    /// older.
    Recent,
    Unused,
}

fn fate(
    name: &str,
    running: bool,
    used: Used,
    now: DateTime<Utc>,
    limit: TimeDelta,
    glob: Option<&Glob>,
) -> Fate {
    if glob.is_some_and(|g| !g.matches(name)) {
        return Fate::Unmatched;
    }
    if running {
        return Fate::Running;
    }
    if limit <= TimeDelta::zero() {
        return Fate::Unused;
    }
    match used.time() {
        Some(t) if now - t >= limit => Fate::Unused,
        _ => Fate::Recent,
    }
}

/// Why an unused env stays: a line for each thing it holds that is nowhere else, none when
/// luoto sees none. `record` is what its repos held as it stopped; `files`, what its volume
/// holds that its folders lack, or why that couldn't be read (asked only with a record).
fn held(
    env: &str,
    ws: &Workspace,
    record: Option<&Work>,
    files: &Result<Vec<Unpulled>, String>,
) -> Vec<String> {
    let Some(record) = record else {
        return vec![format!(
            "not checked: no luoto saw it stop (`luoto up -e {env}`, then `luoto down -e {env}`, \
             looks at its work)"
        )];
    };
    if let Some(e) = &record.error {
        return vec![format!("its repos couldn't be checked as it stopped: {e}")];
    }
    let files = match files {
        Ok(f) => f,
        Err(e) => return vec![format!("its files couldn't be compared with yours: {e}")],
    };
    // With every file in its folder, a folder's repo holds only what no file shows.
    let pulled = |path: &str| ws.folder_of(path) && files.is_empty();
    record
        .unpushed
        .iter()
        .filter(|w| w.only_here(pulled(&w.path)))
        .map(|w| w.to_string())
        .chain(files.iter().map(|u| u.to_string()))
        .collect()
}

/// The work stopped env `env` holds, for [`held`]'s lines; none for one that never started
/// or whose volumes are gone.
fn check(ctx: &Ctx, env: &str, vm_gone: bool) -> Vec<String> {
    let why =
        |what: &str, e: anyhow::Error| vec![format!("{what}: {}", text::lines(&format!("{e:#}")))];
    match EnvState::load(&ctx.paths, env) {
        Ok(Some(_)) if !vm_gone => {}
        Ok(_) => return Vec::new(),
        Err(e) => return why("its state couldn't be read", e),
    }
    let ws = match EnvFile::load(&ctx.paths, env) {
        Ok(f) => f.cfg.workspace,
        Err(e) => return why("its config couldn't be read", e),
    };
    let record = used::work(&ctx.paths, env);
    if record.is_none() && !ctx.rt.volume_exists(&names::volume(env, "work")) {
        return Vec::new();
    }
    let files = match &record {
        Some(r) if r.error.is_none() && ws.has_folder() => {
            let _waiting =
                crate::progress::waiting(&format!("comparing the files of `{env}` with yours"));
            autopull::unpulled_stopped(ctx, env).map_err(|e| text::lines(&format!("{e:#}")))
        }
        _ => Ok(Vec::new()),
    };
    held(env, &ws, record.as_ref(), &files)
}

/// An unused env in the lists.
#[derive(Debug)]
struct Row {
    name: String,
    used: Used,
    /// What its volumes and containers take; None when that wasn't read.
    bytes: Option<u64>,
    held: Vec<String>,
}

/// The envs to remove and the ones that stay for their work.
fn split(rows: Vec<Row>, with_work: bool) -> (Vec<Row>, Vec<Row>) {
    rows.into_iter()
        .partition(|r| with_work || r.held.is_empty())
}

fn total(rows: &[Row]) -> u64 {
    rows.iter().filter_map(|r| r.bytes).sum()
}

/// A list's lines: each env with when it was last used and its size, what it holds under
/// it, wrapped to `width`; the first `shown` envs, then how many more.
fn table(rows: &[Row], now: DateTime<Utc>, width: usize, shown: usize) -> Vec<String> {
    let used: Vec<String> = rows.iter().map(|r| r.used.shown(now)).collect();
    let name_w = rows.iter().map(|r| r.name.chars().count()).max();
    let name_w = name_w.unwrap_or(0).max(3);
    let used_w = used.iter().map(String::len).fold(9, usize::max);
    let mut out = vec![format!(
        "  {:<name_w$}  {:<used_w$}  SIZE",
        "ENV", "LAST USED"
    )];
    for (r, used) in rows.iter().zip(&used).take(shown) {
        let size = r.bytes.map_or_else(|| "-".into(), disk::human);
        out.push(format!("  {:<name_w$}  {used:<used_w$}  {size}", r.name));
        for line in r.held.iter().take(HELD_SHOWN) {
            out.extend(text::hang("      ", line, width).lines().map(String::from));
        }
        if r.held.len() > HELD_SHOWN {
            out.push(format!("      and {} more", r.held.len() - HELD_SHOWN));
        }
    }
    if rows.len() > shown {
        let rest = &rows[shown..];
        out.push(format!(
            "  and {} more, {} (`| cat` lists every one)",
            rest.len(),
            disk::human(total(rest))
        ));
    }
    out
}

/// What follows the lists.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    Remove,
    /// One question, whose answer Enter gives is no.
    Ask,
    /// Without a terminal nothing is removed unasked: the lists, and the command that does.
    List,
}

fn step(yes: bool, terminal: bool) -> Step {
    match (yes, terminal) {
        (true, _) => Step::Remove,
        (false, true) => Step::Ask,
        (false, false) => Step::List,
    }
}

/// The command that removes what was listed, asking nothing.
fn scripted(o: &Opts) -> String {
    let mut c = format!("{} prune --envs", names::instance());
    if let Some(d) = &o.older_than {
        c.push_str(&format!(" --older-than {}", d.trim()));
    }
    if let Some(g) = &o.matching {
        c.push_str(&format!(" --match '{g}'"));
    }
    if o.with_work {
        c.push_str(" --with-work");
    }
    c + " --yes"
}

fn print(lines: &[String]) {
    let style = crate::style::out();
    for (i, line) in lines.iter().enumerate() {
        // The heading, and what an env holds, step back for the envs.
        if i == 0 || line.starts_with("      ") {
            println!("{}", style.dim(line));
        } else {
            println!("{line}");
        }
    }
}

pub fn envs(o: Opts) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let (age, limit) = limit(&ctx.global, o.older_than.as_deref())?;
    let glob = o.matching.as_deref().map(Glob::new).transpose()?;
    let inst = names::instance();
    let all = config::list_envs(&ctx.paths)?;
    // A deleted VM took every env's volumes along: what is left of them is on this machine.
    let vm_gone = machine::gone(&ctx.rt);
    if !vm_gone && !all.is_empty() {
        env::ensure_vm(&ctx)?;
    }
    let states = match vm_gone {
        true => Default::default(),
        false => ctx.rt.states()?,
    };
    let now = Utc::now();
    let unused: Vec<(String, Used)> = all
        .iter()
        .filter_map(|name| {
            let running = states.running(&names::dev(name)) || states.running(&names::gate(name));
            let used = used::of(&ctx.paths, name);
            (fate(name, running, used, now, limit, glob.as_ref()) == Fate::Unused)
                .then(|| (name.clone(), used))
        })
        .collect();
    let named = o.matching.as_ref().map(|g| format!(" named `{g}`"));
    let aged = (limit > TimeDelta::zero()).then(|| format!(" not used for {age}"));
    let which = format!("{}{}", named.unwrap_or_default(), aged.unwrap_or_default());
    if unused.is_empty() {
        out!("no stopped env{which}: nothing to remove");
        return Ok(ExitCode::SUCCESS);
    }
    let sizes = match vm_gone {
        true => None,
        false => crate::progress::wait("measuring every volume", || disk::sizes(&ctx.rt))
            .map_err(|e| crate::progress::warn(&format!("sizes not read: {e:#}")))
            .ok(),
    };
    if !vm_gone {
        // What reads a stopped env's files.
        env::ensure_image(&ctx, &ctx.image("tools"))?;
    }
    let rows: Vec<Row> = unused
        .into_iter()
        .map(|(name, used)| {
            let disk = sizes.as_ref().map(|s| s.env(&name));
            Row {
                held: check(&ctx, &name, vm_gone),
                bytes: disk.filter(|d| !d.parts.is_empty()).map(|d| d.total),
                name,
                used,
            }
        })
        .collect();
    let (remove, keep) = split(rows, o.with_work);
    let width = text::columns();
    let say = |line: String| out_text!("{}", text::wrap(&line, "", width));
    let shown = match std::io::stdout().is_terminal() {
        true => SHOWN,
        false => usize::MAX,
    };
    let with_work = remove.iter().filter(|r| !r.held.is_empty()).count();
    if !remove.is_empty() {
        let work = match with_work {
            0 => String::new(),
            n => format!(", {n} with work that is nowhere else"),
        };
        say(format!(
            "`{inst} prune --envs` removes {} stopped env(s){which}, {}{work}:",
            remove.len(),
            disk::human(total(&remove))
        ));
        print(&table(&remove, now, width, shown));
    }
    if !keep.is_empty() {
        say(format!(
            "{} stopped env(s){which} stay for the work they hold, {} (`--with-work` removes \
             them too):",
            keep.len(),
            disk::human(total(&keep))
        ));
        print(&table(&keep, now, width, shown));
    }
    let unrecorded = |r: &Row| matches!(r.used, Used::Unrecorded(_));
    if remove.iter().chain(&keep).any(unrecorded) {
        say(
            "unknown: last used before luoto kept a record, so its age is counted from when \
             luoto last wrote its config or state"
                .into(),
        );
    }
    if remove.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }
    let lost = match with_work {
        0 => String::new(),
        n => format!(" The work {n} of them hold is lost"),
    };
    match step(o.yes, crate::prompt::interactive()) {
        Step::Remove => {}
        Step::Ask => {
            let question = format!(
                "Remove {} env(s) ({})?{lost}",
                remove.len(),
                disk::human(total(&remove))
            );
            if !crate::prompt::confirm(&question) {
                bail!("nothing removed (`{}` skips the question)", scripted(&o));
            }
        }
        Step::List => {
            say(format!("nothing removed: `{}` removes them", scripted(&o)));
            return Ok(ExitCode::SUCCESS);
        }
    }
    let mut failed: Vec<(String, String)> = Vec::new();
    let mut gone: Vec<&Row> = Vec::new();
    crate::progress::step(&format!("removing {} env(s)", remove.len()), || {
        for r in &remove {
            let started = !vm_gone
                && [names::dev(&r.name), names::gate(&r.name)]
                    .iter()
                    .any(|c| ctx.rt.is_running(c));
            let done = match started {
                true => Err(anyhow::anyhow!("it runs now")),
                false => crate::commands::remove_env(&ctx, &r.name),
            };
            match done {
                Ok(()) => gone.push(r),
                Err(e) => failed.push((r.name.clone(), text::lines(&format!("{e:#}")))),
            }
        }
    });
    head!(
        "removed {} env(s), {}",
        gone.len(),
        disk::human(gone.iter().filter_map(|r| r.bytes).sum())
    );
    // The volumes are gone; only the VM's disk file on this machine keeps its size.
    if !gone.is_empty()
        && !vm_gone
        && machine::is_luoto(ctx.rt.connection.as_deref())
        && let Err(e) =
            crate::progress::step("handing the freed space back to this machine", || {
                machine::trim(&ctx.rt.bin)
            })
    {
        println!("note: {e:#}");
    }
    if failed.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }
    eprintln!("\nluoto: {} env(s) not removed:", failed.len());
    for (name, e) in &failed {
        eprintln!("{}", text::hang(&format!("  {name}: "), e, width));
    }
    Ok(ExitCode::FAILURE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repos::Unpushed;

    #[test]
    fn the_age_is_the_flags_then_the_configs_then_30_days() {
        let mut global = GlobalConfig::default();
        assert_eq!(
            limit(&global, None).unwrap(),
            ("30d".into(), TimeDelta::days(30))
        );
        global.prune_after = Some("12h".into());
        assert_eq!(limit(&global, None).unwrap().1, TimeDelta::hours(12));
        assert_eq!(limit(&global, Some("0d")).unwrap().1, TimeDelta::zero());
        assert_eq!(
            limit(&global, Some(" 2d ")).unwrap(),
            ("2d".into(), TimeDelta::days(2))
        );
        let e = format!("{:#}", limit(&global, Some("soon")).unwrap_err());
        assert!(
            e.contains("--older-than") && e.contains("bad duration"),
            "{e}"
        );
        global.prune_after = Some("1w".into());
        let e = format!("{:#}", limit(&global, None).unwrap_err());
        assert!(e.contains("`prune_after` in config.toml"), "{e}");
    }

    #[test]
    fn prune_after_is_a_key_of_config_toml() {
        let g: GlobalConfig = toml::from_str("prune_after = \"7d\"").unwrap();
        assert_eq!(g.prune_after.as_deref(), Some("7d"));
        assert_eq!(limit(&g, None).unwrap().1, TimeDelta::days(7));
        assert!(toml::from_str::<GlobalConfig>("prune_afer = \"7d\"").is_err());
    }

    #[test]
    fn a_pattern_matches_whole_names_by_case() {
        let m = |p: &str, name: &str| Glob::new(p).unwrap().matches(name);
        assert!(m("job-*", "job-12") && m("job-*", "job-"));
        assert!(!m("job-*", "ajob-12") && !m("job-*", "Job-12") && !m("job", "job-1"));
        assert!(m("*", "web") && m("*-web-*", "a-web-1") && !m("*-web-*", "web"));
        assert!(m("job-?", "job-1") && !m("job-?", "job-12") && !m("job-?", "job-"));
        assert!(m("job-[0-9]*", "job-7x") && !m("job-[0-9]*", "job-x7"));
        assert!(m("job-[!0-9]", "job-x") && !m("job-[^0-9]", "job-7"));
        assert!(m("a[]-]b", "a]b") && m("a[]-]b", "a-b") && !m("a[]-]b", "a_b"));
        assert!(m("web", "web") && !m("web", "we"));
    }

    #[test]
    fn a_pattern_that_cant_be_read_is_an_error() {
        for bad in ["", "job-[0-9", "[", "job-[z-a]"] {
            assert!(Glob::new(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn only_stopped_envs_unused_for_the_limit_are_taken() {
        let now = Utc::now();
        let at = |days: i64| Used::At(now - TimeDelta::days(days));
        let month = TimeDelta::days(30);
        let f = |running, used, limit, glob: Option<&str>| {
            let glob = glob.map(|g| Glob::new(g).unwrap());
            fate("job-1", running, used, now, limit, glob.as_ref())
        };
        assert_eq!(f(false, at(31), month, None), Fate::Unused);
        assert_eq!(f(false, at(30), month, None), Fate::Unused);
        assert_eq!(f(false, at(29), month, None), Fate::Recent);
        // Never a running env, however old its record or short the limit.
        assert_eq!(f(true, at(400), month, None), Fate::Running);
        assert_eq!(f(true, at(400), TimeDelta::zero(), None), Fate::Running);
        // Without a record its age counts from luoto's last write for it; with nothing to
        // count from, it isn't known to be old.
        let old = Used::Unrecorded(Some(now - TimeDelta::days(45)));
        let new = Used::Unrecorded(Some(now - TimeDelta::days(2)));
        assert_eq!(f(false, old, month, None), Fate::Unused);
        assert_eq!(f(false, new, month, None), Fate::Recent);
        assert_eq!(f(false, Used::Unrecorded(None), month, None), Fate::Recent);
        // `--older-than 0d`: every env that isn't running.
        assert_eq!(f(false, at(0), TimeDelta::zero(), None), Fate::Unused);
        assert_eq!(
            f(false, Used::Unrecorded(None), TimeDelta::zero(), None),
            Fate::Unused
        );
        assert_eq!(f(false, at(-1), TimeDelta::zero(), None), Fate::Unused);
        assert_eq!(f(false, at(31), month, Some("job-*")), Fate::Unused);
        assert_eq!(f(false, at(31), month, Some("web-*")), Fate::Unmatched);
        assert_eq!(f(true, at(31), month, Some("web-*")), Fate::Unmatched);
    }

    fn unpushed(path: &str, changed: usize, commits: usize, stashes: usize) -> Unpushed {
        Unpushed {
            path: path.into(),
            changed,
            commits,
            stashes,
            elsewhere: 0,
            unread: false,
        }
    }

    fn record(unpushed: Vec<Unpushed>) -> Work {
        Work {
            unpushed,
            error: None,
        }
    }

    #[test]
    fn an_env_is_kept_for_work_that_is_nowhere_else() {
        let cloned = Workspace {
            url: Some("https://example.com/acme/web".into()),
            ..Default::default()
        };
        let none = Ok(Vec::new());
        assert!(held("web", &cloned, Some(&record(vec![])), &none).is_empty());
        let work = record(vec![unpushed("/workspace", 2, 1, 0)]);
        assert_eq!(
            held("web", &cloned, Some(&work), &none),
            ["/workspace: 2 files changed, 1 commit not pushed"]
        );
        // A folder's env with every file in the folder holds only what no file shows.
        let folder = Workspace {
            dir: Some("/home/me/web".into()),
            ..Default::default()
        };
        assert!(held("web", &folder, Some(&work), &none).is_empty());
        let stashed = record(vec![unpushed("/workspace", 0, 0, 1)]);
        assert_eq!(
            held("web", &folder, Some(&stashed), &none),
            ["/workspace: 1 stash"]
        );
        // Files its folder lacks: they, and its repo's work with them.
        let files = Ok(vec![Unpulled {
            dir: "/home/me/web".into(),
            changed: 3,
            ..Default::default()
        }]);
        let lines = held("web", &folder, Some(&work), &files);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[1].ends_with("3 files new or changed"), "{lines:?}");
    }

    #[test]
    fn an_env_that_cant_be_checked_holds_work() {
        let ws = Workspace::default();
        let none = Ok(Vec::new());
        let unseen = held("web", &ws, None, &none);
        assert!(unseen[0].starts_with("not checked") && unseen[0].contains("luoto down -e web"));
        let failed = Work {
            unpushed: Vec::new(),
            error: Some("timed out".into()),
        };
        assert_eq!(
            held("web", &ws, Some(&failed), &none),
            ["its repos couldn't be checked as it stopped: timed out"]
        );
        let unread = Err("the env's files couldn't be read (timed out)".to_string());
        let lines = held("web", &ws, Some(&record(vec![])), &unread);
        assert!(
            lines[0].starts_with("its files couldn't be compared"),
            "{lines:?}"
        );
    }

    fn row(name: &str, held: &[&str]) -> Row {
        Row {
            name: name.into(),
            used: Used::At(Utc::now() - TimeDelta::days(45)),
            bytes: Some(1_200_000_000),
            held: held.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn envs_with_work_stay_unless_asked_for() {
        let rows = || vec![row("job-1", &[]), row("job-2", &["/workspace: 1 stash"])];
        let names = |rows: &[Row]| rows.iter().map(|r| r.name.clone()).collect::<Vec<_>>();
        let (remove, keep) = split(rows(), false);
        assert_eq!(
            (names(&remove), names(&keep)),
            (vec!["job-1".into()], vec!["job-2".into()])
        );
        let (remove, keep) = split(rows(), true);
        assert_eq!(names(&remove), ["job-1", "job-2"]);
        assert!(keep.is_empty());
    }

    #[test]
    fn nothing_is_removed_unasked() {
        assert_eq!(step(true, true), Step::Remove);
        assert_eq!(step(true, false), Step::Remove);
        assert_eq!(step(false, true), Step::Ask);
        // No terminal and no `--yes`: the lists only, and the command that removes them.
        assert_eq!(step(false, false), Step::List);
        let o = Opts {
            older_than: Some("7d".into()),
            matching: Some("job-*".into()),
            with_work: true,
            yes: false,
        };
        let inst = names::instance();
        assert_eq!(
            scripted(&o),
            format!("{inst} prune --envs --older-than 7d --match 'job-*' --with-work --yes")
        );
        let plain = Opts {
            older_than: None,
            matching: None,
            with_work: false,
            yes: false,
        };
        assert_eq!(scripted(&plain), format!("{inst} prune --envs --yes"));
    }

    #[test]
    fn the_lists_fit_80_columns_and_a_long_one_is_cut_with_its_total() {
        let now = Utc::now();
        let long = "not checked: no luoto saw it stop (`luoto up -e a-long-env-name-12`, then \
                    `luoto down -e a-long-env-name-12`, looks at its work)";
        let mut rows = vec![row("job-1", &[]), row("a-long-env-name-12", &[long])];
        rows[0].used = Used::Unrecorded(Some(now));
        rows[1].used = Used::At(now - TimeDelta::days(45));
        rows[0].bytes = None;
        let lines = table(&rows, now, 79, 40);
        assert_eq!(lines[0], "  ENV                 LAST USED  SIZE");
        assert_eq!(lines[1], "  job-1               unknown    -");
        assert_eq!(lines[2], "  a-long-env-name-12  45d ago    1.2 GB");
        assert!(lines[3].starts_with("      not checked: no luoto saw it stop"));
        assert!(lines.len() > 4);
        for l in &lines {
            assert!(l.chars().count() <= 79, "{l}");
        }
        let many: Vec<Row> = (0..50).map(|i| row(&format!("job-{i}"), &[])).collect();
        let lines = table(&many, now, 79, 40);
        assert_eq!(lines.len(), 42);
        assert_eq!(
            lines[41],
            "  and 10 more, 12.0 GB (`| cat` lists every one)"
        );
        assert_eq!(table(&many, now, 79, usize::MAX).len(), 51);
        let busy = row("job-1", &["a", "b", "c", "d", "e", "f"]);
        let lines = table(&[busy], now, 79, 40);
        assert_eq!(lines.last().unwrap(), "      and 2 more");
    }
}
