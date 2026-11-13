//! Disk use: what each env's volumes and containers take, how full the disk holding them is
//! (luoto's VM on macOS and Windows, the runtime's storage on Linux), and `luoto prune`, which
//! removes this instance's superseded images and gives the VM's freed space back to the host.
//! Podman and docker print sizes differently; the parsers here read both. Apple's volumes and
//! containers are files on this machine, measured by their metadata. Sizes take a walk of
//! every volume, so they are read when asked for, never on a poll.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::env::{self, Ctx};
use crate::notify::Note;
use crate::paths::{Paths, write_private};
use crate::prompt::confirm;
use crate::release::{self, repo_of};
use crate::runtime::{Flavor, Runtime, exec};
use crate::{config, machine, names, text};

/// Under this much free space `doctor`, `up` and the UI warn. An upgrade pulls a whole new set
/// of luoto's images beside the old ones, and a toolchain install writes gigabytes into an
/// env's home; with less free, one of those can fill the disk, and a full disk stops every env.
pub const LOW_FREE: u64 = 10_000_000_000;

/// The label luoto's Containerfile puts on its build stages: their images are build cache,
/// which no name says is luoto's.
const LABEL_BUILD: &str = "luoto.build";

/// An env's volumes, and what each holds.
const VOLUMES: [(&str, &str); 4] = [
    ("work", "workspace"),
    ("home", "home"),
    ("tools", "tools"),
    ("gate", "gate"),
];

/// Used and free bytes of the disk that holds the runtime's images, containers and volumes.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Space {
    pub size: u64,
    pub used: u64,
    pub free: u64,
}

impl Space {
    pub fn low(&self) -> bool {
        self.free < LOW_FREE
    }
}

/// One env's disk use.
#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct EnvDisk {
    /// Its volumes (`workspace`, `home`, `tools`, `gate`) and `containers` (the writable
    /// layers of its dev and gate containers); what doesn't exist yet is left out.
    pub parts: Vec<Part>,
    pub total: u64,
}

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct Part {
    pub what: String,
    pub bytes: u64,
}

impl EnvDisk {
    /// `3.2 GB (workspace 1.1 GB, home 2.0 GB, …)`.
    pub fn describe(&self) -> String {
        if self.parts.is_empty() {
            return "nothing yet".into();
        }
        let parts: Vec<String> = self
            .parts
            .iter()
            .map(|p| format!("{} {}", p.what, human(p.bytes)))
            .collect();
        format!("{} ({})", human(self.total), parts.join(", "))
    }
}

/// Sizes the runtime reports, by volume and by container name.
#[derive(Default, Debug)]
pub struct Sizes {
    volumes: HashMap<String, u64>,
    containers: HashMap<String, u64>,
}

impl Sizes {
    pub fn env(&self, env: &str) -> EnvDisk {
        let mut parts: Vec<Part> = VOLUMES
            .iter()
            .filter_map(|(v, what)| {
                self.volumes.get(&names::volume(env, v)).map(|&bytes| Part {
                    what: (*what).into(),
                    bytes,
                })
            })
            .collect();
        if let Some(bytes) = [names::dev(env), names::gate(env)]
            .iter()
            .filter_map(|c| self.containers.get(c).copied())
            .reduce(|a, b| a + b)
        {
            parts.push(Part {
                what: "containers".into(),
                bytes,
            });
        }
        let total = parts.iter().map(|p| p.bytes).sum();
        EnvDisk { parts, total }
    }
}

/// Every volume's and container's size, from one `system df -v`: both runtimes print it only
/// as tables (podman refuses `--format` with `-v`; docker's JSON has the same rounded sizes).
pub fn sizes(rt: &Runtime) -> Result<Sizes> {
    if rt.flavor == Flavor::Apple {
        return apple_sizes(rt);
    }
    Ok(parse_df(&rt.run(["system", "df", "-v"])?))
}

/// Apple's volumes and containers are disk images on this machine: each takes the blocks its
/// files have allocated (a volume's file is sparse, as big as its 512 GiB capacity). Only
/// their metadata is read.
fn apple_sizes(rt: &Runtime) -> Result<Sizes> {
    let mut s = Sizes::default();
    for (name, file) in parse_apple_volumes(&rt.run(["volume", "list", "--format", "json"])?)? {
        s.volumes.insert(name, allocated(&file));
    }
    // A container's folder holds its root disk, init disk and kernel, named by its id.
    let containers = apple_root(rt)?.join("containers");
    for entry in std::fs::read_dir(&containers)
        .with_context(|| format!("read {}", containers.display()))?
        .flatten()
    {
        if let Some(name) = entry.file_name().to_str() {
            s.containers
                .insert(name.to_string(), allocated(&entry.path()));
        }
    }
    Ok(s)
}

/// Where Apple's `container` keeps its images, containers and volumes on this machine.
fn apple_root(rt: &Runtime) -> Result<std::path::PathBuf> {
    let v: Value = serde_json::from_str(rt.run(["system", "status", "--format", "json"])?.trim())
        .context("`container system status` JSON")?;
    v["paths"]["appRoot"]
        .as_str()
        .map(std::path::PathBuf::from)
        .context("`container system status` names no app root")
}

/// The bytes the files at `path` have allocated on disk, a folder's walked without following
/// links.
fn allocated(path: &std::path::Path) -> u64 {
    let Ok(m) = std::fs::symlink_metadata(path) else {
        return 0;
    };
    if m.is_dir() {
        return std::fs::read_dir(path)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| allocated(&e.path()))
            .sum();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.is_file() { m.blocks() * 512 } else { 0 }
    }
    #[cfg(not(unix))]
    {
        if m.is_file() { m.len() } else { 0 }
    }
}

/// The size and free space of the filesystem holding `path`.
#[cfg(unix)]
fn fs_space(path: &std::path::Path) -> Option<Space> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: `c` is a NUL-terminated path and `st` a statvfs that the call fills.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    let block = st.f_frsize as u64;
    let size = st.f_blocks as u64 * block;
    let free = (st.f_bavail as u64 * block).min(size);
    (size > 0).then_some(Space {
        size,
        used: size - free,
        free,
    })
}

#[cfg(not(unix))]
fn fs_space(_: &std::path::Path) -> Option<Space> {
    None
}

/// Each env's disk use, from one walk of the runtime's storage.
pub fn by_env(ctx: &Ctx) -> Result<BTreeMap<String, EnvDisk>> {
    if machine::stopped(&ctx.rt) {
        bail!("luoto's VM is stopped; sizes are read while it runs");
    }
    let sizes = sizes(&ctx.rt)?;
    Ok(config::list_envs(&ctx.paths)?
        .into_iter()
        .map(|e| {
            let d = sizes.env(&e);
            (e, d)
        })
        .collect())
}

/// What holds envs' containers and volumes, for people.
pub fn place(rt: &Runtime) -> &'static str {
    if machine::is_luoto(rt.connection.as_deref()) {
        "luoto's VM"
    } else if rt.flavor == Flavor::Apple {
        "this Mac's disk"
    } else {
        "the runtime's disk"
    }
}

/// The disk holding the runtime's storage: podman reports its graph root's filesystem (in
/// luoto's VM, the VM's disk); docker only its folder, which is on this machine's disk on
/// Linux; Apple's is the filesystem of its app root. None where that folder is elsewhere
/// (Docker Desktop's VM, a remote engine).
pub fn space(rt: &Runtime) -> Result<Option<Space>> {
    match rt.flavor {
        Flavor::Podman => Ok(parse_info(&rt.run(["info", "--format", "json"])?)),
        Flavor::Docker
            if cfg!(target_os = "linux")
                && rt.connection.is_none()
                && std::env::var_os("DOCKER_HOST").is_none() =>
        {
            let root = rt.run(["info", "--format", "{{.DockerRootDir}}"])?;
            let out = std::process::Command::new("df")
                .args(["-Pk", root.trim()])
                .output()
                .context("df")?;
            Ok(parse_df_pk(&String::from_utf8_lossy(&out.stdout)))
        }
        Flavor::Apple => Ok(fs_space(&apple_root(rt)?)),
        Flavor::Docker => Ok(None),
    }
}

static WARNED: AtomicBool = AtomicBool::new(false);

/// Warn, once a process, when the disk holding envs is nearly full.
pub fn warn_if_low(ctx: &Ctx) {
    if WARNED.swap(true, Ordering::Relaxed) {
        return;
    }
    if let Ok(Some(s)) = space(&ctx.rt)
        && s.low()
    {
        crate::progress::warn(&low_text(place(&ctx.rt), &s));
    }
}

fn low_text(place: &str, s: &Space) -> String {
    format!(
        "{place} has {} free of {}, and a full disk stops every env: `luoto prune` removes \
         luoto's superseded images",
        human(s.free),
        human(s.size)
    )
}

/// How much more of luoto's VM disk is used, at least, before a hint says so: a tenth of the
/// disk if that is more. Each repo's Rust `target/` alone can take gigabytes.
const GROWTH_MIN: u64 = 10_000_000_000;

/// Free space under each of these gets one desktop notification from the watcher.
const FREE_MARKS: [u64; 2] = [LOW_FREE, 3_000_000_000];
/// How far above a mark free space climbs before falling under it notifies again.
const REARM: u64 = 2_000_000_000;

/// What luoto remembers of the disk between commands and the watcher (`<data>/disk.json`).
#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, Eq)]
struct Seen {
    /// Used bytes growth is measured from: those at the last hint, or fewer seen since.
    #[serde(default)]
    base: Option<Mark>,
    /// How many of [`FREE_MARKS`] free space was under when last looked at.
    #[serde(default)]
    marks: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
struct Mark {
    used: u64,
    at: DateTime<Utc>,
}

#[derive(Debug, PartialEq, Eq)]
struct Growth {
    bytes: u64,
    since: DateTime<Utc>,
}

impl Seen {
    fn path(paths: &Paths) -> std::path::PathBuf {
        paths.data.join("disk.json")
    }

    fn load(paths: &Paths) -> Self {
        std::fs::read(Self::path(paths))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Change what is remembered with `f`, read just before and written at once, since the
    /// watcher writes it too; `f`'s result.
    fn update<T>(paths: &Paths, f: impl FnOnce(&mut Self) -> T) -> T {
        let mut seen = Self::load(paths);
        let before = seen.clone();
        let out = f(&mut seen);
        if seen != before
            && let Ok(json) = serde_json::to_vec_pretty(&seen)
        {
            let _ = write_private(&Self::path(paths), &json);
        }
        out
    }

    /// Whether `s` is a step of growth past the base, which it then becomes. Less used than the
    /// base (a prune, an env removed) is the new base: growth counts from the lowest point.
    fn grew(&mut self, s: &Space, now: DateTime<Utc>) -> Option<Growth> {
        let here = Mark {
            used: s.used,
            at: now,
        };
        match self.base {
            Some(b) if s.used >= b.used => {
                let bytes = s.used - b.used;
                if bytes < (s.size / 10).max(GROWTH_MIN) {
                    return None;
                }
                self.base = Some(here);
                Some(Growth { bytes, since: b.at })
            }
            _ => {
                self.base = Some(here);
                None
            }
        }
    }

    /// The mark free space in `s` fell under since last looked at, if it did. A mark counts
    /// as passed again only once free space has climbed [`REARM`] above it.
    fn crossed(&mut self, s: &Space) -> Option<u64> {
        let under = |margin: u64| FREE_MARKS.iter().filter(|m| s.free < **m + margin).count();
        let level = under(0);
        self.marks = self.marks.min(under(REARM));
        if level <= self.marks {
            return None;
        }
        self.marks = level;
        Some(FREE_MARKS[level - 1])
    }
}

/// `in 5 hours`, for how long growth took.
fn over(d: TimeDelta) -> String {
    match d.num_hours() {
        ..1 => "within the hour".into(),
        1 => "in an hour".into(),
        h @ 2..48 => format!("in {h} hours"),
        _ => format!("in {} days", d.num_days()),
    }
}

/// Folders tools fill with build output and dependencies, measured in a hint.
const BUILD_DIRS: &[&str] = &[
    "target",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "_build",
    ".next",
    ".gradle",
    ".turbo",
    ".zig-cache",
];
/// Folders smaller than this go unnamed in a hint.
const BUILD_DIR_MIN: u64 = 500_000_000;
/// How much of a folder's path a hint shows: the sandbox names folders.
const BUILD_DIR_SHOWN: usize = 120;
/// How long measuring them may take, in the env and from here.
const BUILD_DIRS_SECS: u64 = 12;

/// `du -sk` of each [`BUILD_DIRS`] folder up to four levels under `/workspace`, not looking
/// inside one; in a subshell that `timeout` ends where the image has it.
fn build_dirs_script() -> String {
    let names: Vec<String> = BUILD_DIRS.iter().map(|n| format!("-name '{n}'")).collect();
    format!(
        "cd /workspace 2>/dev/null || exit 0; find . -maxdepth 4 -type d \\( {} \\) -prune \
         -print 2>/dev/null | head -n 40 | while IFS= read -r d; do du -sk \"$d\" 2>/dev/null; \
         done",
        names.join(" -o ")
    )
}

/// `du -sk` lines (`<KiB>\t./<path>`): the folders of at least [`BUILD_DIR_MIN`], biggest
/// first, three at most, their paths as the sandbox wrote them.
fn parse_build_dirs(out: &str) -> Vec<(u64, String)> {
    let mut dirs: Vec<(u64, String)> = out
        .lines()
        .filter_map(|l| {
            let (kib, path) = l.split_once('\t')?;
            let bytes = kib.trim().parse::<u64>().ok()?.checked_mul(1024)?;
            let path = path.strip_prefix("./").unwrap_or(path);
            let path = match path.char_indices().nth(BUILD_DIR_SHOWN) {
                Some((i, _)) => format!("{}…", &path[..i]),
                None => path.to_string(),
            };
            Some((bytes, path))
        })
        .filter(|(b, _)| *b >= BUILD_DIR_MIN)
        .collect();
    dirs.sort_by_key(|d| std::cmp::Reverse(d.0));
    dirs.truncate(3);
    dirs
}

/// The biggest build and dependency folders in `env`'s workspace, as `api/target 8.1 GB`.
fn build_dirs(rt: &Runtime, env: &str) -> Vec<String> {
    let outer = format!(
        "if command -v timeout >/dev/null 2>&1; then exec timeout {BUILD_DIRS_SECS} sh -c \"$1\"; \
         else exec sh -c \"$1\"; fi"
    );
    let dev = names::dev(env);
    let script = build_dirs_script();
    let out = rt.run_limited(
        exec(&dev).user(env::UID).sh_with(&outer, [&script]),
        std::time::Duration::from_secs(BUILD_DIRS_SECS + 3),
        64 * 1024,
    );
    out.map(|o| {
        parse_build_dirs(&o)
            .into_iter()
            .map(|(b, p)| format!("{} {}", text::display(&p), human(b)))
            .collect()
    })
    .unwrap_or_default()
}

/// After `up`, `down` or a session in `env`: when luoto's VM disk has grown a step since the
/// last hint (or the least it held since), say by how much and where to look. One call to the
/// runtime; the env's build folders are measured only when the hint is due and its dev
/// container runs.
pub fn hint_growth(ctx: &Ctx, env: &str) {
    if !machine::is_luoto(ctx.rt.connection.as_deref()) {
        return;
    }
    let Ok(Some(s)) = space(&ctx.rt) else {
        return;
    };
    let now = Utc::now();
    let Some(g) = Seen::update(&ctx.paths, |seen| seen.grew(&s, now)) else {
        return;
    };
    let mut note = format!(
        "{} grew by {} {} ({} used, {} free)",
        place(&ctx.rt),
        human(g.bytes),
        over(now - g.since),
        human(s.used),
        human(s.free)
    );
    if ctx.rt.is_running(&names::dev(env)) {
        let dirs = crate::progress::wait("measuring the env's build folders", || {
            build_dirs(&ctx.rt, env)
        });
        if !dirs.is_empty() {
            note.push_str(&format!(
                "\n  the biggest build folders in `{env}`: {}",
                dirs.join(", ")
            ));
        }
    }
    note.push_str(&format!(
        "\n  `luoto list --size` shows what each env takes, `luoto status --size -e {env}` \
         where; `luoto prune` removes superseded images and returns freed space to this machine"
    ));
    crate::progress::note(&note);
}

/// For the watcher: a notification when free space has fallen under one of [`FREE_MARKS`]
/// since it last looked, once per crossing.
pub fn free_note(ctx: &Ctx) -> Option<Note> {
    let s = space(&ctx.rt).ok()??;
    Seen::update(&ctx.paths, |seen| seen.crossed(&s))?;
    Some(Note {
        title: format!(
            "{}: {} free in {}",
            names::instance(),
            human(s.free),
            place(&ctx.rt)
        ),
        body: "A full disk stops every env. `luoto list --size` shows what each takes; \
               `luoto prune` removes superseded images."
            .into(),
    })
}

/// After a pull: how much the images it superseded take, and how to remove them.
pub fn note_superseded(ctx: &Ctx) {
    if let Ok(p) = plan(ctx)
        && !p.remove.is_empty()
    {
        crate::progress::say(|| {
            println!(
                "note: {} superseded luoto image(s) take up to {}: `luoto prune` removes them",
                p.remove.len(),
                human(p.bytes())
            )
        });
    }
}

/// The disk holding envs, as the UI shows it.
#[derive(Serialize)]
pub struct VmDisk {
    /// `luoto's VM`, or `the runtime's disk` (Linux).
    pub place: String,
    /// None while luoto's VM is stopped, or where the runtime doesn't tell (Docker Desktop).
    pub space: Option<Space>,
    /// Under 10 GB is free (`LOW_FREE`).
    pub low: bool,
    /// The images `luoto prune` removes, and up to how many bytes that frees.
    pub prunable: usize,
    pub prunable_bytes: u64,
}

pub fn vm(ctx: &Ctx) -> Result<VmDisk> {
    let place = place(&ctx.rt).to_string();
    if machine::stopped(&ctx.rt) {
        return Ok(VmDisk {
            place,
            space: None,
            low: false,
            prunable: 0,
            prunable_bytes: 0,
        });
    }
    let space = space(&ctx.rt)?;
    let p = plan(ctx)?;
    Ok(VmDisk {
        place,
        low: space.is_some_and(|s| s.low()),
        space,
        prunable: p.remove.len(),
        prunable_bytes: p.bytes(),
    })
}

/// `doctor`'s lines: the disk, what is on it, and what `luoto prune` would free.
pub fn doctor_lines(ctx: &Ctx) -> Vec<String> {
    let rt = &ctx.rt;
    let place = place(rt);
    let mut out = Vec::new();
    match space(rt) {
        Ok(Some(s)) => {
            let file = machine::is_luoto(rt.connection.as_deref())
                .then(|| machine::disk_file(&rt.bin))
                .flatten()
                .map(|(_, n)| format!("; its file takes {} on this machine", human(n)))
                .unwrap_or_default();
            out.push(format!(
                "disk: {place}, {} used of {}, {} free{file}",
                human(s.used),
                human(s.size),
                human(s.free)
            ));
            if s.low() {
                out.push(format!("disk: LOW: {}", low_text(place, &s)));
            }
        }
        Ok(None) => out.push(format!(
            "disk: {place}: its size and free space are unknown"
        )),
        Err(e) => out.push(format!("disk: could not read {place}'s free space: {e:#}")),
    }
    match usage(rt) {
        Ok(u) => out.push(format!(
            "disk: images {} ({} unused), containers {}, volumes {}",
            human(u.images.size),
            human(u.images.reclaimable),
            human(u.containers.size),
            human(u.volumes.size)
        )),
        Err(e) => out.push(format!("disk: could not read what is on it: {e:#}")),
    }
    match plan(ctx) {
        Ok(p) if p.remove.is_empty() => {}
        Ok(p) => out.push(format!(
            "disk: `luoto prune` removes {} superseded luoto image(s), up to {}",
            p.remove.len(),
            human(p.bytes())
        )),
        Err(e) => out.push(format!("disk: could not list luoto's images: {e:#}")),
    }
    out
}

/// What `system df` sums up per kind.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct Kind {
    pub count: u64,
    pub size: u64,
    pub reclaimable: u64,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub images: Kind,
    pub containers: Kind,
    pub volumes: Kind,
}

pub fn usage(rt: &Runtime) -> Result<Usage> {
    let out = rt.run(["system", "df", "--format", "json"])?;
    Ok(if rt.flavor == Flavor::Apple {
        parse_apple_usage(&out)
    } else {
        parse_usage(&out)
    })
}

/// An image, as `luoto prune` judges it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Image {
    /// Without `sha256:`.
    pub id: String,
    /// Its tags and digest references (`repo:tag`, `repo@sha256:…`).
    pub names: Vec<String>,
    /// The names it had (podman): an image whose tag a newer build or pull took has none left.
    pub history: Vec<String>,
    /// Made by a build stage of luoto's Containerfile ([`LABEL_BUILD`]).
    pub build_cache: bool,
    /// Unix seconds; 0 where the runtime's listing doesn't say (docker).
    pub created: i64,
    pub size: u64,
    /// The containers that use it, where the runtime counts them (podman).
    pub containers: u64,
}

/// What `luoto prune` would do.
#[derive(Debug, Default)]
pub struct Plan {
    /// This instance's images that no container uses and that it doesn't run.
    pub remove: Vec<Image>,
    /// This instance's images it keeps: what it runs, and what containers use.
    pub kept: usize,
    /// Every other image: the other instance's, anything else in the VM, and unnamed ones no
    /// luoto build labelled.
    pub others: usize,
}

impl Plan {
    /// Up to what removing them frees: images that share layers count each.
    pub fn bytes(&self) -> u64 {
        self.remove.iter().map(|i| i.size).sum()
    }
}

/// How long before the current gate image its build's cache may be: a build takes minutes.
const BUILD_TIME: i64 = 3600;

pub fn plan(ctx: &Ctx) -> Result<Plan> {
    let rt = &ctx.rt;
    let images = images(rt)?;
    let refs = current_refs(ctx);
    let mut keep_ids = in_use(rt)?;
    keep_ids.extend(ids_of(rt, &refs));
    let (own, local) = own_repos(ctx.global.images.is_some());
    // The cache of the build that made the current images, so the next build needn't start
    // over; a release's gate has no build cache here.
    let gate = ctx.image("gate");
    let cache_since = images
        .iter()
        .find(|i| i.names.contains(&gate))
        .map_or(i64::MAX, |i| i.created - BUILD_TIME);
    Ok(select(images, &own, local, &refs, &keep_ids, cache_since))
}

/// Sort `images` into what prune removes, what it keeps of this instance's, and the rest. An
/// image is this instance's when every name it has is in `own` (or, with none left, every name
/// it had), or it is build cache and `local` builds are this instance's. It stays when its id
/// is in `keep_ids` (current, or a container's), a name of it is in `keep_refs`, or it is build
/// cache made since `cache_since`.
fn select(
    images: Vec<Image>,
    own: &BTreeSet<String>,
    local: bool,
    keep_refs: &BTreeSet<String>,
    keep_ids: &BTreeSet<String>,
    cache_since: i64,
) -> Plan {
    let all_own =
        |names: &[String]| !names.is_empty() && names.iter().all(|n| own.contains(repo_of(n)));
    let mut plan = Plan::default();
    for img in images {
        let cache = img.names.is_empty() && img.history.is_empty();
        let owned = if !img.names.is_empty() {
            all_own(&img.names)
        } else if !img.history.is_empty() {
            all_own(&img.history)
        } else {
            img.build_cache && local
        };
        if !owned {
            plan.others += 1;
        } else if keep_ids.contains(&img.id)
            || img.containers > 0
            || img.names.iter().any(|n| keep_refs.contains(n))
            || (cache && img.created >= cache_since)
        {
            plan.kept += 1;
        } else {
            plan.remove.push(img);
        }
    }
    plan
}

/// This instance's image repositories (the release's registry for a release, local builds for
/// a source build, and local builds as well when config.toml's `images` runs them), and
/// whether local builds are among them.
fn own_repos(runs_local: bool) -> (BTreeSet<String>, bool) {
    let repos = |image: &dyn Fn(&str) -> String| -> BTreeSet<String> {
        release::COMPONENTS
            .iter()
            .map(|c| repo_of(&image(c)).to_string())
            .collect()
    };
    let mut own = repos(&|c| release::image(None, c));
    let local = repos(&|c| names::image(c, "dev"));
    if runs_local {
        own.extend(local.iter().cloned());
    }
    let has_local = local.is_subset(&own);
    (own, has_local)
}

/// The images that run now: this instance's, each env's own, and the local builds either
/// instance in this VM runs.
fn current_refs(ctx: &Ctx) -> BTreeSet<String> {
    let mut refs: BTreeSet<String> = release::COMPONENTS.iter().map(|c| ctx.image(c)).collect();
    for e in config::list_envs(&ctx.paths).unwrap_or_default() {
        if let Ok(cfg) = env::layered(ctx, &e) {
            refs.insert(env::env_image(ctx, &cfg));
        }
    }
    for tag in local_tags() {
        refs.extend(release::COMPONENTS.iter().map(|c| names::image(c, &tag)));
    }
    refs
}

/// The tags of local builds an instance runs: a source build's `dev` unless its config.toml
/// says otherwise, and whatever tag a config.toml's `images` names. Read as plain TOML, so a
/// config in another release's format still counts.
fn local_tags() -> BTreeSet<String> {
    let mut tags = BTreeSet::new();
    for inst in ["luoto", "luoto-dev"] {
        let tag = Paths::of(inst)
            .ok()
            .and_then(|p| std::fs::read_to_string(p.global_config()).ok())
            .and_then(|text| text.parse::<toml::Table>().ok())
            .and_then(|t| t.get("images")?.as_str().map(String::from));
        match (inst, tag) {
            (_, Some(t)) => tags.insert(t),
            ("luoto-dev", None) => tags.insert("dev".into()),
            _ => false,
        };
    }
    if let Ok(home) = Paths::get()
        && let Ok(g) = config::load_global(&home)
        && let Some(t) = g.images
    {
        tags.insert(t);
    }
    tags
}

fn bare_id(id: &str) -> String {
    id.trim().trim_start_matches("sha256:").to_string()
}

fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().map(str::trim).filter(|l| !l.is_empty())
}

/// Every image, podman's with its names' history and container count.
fn images(rt: &Runtime) -> Result<Vec<Image>> {
    match rt.flavor {
        Flavor::Podman => parse_podman_images(&rt.run(["images", "--format", "json"])?),
        Flavor::Docker => {
            let rows = rt.run([
                "images",
                "--no-trunc",
                "--digests",
                "--format",
                "{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Digest}}\t{{.Size}}",
            ])?;
            let cache = rt.run([
                "images",
                "-q",
                "--no-trunc",
                "--filter",
                &format!("label={LABEL_BUILD}"),
            ])?;
            Ok(parse_docker_images(&rows, &cache))
        }
        Flavor::Apple => parse_apple_images(&rt.run(["image", "list", "--format", "json"])?),
    }
}

/// The ids of the images every container (any instance's, anyone's) was created from.
fn in_use(rt: &Runtime) -> Result<BTreeSet<String>> {
    if rt.flavor == Flavor::Apple {
        return parse_apple_in_use(&rt.run(["ls", "-a", "--format", "json"])?);
    }
    let ids: Vec<String> = lines(&rt.run(["ps", "-a", "-q", "--no-trunc"])?)
        .map(String::from)
        .collect();
    if ids.is_empty() {
        return Ok(BTreeSet::new());
    }
    let mut args: Vec<String> = ["container", "inspect", "--format", "{{.Image}}"]
        .map(String::from)
        .into();
    args.extend(ids);
    Ok(lines(&rt.run(args)?).map(bare_id).collect())
}

/// The ids of the images `refs` name; one call, or one each when an image is missing.
fn ids_of(rt: &Runtime, refs: &BTreeSet<String>) -> BTreeSet<String> {
    fn inspect<'a>(rt: &Runtime, refs: impl Iterator<Item = &'a String>) -> Result<String> {
        if rt.flavor == Flavor::Apple {
            let mut args: Vec<String> = ["image", "inspect"].map(String::from).into();
            args.extend(refs.cloned());
            let v: Value = serde_json::from_str(rt.run(args)?.trim()).context("image JSON")?;
            return Ok(v
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|i| i["id"].as_str())
                .map(|id| format!("{id}\n"))
                .collect());
        }
        let mut args: Vec<String> = ["image", "inspect", "--format", "{{.Id}}"]
            .map(String::from)
            .into();
        args.extend(refs.cloned());
        rt.run(args)
    }
    let found = match inspect(rt, refs.iter()) {
        Ok(out) => out,
        Err(_) => refs
            .iter()
            .filter_map(|r| inspect(rt, std::iter::once(r)).ok())
            .collect(),
    };
    lines(&found).map(bare_id).collect()
}

/// `rmi` of each image: by its names (an image with several can't go by id), else its id.
/// Never forced, so an image a container uses stays whatever the plan said. The errors.
fn remove(rt: &Runtime, images: &[Image]) -> Vec<String> {
    let rmi: &[&str] = if rt.flavor == Flavor::Apple {
        &["image", "delete"]
    } else {
        &["rmi"]
    };
    let refs: Vec<String> = images
        .iter()
        .flat_map(|i| {
            if i.names.is_empty() {
                vec![i.id.clone()]
            } else {
                i.names.clone()
            }
        })
        .collect();
    refs.chunks(50)
        .filter_map(|chunk| {
            let mut args: Vec<String> = rmi.iter().map(|s| s.to_string()).collect();
            args.extend(chunk.iter().cloned());
            rt.run(args).err().map(|e| format!("{e:#}"))
        })
        .collect()
}

/// `luoto prune`: remove this instance's images that no container uses and that it doesn't
/// run, after one question, then trim luoto's VM disk so the space returns to this machine.
pub fn prune(yes: bool) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    env::ensure_vm(&ctx)?;
    let rt = &ctx.rt;
    let inst = names::instance();
    let place = place(rt);
    let in_vm = machine::is_luoto(rt.connection.as_deref());
    let (before, file_before, p) = crate::progress::wait("looking for older images", || {
        let before = space(rt).ok().flatten();
        let file_before = in_vm.then(|| machine::disk_file(&rt.bin)).flatten();
        plan(&ctx).map(|p| (before, file_before, p))
    })?;
    let mut failed = false;
    if p.remove.is_empty() {
        println!(
            "no superseded images of {inst}'s to remove ({} kept: what it runs, what containers use)",
            p.kept
        );
    } else {
        println!(
            "`{inst} prune` removes {} of its images that no container uses and it doesn't run, \
             up to {}:",
            p.remove.len(),
            human(p.bytes())
        );
        for (group, (n, bytes)) in groups(&p.remove) {
            println!("  {group:<40} {n:>5}  {}", human(bytes));
        }
        println!(
            "It keeps {} of its images (what it runs, what containers use), the {} other image(s) \
             in {place}, and every volume.",
            p.kept, p.others
        );
        if !yes && !confirm("Remove them?") {
            bail!("nothing removed (`{inst} prune --yes` skips the question)");
        }
        let (errors, left) = crate::progress::step(
            &format!("removing {} image(s)", p.remove.len()),
            || -> Result<_> {
                let errors = remove(rt, &p.remove);
                let left: BTreeSet<String> = images(rt)?.into_iter().map(|i| i.id).collect();
                Ok((errors, left))
            },
        )?;
        let gone = p.remove.iter().filter(|i| !left.contains(&i.id)).count();
        println!("removed {gone} image(s)");
        if gone < p.remove.len() {
            failed = true;
            println!(
                "{} not removed: {}",
                p.remove.len() - gone,
                errors.first().map_or("", String::as_str)
            );
        }
    }
    // The images are gone either way; only the file on this machine keeps its size.
    if in_vm
        && let Err(e) =
            crate::progress::step("handing the freed space back to this machine", || {
                machine::trim(&rt.bin)
            })
    {
        println!("note: {e:#}");
    }
    if let (Some(b), Some(a)) = (before, space(rt).ok().flatten()) {
        println!(
            "{place}: {} used, {} before ({} freed); {} free",
            human(a.used),
            human(b.used),
            human(b.used.saturating_sub(a.used)),
            human(a.free)
        );
    }
    if let (Some((path, b)), Some((_, a))) = (file_before, machine::disk_file(&rt.bin)) {
        println!(
            "its disk file on this machine takes {}, {} before ({})",
            human(a),
            human(b),
            crate::ssh::tilde(&path)
        );
    }
    Ok(if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

/// The images to remove by repository (`build cache` for the unnamed), with count and size.
fn groups(images: &[Image]) -> BTreeMap<String, (usize, u64)> {
    let mut out: BTreeMap<String, (usize, u64)> = BTreeMap::new();
    for i in images {
        let group = match (i.names.first(), i.history.first()) {
            (Some(n), _) => repo_of(n).to_string(),
            (None, Some(h)) => format!("{} (superseded builds)", repo_of(h)),
            (None, None) => "build cache".into(),
        };
        let e = out.entry(group).or_default();
        e.0 += 1;
        e.1 += i.size;
    }
    out
}

/// Bytes for people, in the runtimes' decimal units: `4.2 GB`.
pub fn human(n: u64) -> String {
    const UNITS: [&str; 5] = ["kB", "MB", "GB", "TB", "PB"];
    if n < 1000 {
        return format!("{n} B");
    }
    let mut v = n as f64 / 1000.0;
    let mut unit = 0;
    while v >= 999.95 && unit < UNITS.len() - 1 {
        v /= 1000.0;
        unit += 1;
    }
    format!("{v:.1} {}", UNITS[unit])
}

/// Bytes from a size the runtimes print for people: `796.6MB`, `1.23 GB` (podman's images),
/// `36 B` (older docker), `2GiB`, `212B (virtual 4.8MB)` (docker's containers).
fn parse_size(text: &str) -> Option<u64> {
    let t = text.split(" (").next()?.trim();
    let end = t
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(t.len());
    let n: f64 = t[..end].parse().ok()?;
    let k: f64 = match t[end..].trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1.0,
        "kb" | "k" => 1e3,
        "mb" | "m" => 1e6,
        "gb" | "g" => 1e9,
        "tb" | "t" => 1e12,
        "pb" | "p" => 1e15,
        "kib" => 1024.0,
        "mib" => 1024f64.powi(2),
        "gib" => 1024f64.powi(3),
        "tib" => 1024f64.powi(4),
        _ => return None,
    };
    Some((n * k).round() as u64)
}

/// The tables of `system df -v` by title (`Local Volumes space usage`), each row as its cells
/// by column header. Go's tabwriter aligns them with two or more spaces between columns (a
/// header may hold one); a row splits the same way, else at its header's offsets.
fn tables(text: &str) -> HashMap<String, Vec<HashMap<String, String>>> {
    let mut out: HashMap<String, Vec<HashMap<String, String>>> = HashMap::new();
    let mut title: Option<String> = None;
    let mut columns: Option<Vec<(usize, String)>> = None;
    for line in text.lines() {
        let line = line.trim_end();
        match (&title, &columns) {
            (_, Some(_)) if line.is_empty() => (title, columns) = (None, None),
            (Some(t), Some(cols)) => out.entry(t.clone()).or_default().push(cells(line, cols)),
            (Some(_), None) if !line.is_empty() => columns = Some(header(line)),
            (None, _) => title = line.strip_suffix(':').map(String::from),
            _ => {}
        }
    }
    out
}

/// The columns of a header: where each starts (in characters) and its name.
fn header(line: &str) -> Vec<(usize, String)> {
    let chars: Vec<char> = line.chars().collect();
    let mut cols = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == ' ' {
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && !(chars[i] == ' ' && chars.get(i + 1).is_none_or(|c| *c == ' ')) {
            i += 1;
        }
        cols.push((start, chars[start..i].iter().collect()));
    }
    cols
}

fn cells(line: &str, cols: &[(usize, String)]) -> HashMap<String, String> {
    let split: Vec<&str> = line
        .split("  ")
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .collect();
    if split.len() == cols.len() {
        return cols
            .iter()
            .zip(split)
            .map(|((_, name), cell)| (name.clone(), cell.to_string()))
            .collect();
    }
    let chars: Vec<char> = line.chars().collect();
    cols.iter()
        .enumerate()
        .map(|(n, (start, name))| {
            let end = cols
                .get(n + 1)
                .map_or(chars.len(), |c| c.0)
                .min(chars.len());
            let cell: String = chars[(*start).min(end)..end].iter().collect();
            (name.clone(), cell.trim().to_string())
        })
        .collect()
}

fn parse_df(text: &str) -> Sizes {
    let mut s = Sizes::default();
    for (title, rows) in tables(text) {
        let title = title.to_ascii_lowercase();
        let (map, name_cols): (&mut HashMap<String, u64>, &[&str]) = if title.contains("volume") {
            (&mut s.volumes, &["VOLUME NAME", "NAME"])
        } else if title.contains("container") {
            (&mut s.containers, &["NAMES"])
        } else {
            continue;
        };
        for row in rows {
            let name = name_cols.iter().find_map(|c| row.get(*c));
            let size = row.get("SIZE").and_then(|v| parse_size(v));
            if let (Some(name), Some(size)) = (name, size) {
                map.insert(name.clone(), size);
            }
        }
    }
    s
}

/// The graph root's filesystem from `podman info --format json`: statfs's size, and its size
/// less its free blocks.
fn parse_info(text: &str) -> Option<Space> {
    let v: Value = serde_json::from_str(text.trim()).ok()?;
    let store = &v["store"];
    let size = store["graphRootAllocated"].as_u64()?;
    let used = store["graphRootUsed"].as_u64()?.min(size);
    (size > 0).then_some(Space {
        size,
        used,
        free: size - used,
    })
}

/// `df -Pk <dir>`: the line after the header, whose capacity field ends in `%` (a filesystem
/// name may hold spaces).
fn parse_df_pk(text: &str) -> Option<Space> {
    let fields: Vec<&str> = text.lines().nth(1)?.split_whitespace().collect();
    let cap = fields.iter().position(|w| w.ends_with('%'))?;
    let kb = |i: usize| -> Option<u64> { fields.get(i)?.parse::<u64>().ok().map(|n| n * 1024) };
    Some(Space {
        size: kb(cap.checked_sub(3)?)?,
        used: kb(cap - 2)?,
        free: kb(cap - 1)?,
    })
}

/// `system df --format json`: podman's array with raw byte counts, or docker's line per kind
/// with sizes for people.
fn parse_usage(text: &str) -> Usage {
    let objs: Vec<Value> = match serde_json::from_str::<Value>(text.trim()) {
        Ok(Value::Array(a)) => a,
        Ok(v) => vec![v],
        Err(_) => lines(text)
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect(),
    };
    let mut u = Usage::default();
    for o in objs {
        let bytes = |raw: &str, shown: &str| {
            o[raw]
                .as_u64()
                .or_else(|| o[shown].as_str().and_then(parse_size))
                .unwrap_or(0)
        };
        let kind = Kind {
            count: o["Total"]
                .as_u64()
                .or_else(|| o["TotalCount"].as_u64())
                .or_else(|| o["TotalCount"].as_str()?.parse().ok())
                .unwrap_or(0),
            size: bytes("RawSize", "Size"),
            reclaimable: bytes("RawReclaimable", "Reclaimable"),
        };
        match o["Type"].as_str() {
            Some("Images") => u.images = kind,
            Some("Containers") => u.containers = kind,
            Some("Local Volumes") => u.volumes = kind,
            _ => {}
        }
    }
    u
}

/// `podman images --format json`: an entry per tag of an image, so one image per id here.
fn parse_podman_images(text: &str) -> Result<Vec<Image>> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let v: Value = serde_json::from_str(text.trim()).context("podman images JSON")?;
    let strings = |v: &Value| -> Vec<String> {
        v.as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|s| !s.starts_with("<none>"))
            .map(String::from)
            .collect()
    };
    let mut by_id: BTreeMap<String, Image> = BTreeMap::new();
    for o in v.as_array().into_iter().flatten() {
        let Some(id) = o["Id"].as_str().map(bare_id) else {
            continue;
        };
        by_id.entry(id.clone()).or_insert_with(|| Image {
            id,
            names: strings(&o["Names"]),
            history: strings(&o["History"]),
            build_cache: o["Labels"].get(LABEL_BUILD).is_some(),
            created: o["Created"].as_i64().unwrap_or(0),
            size: o["Size"].as_u64().unwrap_or(0),
            containers: o["Containers"].as_u64().unwrap_or(0),
        });
    }
    Ok(by_id.into_values().collect())
}

/// `docker images` rows (id, repository, tag, digest, size), a row per tag; `cache` the ids
/// of build cache.
fn parse_docker_images(rows: &str, cache: &str) -> Vec<Image> {
    let cache: BTreeSet<String> = lines(cache).map(bare_id).collect();
    let mut by_id: BTreeMap<String, Image> = BTreeMap::new();
    for line in rows.lines() {
        let f: Vec<&str> = line.split('\t').map(str::trim).collect();
        let [id, repo, tag, digest, size] = f[..] else {
            continue;
        };
        if id.is_empty() {
            continue;
        }
        let id = bare_id(id);
        let img = by_id.entry(id.clone()).or_insert_with(|| Image {
            build_cache: cache.contains(&id),
            size: parse_size(size).unwrap_or(0),
            id,
            ..Default::default()
        });
        let name = match (repo, tag) {
            ("<none>" | "", _) => continue,
            (_, "<none>" | "") if digest.starts_with("sha256:") => format!("{repo}@{digest}"),
            (_, "<none>" | "") => continue,
            _ => format!("{repo}:{tag}"),
        };
        if !img.names.contains(&name) {
            img.names.push(name);
        }
    }
    by_id.into_values().collect()
}

/// `volume list --format json` of Apple's: each volume's name and its disk image's path.
fn parse_apple_volumes(text: &str) -> Result<Vec<(String, std::path::PathBuf)>> {
    let v: Value = serde_json::from_str(text.trim()).context("volume list JSON")?;
    Ok(v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|o| {
            let c = &o["configuration"];
            Some((
                c["name"].as_str()?.to_string(),
                c["source"].as_str()?.into(),
            ))
        })
        .collect())
}

/// Apple's `system df --format json`: one object, its kinds by key.
fn parse_apple_usage(text: &str) -> Usage {
    let v: Value = serde_json::from_str(text.trim()).unwrap_or_default();
    let kind = |k: &str| Kind {
        count: v[k]["total"].as_u64().unwrap_or(0),
        size: v[k]["sizeInBytes"].as_u64().unwrap_or(0),
        reclaimable: v[k]["reclaimable"].as_u64().unwrap_or(0),
    };
    Usage {
        images: kind("images"),
        containers: kind("containers"),
        volumes: kind("volumes"),
    }
}

/// Apple's `image list --format json`: an entry per name, so one image per id here, its size
/// its variants' (compressed) sizes.
fn parse_apple_images(text: &str) -> Result<Vec<Image>> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let v: Value = serde_json::from_str(text.trim()).context("image list JSON")?;
    let mut by_id: BTreeMap<String, Image> = BTreeMap::new();
    for o in v.as_array().into_iter().flatten() {
        let Some(id) = o["id"].as_str().map(bare_id) else {
            continue;
        };
        let variants: Vec<&Value> = o["variants"].as_array().into_iter().flatten().collect();
        let img = by_id.entry(id.clone()).or_insert_with(|| Image {
            id,
            build_cache: variants
                .iter()
                .any(|v| v["config"]["config"]["Labels"].get(LABEL_BUILD).is_some()),
            created: o["configuration"]["creationDate"]
                .as_str()
                .and_then(|d| DateTime::parse_from_rfc3339(d).ok())
                .map_or(0, |d| d.timestamp()),
            size: variants.iter().filter_map(|v| v["size"].as_u64()).sum(),
            ..Default::default()
        });
        if let Some(name) = o["configuration"]["name"].as_str()
            && !img.names.iter().any(|n| n == name)
        {
            img.names.push(name.to_string());
        }
    }
    Ok(by_id.into_values().collect())
}

/// The ids of the images Apple's containers (`ls -a --format json`) were created from.
fn parse_apple_in_use(text: &str) -> Result<BTreeSet<String>> {
    let v: Value = serde_json::from_str(text.trim()).context("container list JSON")?;
    Ok(v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| c["configuration"]["image"]["descriptor"]["digest"].as_str())
        .map(bare_id)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PODMAN_DF: &str = "Images space usage:

REPOSITORY                TAG         IMAGE ID      CREATED       SIZE        SHARED SIZE  UNIQUE SIZE  CONTAINERS
localhost/luoto-base      dev         0b3f9c1e5a7d  3 days ago    1.07GB      0B           1.07GB       1
localhost/luoto-gate      dev         9e1d2c3b4a5f  3 days ago    21.4MB      8.31MB       13.09MB      1

Containers space usage:

CONTAINER ID  IMAGE         COMMAND               LOCAL VOLUMES  SIZE        CREATED       STATUS      NAMES
4f1e2d3c4b5a  9e1d2c3b4a5f  run                   1              12.29kB     3 days ago    running     luoto-dev-web-gate
7a6b5c4d3e2f  0b3f9c1e5a7d  sh -c  exec sleep 1d  3              482.7MB     3 days ago    running     luoto-dev-web
1c2d3e4f5a6b  5cb3aa00f899  sleep 100             0              5.52kB      20 hours ago  exited      zen_joliot

Local Volumes space usage:

VOLUME NAME          LINKS       SIZE
luoto-dev-web-gate   1           1.94MB
luoto-dev-web-home   1           2.104GB
luoto-dev-web-tools  1           11.6MB
luoto-dev-web-work   1           356.2MB
pgdata               0           0B
";

    const DOCKER_DF: &str = "Images space usage:

REPOSITORY                TAG       IMAGE ID       CREATED       SIZE      SHARED SIZE   UNIQUE SIZE   CONTAINERS
ghcr.io/eetu/luoto-gate   <none>    1a2b3c4d5e6f   2 weeks ago   21.4MB    8.31MB        13.09MB       1

Containers space usage:

CONTAINER ID   IMAGE                                COMMAND                  LOCAL VOLUMES   SIZE                     CREATED       STATUS                     NAMES
0d1e2f3a4b5c   ghcr.io/eetu/luoto-gate@sha256:aa    \"/usr/local/bin/luot…\"   1               8.19kB (virtual 21.4MB)  2 weeks ago   Up 3 hours                 luoto-web-gate
6a7b8c9d0e1f   ghcr.io/eetu/luoto-base@sha256:dd    \"sh -c 'exec sleep 1…\"   3               1.2GB                    2 weeks ago   Exited (0) 2 minutes ago   luoto-web

Local Volumes space usage:

VOLUME NAME      LINKS     SIZE
luoto-web-home   1         3.5GB
luoto-web-work   1         36 B

Build cache usage: 0B

CACHE ID   CACHE TYPE   SIZE      CREATED   LAST USED   USAGE     SHARED
";

    #[test]
    fn sizes_people_read_become_bytes() {
        for (text, bytes) in [
            ("796.6MB", 796_600_000),
            ("1.23 GB", 1_230_000_000),
            ("36 B", 36),
            ("0B", 0),
            ("209.3kB", 209_300),
            ("2GiB", 2 * 1024 * 1024 * 1024),
            ("8.19kB (virtual 21.4MB)", 8_190),
            ("2.498GB (94%)", 2_498_000_000),
        ] {
            assert_eq!(parse_size(text), Some(bytes), "{text}");
        }
        assert_eq!(parse_size("N/A"), None);
        assert_eq!(human(999), "999 B");
        assert_eq!(human(2_104_000_000), "2.1 GB");
        assert_eq!(human(999_960), "1.0 MB");
    }

    #[test]
    fn podman_df_gives_an_envs_volumes_and_layers() {
        let s = parse_df(PODMAN_DF);
        assert_eq!(s.volumes.len(), 5);
        assert_eq!(s.containers["zen_joliot"], 5_520);
        let web = Sizes {
            volumes: s
                .volumes
                .into_iter()
                .map(|(k, v)| {
                    (
                        k.replace("luoto-dev-", &format!("{}-", names::instance())),
                        v,
                    )
                })
                .collect(),
            containers: s
                .containers
                .into_iter()
                .map(|(k, v)| {
                    (
                        k.replace("luoto-dev-", &format!("{}-", names::instance())),
                        v,
                    )
                })
                .collect(),
        }
        .env("web");
        let parts: Vec<(&str, u64)> = web
            .parts
            .iter()
            .map(|p| (p.what.as_str(), p.bytes))
            .collect();
        assert_eq!(
            parts,
            [
                ("workspace", 356_200_000),
                ("home", 2_104_000_000),
                ("tools", 11_600_000),
                ("gate", 1_940_000),
                ("containers", 482_712_290),
            ]
        );
        assert_eq!(web.total, parts.iter().map(|p| p.1).sum::<u64>());
        assert_eq!(
            web.describe(),
            "3.0 GB (workspace 356.2 MB, home 2.1 GB, tools 11.6 MB, gate 1.9 MB, containers 482.7 MB)"
        );
        assert_eq!(Sizes::default().env("web").describe(), "nothing yet");
    }

    #[test]
    fn docker_df_gives_sizes_too() {
        let s = parse_df(DOCKER_DF);
        assert_eq!(s.volumes["luoto-web-home"], 3_500_000_000);
        assert_eq!(s.volumes["luoto-web-work"], 36);
        assert_eq!(s.containers["luoto-web-gate"], 8_190);
        assert_eq!(s.containers["luoto-web"], 1_200_000_000);
        assert_eq!(s.containers.len(), 2);
    }

    #[test]
    fn a_misaligned_row_still_reads_by_its_spacing() {
        let s = parse_df(
            "Local Volumes space usage:\n\nVOLUME NAME   LINKS   SIZE\ndata          1       0B\nlong-volume-name 2 1.5GB\n",
        );
        assert_eq!(s.volumes["data"], 0);
        assert_eq!(s.volumes.len(), 1);
    }

    #[test]
    fn free_space_comes_from_podman_info_or_df() {
        let info = r#"{"host": {"arch": "arm64"}, "store": {"configFile": "/home/core/.config/containers/storage.conf",
            "graphDriverName": "overlay", "graphRoot": "/var/home/core/.local/share/containers/storage",
            "graphRootAllocated": 106769133568, "graphRootUsed": 98930077696,
            "volumePath": "/var/home/core/.local/share/containers/storage/volumes"}}"#;
        let s = parse_info(info).unwrap();
        assert_eq!(s.free, 106_769_133_568 - 98_930_077_696);
        assert!(s.low());
        assert_eq!(parse_info(r#"{"store": {"graphRoot": "/x"}}"#), None);
        let df = "Filesystem     1024-blocks      Used Available Capacity Mounted on\n\
                  /dev/nvme0n1p2   491134768 156323708 309784404      34% /\n";
        let s = parse_df_pk(df).unwrap();
        assert_eq!(s.size, 491_134_768 * 1024);
        assert_eq!(s.free, 309_784_404 * 1024);
        assert!(!s.low());
    }

    #[test]
    fn low_is_under_ten_gigabytes_free() {
        let s = |free| Space {
            size: 100_000_000_000,
            used: 100_000_000_000 - free,
            free,
        };
        assert!(s(9_999_999_999).low());
        assert!(!s(LOW_FREE).low());
    }

    fn space(used: u64) -> Space {
        let size = 100_000_000_000;
        Space {
            size,
            used,
            free: size - used,
        }
    }

    #[test]
    fn growth_is_hinted_once_a_step_from_the_lowest_point() {
        let t0 = DateTime::parse_from_rfc3339("2026-11-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let at = |h: i64| t0 + TimeDelta::hours(h);
        let mut seen = Seen::default();
        // The first look only sets the base.
        assert_eq!(seen.grew(&space(40_000_000_000), at(0)), None);
        assert_eq!(seen.grew(&space(49_000_000_000), at(1)), None);
        assert_eq!(
            seen.grew(&space(52_000_000_000), at(3)),
            Some(Growth {
                bytes: 12_000_000_000,
                since: at(0)
            })
        );
        // Not again until another step on from there.
        assert_eq!(seen.grew(&space(55_000_000_000), at(4)), None);
        // A prune lowers the base, and growth counts from there.
        assert_eq!(seen.grew(&space(30_000_000_000), at(5)), None);
        assert_eq!(
            seen.grew(&space(41_000_000_000), at(6)),
            Some(Growth {
                bytes: 11_000_000_000,
                since: at(5)
            })
        );
        // On a bigger disk the step is a tenth of it.
        let big = |used| Space {
            size: 500_000_000_000,
            used,
            free: 500_000_000_000 - used,
        };
        let mut seen = Seen::default();
        seen.grew(&big(100_000_000_000), at(0));
        assert_eq!(seen.grew(&big(140_000_000_000), at(1)), None);
        assert!(seen.grew(&big(150_000_000_000), at(1)).is_some());
    }

    #[test]
    fn each_free_mark_notifies_once_per_crossing() {
        let free = |f: u64| space(100_000_000_000 - f);
        let mut seen = Seen::default();
        assert_eq!(seen.crossed(&free(30_000_000_000)), None);
        assert_eq!(seen.crossed(&free(9_000_000_000)), Some(LOW_FREE));
        assert_eq!(seen.crossed(&free(8_000_000_000)), None);
        // Back over the mark, but not by REARM: still passed.
        assert_eq!(seen.crossed(&free(11_000_000_000)), None);
        assert_eq!(seen.crossed(&free(9_500_000_000)), None);
        assert_eq!(seen.crossed(&free(2_000_000_000)), Some(3_000_000_000));
        assert_eq!(seen.crossed(&free(2_500_000_000)), None);
        // Clear of both, then under the first again.
        assert_eq!(seen.crossed(&free(13_000_000_000)), None);
        assert_eq!(seen.marks, 0);
        assert_eq!(seen.crossed(&free(9_000_000_000)), Some(LOW_FREE));
        // Straight past both: the lower one is named.
        let mut seen = Seen::default();
        assert_eq!(seen.crossed(&free(1_000_000_000)), Some(3_000_000_000));
    }

    #[test]
    fn seen_survives_a_round_trip_and_a_bad_file() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths {
            config: dir.path().join("config"),
            data: dir.path().join("data"),
        };
        assert_eq!(Seen::load(&paths), Seen::default());
        let t = Utc::now();
        Seen::update(&paths, |s| s.grew(&space(1), t));
        assert_eq!(Seen::load(&paths).base.map(|b| b.used), Some(1));
        std::fs::write(Seen::path(&paths), b"not json").unwrap();
        assert_eq!(Seen::load(&paths), Seen::default());
    }

    #[test]
    fn growth_takes_hours_or_days() {
        assert_eq!(over(TimeDelta::minutes(20)), "within the hour");
        assert_eq!(over(TimeDelta::minutes(90)), "in an hour");
        assert_eq!(over(TimeDelta::hours(30)), "in 30 hours");
        assert_eq!(over(TimeDelta::days(9)), "in 9 days");
    }

    #[test]
    fn build_dirs_are_the_biggest_three_over_the_minimum() {
        let out = "8500000\t./api/target\n\
                   120\t./web/dist\n\
                   3100000\t./web/node_modules\n\
                   900000\t./cli/target\n\
                   2000000\t./tools/.venv\n\
                   garbage line\n\
                   x\t./bad\n";
        let dirs = parse_build_dirs(out);
        let paths: Vec<&str> = dirs.iter().map(|(_, p)| p.as_str()).collect();
        assert_eq!(paths, ["api/target", "web/node_modules", "tools/.venv"]);
        assert_eq!(dirs[0].0, 8_500_000 * 1024);
        assert!(parse_build_dirs("").is_empty());
        let long = format!("9000000\t./{}/target\n", "x".repeat(5000));
        let shown = &parse_build_dirs(&long)[0].1;
        assert_eq!(shown.chars().count(), BUILD_DIR_SHOWN + 1);
        assert!(shown.ends_with('…'));
        let script = build_dirs_script();
        assert!(script.contains("-name 'target' -o -name 'node_modules'"));
        assert!(script.contains("-prune"));
    }

    #[test]
    fn usage_reads_podmans_raw_sizes_and_dockers_lines() {
        let podman = r#"[
 {"Type":"Images","Total":12,"Active":3,"RawSize":13491151377,"RawReclaimable":922956674,"TotalCount":12,"Size":"13.49GB","Reclaimable":"923MB (7%)"},
 {"Type":"Containers","Total":4,"Active":0,"RawSize":209266,"RawReclaimable":209266,"TotalCount":4,"Size":"209.3kB","Reclaimable":"209.3kB (100%)"},
 {"Type":"Local Volumes","Total":6,"Active":1,"RawSize":796638905,"RawReclaimable":47800633,"TotalCount":6,"Size":"796.6MB","Reclaimable":"47.8MB (6%)"}
]"#;
        let u = parse_usage(podman);
        assert_eq!(
            u.images,
            Kind {
                count: 12,
                size: 13_491_151_377,
                reclaimable: 922_956_674
            }
        );
        assert_eq!(u.volumes.size, 796_638_905);
        let docker = r#"{"Active":"2","Reclaimable":"2.498GB (94%)","Size":"2.631GB","TotalCount":"6","Type":"Images"}
{"Active":"1","Reclaimable":"1.114kB (49%)","Size":"2.23kB","TotalCount":"7","Type":"Containers"}
{"Active":"0","Reclaimable":"256.5MB (100%)","Size":"256.5MB","TotalCount":"1","Type":"Local Volumes"}
{"Active":"0","Reclaimable":"158B","Size":"158B","TotalCount":"17","Type":"Build Cache"}"#;
        let u = parse_usage(docker);
        assert_eq!(
            u.images,
            Kind {
                count: 6,
                size: 2_631_000_000,
                reclaimable: 2_498_000_000
            }
        );
        assert_eq!(u.containers.count, 7);
        assert_eq!(u.volumes.size, 256_500_000);
    }

    #[test]
    fn podman_images_are_one_per_id_with_their_history() {
        // podman 5's `images --format json`: an entry per tag, RepoTags left out.
        let json = r#"[
  {"Id": "9e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d", "ParentId": "", "RepoDigests": ["localhost/luoto-gate@sha256:11"],
   "Created": 1762000000, "Size": 21400000, "SharedSize": 0, "VirtualSize": 21400000, "Labels": null, "Containers": 1,
   "Names": ["localhost/luoto-gate:dev", "localhost/luoto-gate:old"], "Digest": "sha256:11", "History": ["localhost/luoto-gate:dev"], "CreatedAt": "2026-11-01T12:00:00Z"},
  {"Id": "9e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d", "Size": 21400000, "Containers": 1,
   "Names": ["localhost/luoto-gate:dev", "localhost/luoto-gate:old"], "History": ["localhost/luoto-gate:dev"]},
  {"Id": "aa11", "Size": 20900000, "Containers": 0, "Dangling": true, "History": ["localhost/luoto-gate:dev"], "Labels": {}},
  {"Id": "bb22", "Size": 2300000000, "Containers": 0, "Dangling": true, "Labels": {"luoto.build": "cache", "org.opencontainers.image.ref.name": "x"}}
]"#;
        let imgs = parse_podman_images(json).unwrap();
        assert_eq!(imgs.len(), 3);
        let gate = imgs.iter().find(|i| i.id.starts_with("9e1d")).unwrap();
        assert_eq!(
            gate.names,
            ["localhost/luoto-gate:dev", "localhost/luoto-gate:old"]
        );
        assert_eq!((gate.containers, gate.size), (1, 21_400_000));
        let old = imgs.iter().find(|i| i.id == "aa11").unwrap();
        assert!(old.names.is_empty() && old.history == ["localhost/luoto-gate:dev"]);
        assert!(imgs.iter().find(|i| i.id == "bb22").unwrap().build_cache);
        assert!(parse_podman_images("[]\n").unwrap().is_empty());
    }

    #[test]
    fn docker_images_group_their_rows() {
        let rows = "sha256:aa\tghcr.io/eetu/luoto-gate\t<none>\tsha256:d1\t21.4MB\n\
                    sha256:bb\tlocalhost/luoto-gate\tdev\tsha256:d2\t21.4MB\n\
                    sha256:bb\tlocalhost/luoto-gate\told\tsha256:d2\t21.4MB\n\
                    sha256:cc\t<none>\t<none>\t<none>\t2.3GB\n";
        let imgs = parse_docker_images(rows, "sha256:cc\n");
        assert_eq!(imgs.len(), 3);
        assert_eq!(imgs[0].names, ["ghcr.io/eetu/luoto-gate@sha256:d1"]);
        assert_eq!(
            imgs[1].names,
            ["localhost/luoto-gate:dev", "localhost/luoto-gate:old"]
        );
        assert!(imgs[2].names.is_empty() && imgs[2].build_cache);
        assert_eq!(imgs[2].size, 2_300_000_000);
    }

    fn img(id: &str, names: &[&str]) -> Image {
        Image {
            id: id.into(),
            names: names.iter().map(|n| n.to_string()).collect(),
            size: 1_000,
            ..Default::default()
        }
    }

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn prune_takes_only_this_instances_unused_superseded_images() {
        let release = set(&["ghcr.io/eetu/luoto-gate", "ghcr.io/eetu/luoto-base"]);
        let images = vec![
            // The release's current pin, and the one a container still runs.
            img("cur", &["ghcr.io/eetu/luoto-gate@sha256:new"]),
            img("used", &["ghcr.io/eetu/luoto-gate@sha256:mid"]),
            // Superseded and unused.
            img("old", &["ghcr.io/eetu/luoto-gate@sha256:old"]),
            img("oldbase", &["ghcr.io/eetu/luoto-base@sha256:old"]),
            // The source build's, the user's own, and one also tagged as something else.
            img("dev", &["localhost/luoto-gate:dev"]),
            img("pg", &["docker.io/library/postgres:16"]),
            img("both", &["ghcr.io/eetu/luoto-base@sha256:x", "acme/base:1"]),
            // Unnamed: the source build's superseded build, build cache, and anyone's.
            Image {
                history: vec!["localhost/luoto-gate:dev".into()],
                ..img("devold", &[])
            },
            Image {
                build_cache: true,
                ..img("cache", &[])
            },
            // The cache of the build that made the current images.
            Image {
                build_cache: true,
                created: 2_000,
                ..img("hot", &[])
            },
            img("anon", &[]),
            // Counted as used by podman.
            Image {
                containers: 2,
                ..img("ext", &["ghcr.io/eetu/luoto-base@sha256:ext"])
            },
        ];
        let keep_refs = set(&["ghcr.io/eetu/luoto-gate@sha256:new"]);
        let keep_ids = set(&["used"]);
        let p = select(images.clone(), &release, false, &keep_refs, &keep_ids, 0);
        let ids: Vec<&str> = p.remove.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(ids, ["old", "oldbase"]);
        assert_eq!((p.kept, p.others), (3, 7));
        assert_eq!(p.bytes(), 2_000);

        // The source build: local builds, their superseded ones and older build cache.
        let local = set(&["localhost/luoto-gate", "localhost/luoto-base"]);
        let p = select(
            images.clone(),
            &local,
            true,
            &set(&["localhost/luoto-gate:dev"]),
            &BTreeSet::new(),
            1_000,
        );
        let ids: Vec<&str> = p.remove.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(ids, ["devold", "cache"]);
        assert_eq!(p.kept, 2);

        // An id kept by name alone (a pin inspected as missing) still stays by its name.
        let p = select(
            vec![img("cur", &["ghcr.io/eetu/luoto-gate@sha256:new"])],
            &release,
            false,
            &keep_refs,
            &BTreeSet::new(),
            0,
        );
        assert!(p.remove.is_empty());
    }

    #[test]
    fn superseded_history_with_another_name_is_not_ours() {
        let local = set(&["localhost/luoto-gate"]);
        let mixed = Image {
            history: vec!["localhost/luoto-gate:dev".into(), "acme/gate:1".into()],
            ..img("x", &[])
        };
        let none = BTreeSet::new();
        let p = select(vec![mixed], &local, true, &none, &none, i64::MAX);
        assert!(p.remove.is_empty());
        assert_eq!(p.others, 1);
    }

    #[test]
    fn own_repos_follow_the_instance_and_its_local_builds() {
        let (own, local) = own_repos(false);
        for c in release::COMPONENTS {
            assert!(own.contains(repo_of(&release::image(None, c))));
        }
        // A source build (as tests are) runs local builds anyway.
        assert_eq!(local, !release::pinned());
        let (own, local) = own_repos(true);
        assert!(local && own.contains("localhost/luoto-base"));
    }

    #[test]
    fn groups_name_repositories_and_build_cache() {
        let g = groups(&[
            img("a", &["ghcr.io/eetu/luoto-gate@sha256:a"]),
            img("b", &["ghcr.io/eetu/luoto-gate@sha256:b"]),
            Image {
                history: vec!["localhost/luoto-gate:dev".into()],
                ..img("c", &[])
            },
            img("d", &[]),
        ]);
        assert_eq!(g["ghcr.io/eetu/luoto-gate"], (2, 2_000));
        assert_eq!(g["localhost/luoto-gate (superseded builds)"], (1, 1_000));
        assert_eq!(g["build cache"], (1, 1_000));
    }

    #[test]
    fn apple_listings_give_usage_volumes_and_images() {
        let df = r#"{"containers":{"active":0,"reclaimable":4336214016,"sizeInBytes":4336214016,"total":4},
            "images":{"active":4,"reclaimable":1568169984,"sizeInBytes":3393437696,"total":14},
            "volumes":{"active":4,"reclaimable":0,"sizeInBytes":160038912,"total":4}}"#;
        let u = parse_apple_usage(df);
        assert_eq!(
            u.images,
            Kind {
                count: 14,
                size: 3_393_437_696,
                reclaimable: 1_568_169_984
            }
        );
        assert_eq!(u.containers.size, 4_336_214_016);
        assert_eq!(u.volumes.count, 4);

        let vols = r#"[{"configuration":{"driver":"local","format":"ext4","labels":{"luoto.role":"work"},"name":"luoto-dev-ae-work","sizeInBytes":549755813888,"source":"/Users/u/Library/Application Support/com.apple.container/volumes/luoto-dev-ae-work/volume.img"},"id":"luoto-dev-ae-work"}]"#;
        assert_eq!(
            parse_apple_volumes(vols).unwrap(),
            [(
                "luoto-dev-ae-work".to_string(),
                "/Users/u/Library/Application Support/com.apple.container/volumes/luoto-dev-ae-work/volume.img".into()
            )]
        );

        let imgs = r#"[{"configuration":{"creationDate":"2026-11-11T21:34:59Z","name":"localhost/luoto-gate:apple"},"id":"f9a3","variants":[{"config":{"config":{"Labels":{"io.buildah.version":"1.45.2"}}},"platform":{"architecture":"arm64"},"size":8149647}]},
            {"configuration":{"creationDate":"2026-11-11T21:34:59Z","name":"localhost/luoto-gate:dev"},"id":"f9a3","variants":[{"config":{"config":{}},"size":8149647}]},
            {"configuration":{"creationDate":"2026-11-11T21:05:48Z","name":"localhost/luoto-gate:tun"},"id":"ea33","variants":[{"config":{"config":{"Labels":{"luoto.build":"gate"}}},"size":8172138},{"config":{},"size":100}]}]"#;
        let images = parse_apple_images(imgs).unwrap();
        assert_eq!(images.len(), 2);
        let tun = images.iter().find(|i| i.id == "ea33").unwrap();
        assert_eq!(tun.names, ["localhost/luoto-gate:tun"]);
        assert!(tun.build_cache);
        assert_eq!(tun.size, 8_172_238);
        let dev = images.iter().find(|i| i.id == "f9a3").unwrap();
        assert_eq!(
            dev.names,
            ["localhost/luoto-gate:apple", "localhost/luoto-gate:dev"]
        );
        assert_eq!(dev.created, 1_794_432_899);
        assert!(!dev.build_cache);

        let ls = r#"[{"configuration":{"id":"luoto-dev-ae-gate","image":{"descriptor":{"digest":"sha256:f9a3"},"reference":"localhost/luoto-gate:dev"}},"id":"luoto-dev-ae-gate"}]"#;
        let used = parse_apple_in_use(ls).unwrap();
        assert_eq!(used, set(&["f9a3"]));
        // What a container uses stays; the superseded tag goes.
        let own = set(&["localhost/luoto-gate"]);
        let p = select(images, &own, true, &BTreeSet::new(), &used, i64::MAX);
        assert_eq!(p.remove.len(), 1);
        assert_eq!(p.remove[0].id, "ea33");
        assert_eq!(p.kept, 1);
    }

    #[cfg(unix)]
    #[test]
    fn allocated_counts_blocks_not_length() {
        let dir = tempfile::tempdir().unwrap();
        let sparse = std::fs::File::create(dir.path().join("volume.img")).unwrap();
        sparse.set_len(1 << 30).unwrap();
        std::fs::write(dir.path().join("config.json"), vec![1u8; 10_000]).unwrap();
        let n = allocated(dir.path());
        assert!(n >= 10_000, "{n}");
        assert!(n < 1 << 20, "a sparse file counts what it holds: {n}");
        assert_eq!(allocated(&dir.path().join("missing")), 0);
        let s = fs_space(dir.path()).unwrap();
        assert!(s.size > 0 && s.free <= s.size && s.used == s.size - s.free);
    }
}
