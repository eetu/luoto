//! What a project says about itself, read from its folder at `luoto init` or from a running
//! env's workspace: the toolchains its version files pin, the package managers its lockfiles
//! name and the package registries it uses (presets whose `detect` files are present), in the
//! folder and its subfolders (a monorepo's `frontend/`, `backend/`).
//! Suggestions only: mise reads the same files again inside the env.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use luoto_shared::presets;
use serde::Serialize;

/// The most of one file detection reads: pins sit at the top.
pub const READ_CAP: usize = 256 * 1024;

/// Tools whose idiomatic version files mise reads in an env (mise has them off by default).
pub const IDIOMATIC_TOOLS: &[&str] = &[
    "node",
    "npm",
    "yarn",
    "pnpm",
    "bun",
    "deno",
    "python",
    "ruby",
    "java",
    "go",
    "rust",
    "terraform",
    "zig",
    "swift",
];

/// Single-version files, by tool.
const VERSION_FILES: &[(&str, &str)] = &[
    (".node-version", "node"),
    (".nvmrc", "node"),
    (".python-version", "python"),
    (".ruby-version", "ruby"),
    (".java-version", "java"),
    (".go-version", "go"),
    (".bun-version", "bun"),
    (".deno-version", "deno"),
    (".terraform-version", "terraform"),
    (".zig-version", "zig"),
    (".swift-version", "swift"),
];

const MISE_CONFIGS: &[&str] = &[
    "mise.toml",
    ".mise.toml",
    "mise/config.toml",
    ".mise/config.toml",
    ".config/mise.toml",
    ".config/mise/config.toml",
];

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ToolPin {
    pub tool: String,
    pub version: String,
    /// The file that pins it.
    pub source: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Detected {
    /// Suggested presets, each with the file that suggested it.
    pub presets: Vec<(String, String)>,
    /// Pinned toolchains: per folder, one per tool in the order mise prefers its sources.
    pub tools: Vec<ToolPin>,
    /// Runtimes the project needs (a preset's file is there) but pins nowhere; the env gets
    /// them as defaults, which a version file overrides wherever one appears.
    pub defaults: Vec<ToolPin>,
}

/// How deep below the project folder detection and installs look.
pub const DEPTH: usize = 3;

/// Folders never looked into (dependencies, build output, virtualenvs), as hidden ones aren't.
/// In a git work tree, `.gitignore` excludes more.
pub const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "target",
    "vendor",
    "dist",
    "build",
    "out",
    "coverage",
    "venv",
    "__pycache__",
];

/// Files besides `VERSION_FILES` and `MISE_CONFIGS` that can pin a toolchain for the folder
/// they are in.
const OTHER_PINS: &[&str] = &[
    ".tool-versions",
    "package.json",
    "go.mod",
    "rust-toolchain.toml",
    "Gemfile",
];

/// Files that mark a Terraform or OpenTofu module; detection reads them for the tool and its
/// `required_version`.
const TF_FILES: &[&str] = &[
    ".terraform.lock.hcl",
    ".opentofu-version",
    "versions.tf",
    "terraform.tf",
    "main.tf",
    "versions.tofu",
    "main.tofu",
];

/// Task runners a project drives through a file of theirs: (file, tool). The env gets the
/// latest unless a version file pins one.
const RUNNERS: &[(&str, &str)] = &[
    ("justfile", "just"),
    ("Justfile", "just"),
    (".justfile", "just"),
    ("Taskfile.yml", "task"),
    ("Taskfile.yaml", "task"),
];

/// Package managers a project drives through a lockfile of theirs: (lockfile, tool, the
/// `pyproject.toml` `[tool.*]` table that names it too). The env gets the latest unless
/// something pins one.
const MANAGERS: &[(&str, &str, Option<&str>)] = &[
    ("uv.lock", "uv", Some("uv")),
    ("poetry.lock", "poetry", Some("poetry")),
    ("yarn.lock", "yarn", None),
    ("pnpm-lock.yaml", "pnpm", None),
];

/// What `package.json` can name as its package manager: once it names one, a lockfile of
/// another is left over from before.
const JS_MANAGERS: &[&str] = &["npm", "yarn", "pnpm", "bun"];

/// A preset's file implies its runtime: (preset, tool, default version).
const UNPINNED: &[(&str, &str, &str)] = &[
    ("crates", "rust", "stable"),
    ("npm", "node", "lts"),
    // Python 3 would be the newest minor, released each October; packages with C code take
    // months to publish wheels for it (cffi had none for 3.15 at its release), and without
    // one they build from source. Move this up when the next one has caught up.
    ("pypi", "python", "3.14"),
];

/// The preset a runtime's packages come from (`node` → `npm`).
pub fn preset_for(tool: &str) -> Option<&'static str> {
    match tool {
        "go" => Some("go"),
        "terraform" => Some("terraform"),
        "opentofu" => Some("opentofu"),
        _ => UNPINNED
            .iter()
            .find(|(_, t, _)| *t == tool)
            .map(|(p, _, _)| *p),
    }
}

/// A project's files: their relative paths (in a git work tree, those git doesn't ignore),
/// and the text of those detection reads ([`read_paths`]).
#[derive(Debug, Default)]
pub struct Listed {
    pub files: Vec<String>,
    pub texts: HashMap<String, String>,
}

/// The files whose text detection reads, among `files` (relative paths): those that can pin
/// a toolchain or name a package manager, in the folders worth reading.
pub fn read_paths(files: &[String]) -> Vec<String> {
    let mut names: Vec<&str> = MISE_CONFIGS.to_vec();
    names.extend(VERSION_FILES.iter().map(|(f, _)| *f));
    names.extend(OTHER_PINS);
    // What `MANAGERS` reads: pyproject's `[tool.*]` tables and yarn.lock's version.
    names.extend(["pyproject.toml", "yarn.lock"]);
    names.extend(TF_FILES);
    let listed: HashSet<&str> = files.iter().map(String::as_str).collect();
    pin_dirs(files.iter().map(String::as_str))
        .iter()
        .flat_map(|dir| names.iter().map(move |n| join(dir, n)))
        .filter(|f| listed.contains(f.as_str()))
        .collect()
}

/// A relative path in `dir` (`""` for the root), with `/` on every platform.
fn join(dir: &str, file: &str) -> String {
    if dir.is_empty() {
        file.to_string()
    } else {
        format!("{dir}/{file}")
    }
}

/// What a folder on the host says about itself.
pub fn detect(root: &Path) -> Detected {
    detect_roots(&[(String::new(), root.to_path_buf())])
}

/// Detection over folders read as one tree, each `(name, folder)` with its files under
/// `name/` (`""` for the project's folder): the repos of a multi-repo env.
pub fn detect_roots(roots: &[(String, PathBuf)]) -> Detected {
    let mut files = Vec::new();
    let mut texts = HashMap::new();
    for (name, root) in roots {
        let own = host_files(root);
        for rel in read_paths(&own) {
            if let Some(text) = read_host(&root.join(&rel)) {
                texts.insert(join(name, &rel), text);
            }
        }
        files.extend(own.iter().map(|f| join(name, f)));
    }
    detect_tree(&Listed { files, texts })
}

/// A folder's files: from git in a work tree, else from a walk; plus those of the
/// repositories directly in it (a folder that holds a project's repos), which git in the
/// folder doesn't list.
fn host_files(root: &Path) -> Vec<String> {
    let Some(mut files) = git_files(root) else {
        return walk_files(root);
    };
    let Ok(entries) = std::fs::read_dir(root) else {
        return files;
    };
    for e in entries.filter_map(Result::ok) {
        let Ok(name) = e.file_name().into_string() else {
            continue;
        };
        if e.file_type().is_ok_and(|t| t.is_dir())
            && !name.starts_with('.')
            && !SKIP_DIRS.contains(&name.as_str())
            && e.path().join(".git").exists()
            && let Some(nested) = git_files(&e.path())
        {
            let prefix = format!("{name}/");
            files.retain(|f| !f.starts_with(&prefix));
            files.extend(nested.into_iter().map(|f| join(&name, &f)));
        }
    }
    files
}

/// A regular file's text, at most `READ_CAP` bytes. Never through a symlink: a repository can
/// commit one to `/dev/zero`, a FIFO or a file of yours.
fn read_host(path: &Path) -> Option<String> {
    if !std::fs::symlink_metadata(path).ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    std::fs::File::open(path)
        .ok()?
        .take(READ_CAP as u64)
        .read_to_string(&mut text)
        .ok()?;
    Some(text)
}

pub fn detect_tree(tree: &Listed) -> Detected {
    let mut d = Detected::default();
    let listed: HashSet<&str> = tree.files.iter().map(String::as_str).collect();
    for rel in pin_dirs(tree.files.iter().map(String::as_str)) {
        detect_in(tree, &listed, &rel, &mut d);
    }
    d.defaults
        .retain(|r| !d.tools.iter().any(|t| t.tool == r.tool));
    for (preset, tool, version) in UNPINNED {
        if let Some((_, file)) = d.presets.iter().find(|(p, _)| p == preset)
            && !d.tools.iter().any(|t| t.tool == *tool)
        {
            d.defaults.push(ToolPin {
                tool: (*tool).to_string(),
                version: (*version).to_string(),
                source: file.clone(),
            });
        }
    }
    d
}

/// The folders worth reading (relative, `""` for the root, always included, then sorted):
/// those holding a file that pins a toolchain or names a registry among `files` (relative
/// paths), down to `DEPTH`. On the host the list comes from git in a work tree (so
/// .gitignore keeps dependencies and build output out), else from a walk.
pub fn pin_dirs<'a>(files: impl Iterator<Item = &'a str>) -> BTreeSet<String> {
    let mut names: HashSet<&str> = OTHER_PINS.iter().copied().collect();
    names.extend(VERSION_FILES.iter().map(|(f, _)| *f));
    names.extend(MISE_CONFIGS.iter().filter(|f| !f.contains('/')));
    names.extend(RUNNERS.iter().map(|(f, _)| *f));
    names.extend(MANAGERS.iter().map(|(f, _, _)| *f));
    names.extend(TF_FILES);
    let presets = presets::all();
    names.extend(
        presets
            .iter()
            .flat_map(|p| p.detect.iter())
            .filter(|f| !f.contains('/'))
            .map(String::as_str),
    );
    let mut dirs = BTreeSet::from([String::new()]);
    for f in files {
        let p = Path::new(f);
        // The name list holds in git work trees too: .gitignore only adds to it.
        let skipped = p.parent().is_some_and(|d| {
            d.components().any(|c| {
                let c = c.as_os_str().to_string_lossy();
                c.starts_with('.') || SKIP_DIRS.contains(&c.as_ref())
            })
        });
        if skipped || p.components().count() > DEPTH + 1 {
            continue;
        }
        if p.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| names.contains(n))
        {
            let parent = p.parent().map(|d| d.to_string_lossy().into_owned());
            dirs.insert(parent.unwrap_or_default());
        }
    }
    dirs
}

/// Tracked and untracked-but-not-ignored files, when `root` is a git work tree. Run with
/// fsmonitor off, so a repository's config can't make this start a program.
fn git_files(root: &Path) -> Option<Vec<String>> {
    let out = Command::new("git")
        .args(["-c", "core.fsmonitor=false", "-C"])
        .arg(root)
        .args([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status.success().then(|| {
        String::from_utf8_lossy(&out.stdout)
            .split('\0')
            .filter(|f| !f.is_empty())
            .map(str::to_string)
            .collect()
    })
}

/// Files down to `DEPTH` folders, skipping symlinks, hidden folders and `SKIP_DIRS`. Paths
/// are relative with `/`, as git lists them, on every platform.
fn walk_files(root: &Path) -> Vec<String> {
    let mut files = Vec::new();
    let mut dirs = vec![(String::new(), 0)];
    while let Some((rel, depth)) = dirs.pop() {
        let Ok(entries) = std::fs::read_dir(root.join(&rel)) else {
            continue;
        };
        for e in entries.filter_map(Result::ok) {
            let Ok(name) = e.file_name().into_string() else {
                continue;
            };
            let Ok(kind) = e.file_type() else { continue };
            if kind.is_file() {
                files.push(join(&rel, &name));
            } else if kind.is_dir()
                && depth < DEPTH
                && !name.starts_with('.')
                && !SKIP_DIRS.contains(&name.as_str())
            {
                dirs.push((join(&rel, &name), depth + 1));
            }
        }
    }
    files
}

fn detect_in(tree: &Listed, listed: &HashSet<&str>, rel: &str, d: &mut Detected) {
    let source = |f: &str| join(rel, f);
    let mut here: Vec<ToolPin> = Vec::new();
    let mut add = |tool: &str, version: &str, file: &str| {
        // asdf plugin names mise aliases.
        let tool = match tool {
            "nodejs" => "node",
            "golang" => "go",
            t => t,
        };
        let version = version.trim();
        // From the project's files: only what reads as a tool name and a version, so a file
        // can't put escape sequences or pages of text in the proposal.
        let plausible = |s: &str, extra: &[u8]| {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
        };
        if plausible(version, b"._-+~^<>=*@/: ")
            && plausible(tool, b"._-:@/")
            && !here.iter().any(|t| t.tool == tool)
        {
            here.push(ToolPin {
                tool: tool.to_string(),
                version: version.to_string(),
                source: source(file),
            });
        }
    };
    let read = |f: &str| tree.texts.get(&join(rel, f)).map(String::as_str);
    let has = |f: &str| listed.contains(join(rel, f).as_str());

    for f in MISE_CONFIGS {
        if let Some(t) = read(f).and_then(|s| s.parse::<toml::Table>().ok())
            && let Some(table) = t.get("tools").and_then(|v| v.as_table())
        {
            for (tool, v) in table {
                add(tool, &mise_version(v), f);
            }
        }
    }
    if let Some(s) = read(".tool-versions") {
        for line in s.lines() {
            let mut parts = line.split('#').next().unwrap_or("").split_whitespace();
            if let (Some(tool), Some(v)) = (parts.next(), parts.next()) {
                add(tool, v, ".tool-versions");
            }
        }
    }
    for (f, tool) in VERSION_FILES {
        if let Some(s) = read(f) {
            let v = s
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty() && !l.starts_with('#'))
                .unwrap_or("");
            add(tool, v, f);
        }
    }
    if let Some(pkg) =
        read("package.json").and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
    {
        let dev = &pkg["devEngines"];
        let first = |v: &serde_json::Value| {
            v.as_array()
                .and_then(|a| a.first())
                .cloned()
                .unwrap_or(v.clone())
        };
        let runtime = first(&dev["runtime"]);
        if let (Some(n), Some(v)) = (runtime["name"].as_str(), runtime["version"].as_str()) {
            add(n, v, "package.json");
        }
        let pm = first(&dev["packageManager"]);
        if let (Some(n), Some(v)) = (pm["name"].as_str(), pm["version"].as_str()) {
            add(n, v, "package.json");
        }
        if let Some((n, v)) = pkg["packageManager"]
            .as_str()
            .and_then(|s| s.split_once('@'))
        {
            add(n, v.split('+').next().unwrap_or(v), "package.json");
        }
    }
    if let Some(s) = read("go.mod")
        && let Some(v) = s.lines().find_map(|l| l.trim().strip_prefix("go "))
    {
        add("go", v, "go.mod");
    }
    if let Some(t) = read("rust-toolchain.toml").and_then(|s| s.parse::<toml::Table>().ok())
        && let Some(v) = t
            .get("toolchain")
            .and_then(|t| t.get("channel"))
            .and_then(|v| v.as_str())
    {
        add("rust", v, "rust-toolchain.toml");
    }
    if let Some(s) = read("Gemfile")
        && let Some(v) = s.lines().find_map(|l| l.trim().strip_prefix("ruby "))
    {
        add("ruby", v.trim_matches(|c| c == '"' || c == '\''), "Gemfile");
    }

    let js_named = here.iter().any(|t| JS_MANAGERS.contains(&t.tool.as_str()));
    let pyproject = read("pyproject.toml").and_then(|s| s.parse::<toml::Table>().ok());
    for (lock, tool, table) in MANAGERS {
        if js_named && JS_MANAGERS.contains(tool) {
            continue;
        }
        let file = if has(lock) {
            *lock
        } else if table.is_some_and(|t| {
            pyproject
                .as_ref()
                .and_then(|p| p.get("tool"))
                .is_some_and(|tools| tools.get(t).is_some())
        }) {
            "pyproject.toml"
        } else {
            continue;
        };
        // Yarn 1 and Yarn 2+ are different tools: a v1 lockfile wants the first.
        let classic = *tool == "yarn"
            && read(lock)
                .is_some_and(|s| s.lines().take(5).any(|l| l.contains("yarn lockfile v1")));
        if !d.defaults.iter().any(|t| t.tool == *tool) {
            d.defaults.push(ToolPin {
                tool: (*tool).to_string(),
                version: if classic { "1" } else { "latest" }.into(),
                source: source(file),
            });
        }
    }

    terraform(&read, &has, &source, d);

    for t in here {
        if !d
            .tools
            .iter()
            .any(|x| x.tool == t.tool && x.version == t.version)
        {
            d.tools.push(t);
        }
    }
    for (file, tool) in RUNNERS {
        if has(file) && !d.defaults.iter().any(|t| t.tool == *tool) {
            d.defaults.push(ToolPin {
                tool: (*tool).to_string(),
                version: "latest".into(),
                source: source(file),
            });
        }
    }
    for p in presets::all() {
        if !d.presets.iter().any(|(n, _)| *n == p.name)
            && let Some(f) = p.detect.iter().find(|f| has(f))
        {
            d.presets.push((p.name.clone(), source(f)));
        }
    }
}

/// Terraform or OpenTofu: the lock file names the tool by its providers' registry, and
/// `.opentofu-version` or a `.tofu` file means OpenTofu. Its version (OpenTofu's version file,
/// else an exact `required_version`, else the latest) is a default, as mise reads neither;
/// `.terraform-version`, which it does read, pins over it.
fn terraform<'a>(
    read: &impl Fn(&str) -> Option<&'a str>,
    has: &impl Fn(&str) -> bool,
    source: &impl Fn(&str) -> String,
    d: &mut Detected,
) {
    let Some(marker) = std::iter::once(&".terraform-version")
        .chain(TF_FILES)
        .find(|f| has(f))
    else {
        return;
    };
    let tofu = has(".opentofu-version")
        || TF_FILES.iter().any(|f| f.ends_with(".tofu") && has(f))
        || read(".terraform.lock.hcl").is_some_and(|l| l.contains("\"registry.opentofu.org/"));
    let tool = if tofu { "opentofu" } else { "terraform" };
    let from_file = tofu
        .then(|| read(".opentofu-version"))
        .flatten()
        .and_then(|s| {
            s.lines()
                .map(str::trim)
                .find(|l| !l.is_empty() && !l.starts_with('#'))
        })
        .filter(|v| {
            v.len() <= 32
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
        .map(|v| (v.to_string(), ".opentofu-version"));
    let (version, file) = from_file
        .or_else(|| {
            [
                "versions.tf",
                "terraform.tf",
                "main.tf",
                "versions.tofu",
                "main.tofu",
            ]
            .into_iter()
            .find_map(|f| read(f).and_then(required_version).map(|v| (v, f)))
        })
        .unwrap_or_else(|| ("latest".into(), marker));
    if !d.defaults.iter().any(|t| t.tool == tool) {
        d.defaults.push(ToolPin {
            tool: tool.into(),
            version,
            source: source(file),
        });
    }
    if !d.presets.iter().any(|(n, _)| n == tool) {
        d.presets.push((tool.into(), source(marker)));
    }
}

/// The version an exact or patch-level `required_version` names (`1.9.5`, `= 1.9.5`,
/// `~> 1.9.0` as `1.9`); `None` for a range, which leaves the latest.
fn required_version(text: &str) -> Option<String> {
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with("required_version"))?;
    let quoted = line.split_once('=')?.1.trim().strip_prefix('"')?;
    let value = quoted.split('"').next()?.trim();
    let (exact, v) = match value.strip_prefix("~>") {
        Some(v) => (false, v.trim()),
        None => (true, value.strip_prefix('=').unwrap_or(value).trim()),
    };
    let parts: Vec<&str> = v.split('.').collect();
    let numbers = parts
        .iter()
        .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    match (numbers, parts.len(), exact) {
        (true, 3, true) => Some(v.to_string()),
        (true, 3, false) => Some(parts[..2].join(".")),
        _ => None,
    }
}

/// The version a mise `[tools]` entry asks for: `"22"`, `["22", "20"]` or `{ version = "22" }`.
fn mise_version(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => s.clone(),
        toml::Value::Array(a) => a.first().map(mise_version).unwrap_or_default(),
        toml::Value::Table(t) => t.get("version").map(mise_version).unwrap_or_default(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn hostile_files_pin_nothing_and_are_never_followed() {
        let d = tempfile::tempdir().unwrap();
        let secret = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(secret.path(), "the first line of a key\n").unwrap();
        std::os::unix::fs::symlink(secret.path(), d.path().join(".nvmrc")).unwrap();
        // A FIFO would block a plain read forever.
        assert!(
            std::process::Command::new("mkfifo")
                .arg(d.path().join(".python-version"))
                .status()
                .unwrap()
                .success()
        );
        std::fs::write(
            d.path().join(".ruby-version"),
            "3.3\x1b]52;c;cHduZWQ=\x07\n",
        )
        .unwrap();
        std::fs::write(d.path().join(".go-version"), "1.23\n").unwrap();
        let found = detect(d.path());
        let pinned: Vec<(&str, &str)> = found
            .tools
            .iter()
            .map(|t| (t.tool.as_str(), t.version.as_str()))
            .collect();
        assert_eq!(pinned, [("go", "1.23")], "{pinned:?}");
    }

    #[test]
    fn reads_version_files_in_mise_order() {
        let d = tempfile::tempdir().unwrap();
        let w = |f: &str, s: &str| {
            let p = d.path().join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, s).unwrap();
        };
        w("mise.toml", "[tools]\npython = { version = \"3.13\" }\n");
        w(
            ".tool-versions",
            "# comment\nnodejs 20.1.0\nphp 8.3.14 8.2.0\n",
        );
        w(".node-version", "v22\n");
        w(".python-version", "3.12\n");
        w(
            "package.json",
            r#"{"packageManager":"yarn@4.16.0+sha512.abc","devEngines":{"runtime":{"name":"node","version":"24"}}}"#,
        );
        w("go.mod", "module x\n\ngo 1.23.4\n");
        w("pyproject.toml", "");
        let r = detect(d.path());
        let pins: Vec<(&str, &str, &str)> = r
            .tools
            .iter()
            .map(|t| (t.tool.as_str(), t.version.as_str(), t.source.as_str()))
            .collect();
        assert_eq!(
            pins,
            [
                ("python", "3.13", "mise.toml"),
                ("node", "20.1.0", ".tool-versions"),
                ("php", "8.3.14", ".tool-versions"),
                ("yarn", "4.16.0", "package.json"),
                ("go", "1.23.4", "go.mod"),
            ]
        );
        let presets: Vec<&str> = r.presets.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(presets, ["npm", "pypi", "go"]);
    }

    #[test]
    fn subfolders_count_and_unpinned_runtimes_get_defaults() {
        let d = tempfile::tempdir().unwrap();
        let w = |f: &str, s: &str| {
            let p = d.path().join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, s).unwrap();
        };
        w("Cargo.toml", "[workspace]\n");
        w("justfile", "default:\n");
        w("frontend/.node-version", "26\n");
        w(
            "frontend/package.json",
            r#"{"packageManager":"yarn@4.18.0"}"#,
        );
        w("frontend/node_modules/x/.node-version", "10\n");
        w(".hidden/.python-version", "3.9\n");
        w("generated/.python-version", "3.8\n");
        w(".gitignore", "generated/\n");
        let walked = detect(d.path());
        // In a git work tree .gitignore decides; outside one a name list does.
        let git = |args: &[&str]| {
            Command::new("git")
                .arg("-C")
                .arg(d.path())
                .args(args)
                .output()
                .unwrap()
        };
        git(&["init", "-q"]);
        let r = detect(d.path());
        for found in [&walked, &r] {
            let pins: Vec<(&str, &str, &str)> = found
                .tools
                .iter()
                .filter(|t| t.tool != "python")
                .map(|t| (t.tool.as_str(), t.version.as_str(), t.source.as_str()))
                .collect();
            assert_eq!(
                pins,
                [
                    ("node", "26", "frontend/.node-version"),
                    ("yarn", "4.18.0", "frontend/package.json"),
                ]
            );
        }
        assert!(
            r.tools.iter().all(|t| t.tool != "python"),
            "ignored by .gitignore"
        );
        let presets: Vec<&str> = r.presets.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(presets, ["crates", "npm"]);
        let defaults: Vec<(&str, &str)> = r
            .defaults
            .iter()
            .map(|t| (t.tool.as_str(), t.version.as_str()))
            .collect();
        assert_eq!(defaults, [("just", "latest"), ("rust", "stable")]);
    }

    fn managers(files: &[(&str, &str)]) -> Vec<(String, String, String)> {
        let d = tempfile::tempdir().unwrap();
        for (f, s) in files {
            let p = d.path().join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, s).unwrap();
        }
        detect(d.path())
            .defaults
            .into_iter()
            .filter(|t| ["uv", "poetry", "yarn", "pnpm"].contains(&t.tool.as_str()))
            .map(|t| (t.tool, t.version, t.source))
            .collect()
    }

    fn pin(tool: &str, version: &str, source: &str) -> (String, String, String) {
        (tool.into(), version.into(), source.into())
    }

    #[test]
    fn a_lockfile_brings_its_package_manager_unless_something_pins_one() {
        let v1 = "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n";
        assert_eq!(
            managers(&[
                ("shim/pyproject.toml", "[project]\nname = \"x\"\n"),
                ("shim/uv.lock", "version = 1\n"),
                ("api/pyproject.toml", "[tool.poetry]\nname = \"y\"\n"),
                ("web/package.json", "{}"),
                ("web/yarn.lock", v1),
            ]),
            [
                pin("poetry", "latest", "api/pyproject.toml"),
                pin("uv", "latest", "shim/uv.lock"),
                pin("yarn", "1", "web/yarn.lock"),
            ]
        );
        assert_eq!(
            managers(&[
                ("package.json", r#"{"packageManager":"pnpm@9.1.0"}"#),
                ("yarn.lock", v1),
                ("pnpm-lock.yaml", "lockfileVersion: 9.0\n"),
            ]),
            [],
            "package.json names the one it runs"
        );
        assert_eq!(
            managers(&[(".tool-versions", "uv 0.5.1\n"), ("uv.lock", "")]),
            [],
            "a pin wins"
        );
        assert_eq!(
            managers(&[
                ("package.json", "{}"),
                ("yarn.lock", "__metadata:\n  version: 8\n")
            ]),
            [pin("yarn", "latest", "yarn.lock")]
        );
    }

    #[test]
    fn a_listed_tree_reads_like_a_folder() {
        let files: Vec<String> = [
            "package.json",
            "shim/pyproject.toml",
            "shim/uv.lock",
            "README.md",
        ]
        .map(String::from)
        .to_vec();
        assert_eq!(read_paths(&files), ["package.json", "shim/pyproject.toml"]);
        let tree = Listed {
            texts: HashMap::from([
                (
                    "package.json".into(),
                    r#"{"packageManager":"pnpm@9.1.0"}"#.into(),
                ),
                (
                    "shim/pyproject.toml".into(),
                    "[project]\nname = \"x\"\n".into(),
                ),
            ]),
            files,
        };
        let d = detect_tree(&tree);
        let presets: Vec<&str> = d.presets.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(presets, ["npm", "pypi"]);
        assert_eq!(d.tools[0].tool, "pnpm");
        let defaults: Vec<(&str, &str)> = d
            .defaults
            .iter()
            .map(|t| (t.tool.as_str(), t.source.as_str()))
            .collect();
        assert_eq!(
            defaults,
            [
                ("uv", "shim/uv.lock"),
                ("node", "package.json"),
                ("python", "shim/pyproject.toml")
            ]
        );
    }

    /// The Terraform or OpenTofu default and preset detection proposes for `files`.
    fn infra(files: &[(&str, &str)]) -> (Vec<(String, String, String)>, Vec<String>) {
        let d = tempfile::tempdir().unwrap();
        for (f, s) in files {
            let p = d.path().join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, s).unwrap();
        }
        let r = detect(d.path());
        let tools = r
            .defaults
            .into_iter()
            .chain(r.tools)
            .filter(|t| t.tool == "terraform" || t.tool == "opentofu")
            .map(|t| (t.tool, t.version, t.source))
            .collect();
        let presets = r
            .presets
            .into_iter()
            .map(|(p, _)| p)
            .filter(|p| p == "terraform" || p == "opentofu")
            .collect();
        (tools, presets)
    }

    #[test]
    fn the_lock_file_names_terraform_or_opentofu() {
        let lock = |registry: &str| {
            format!("provider \"{registry}/hashicorp/random\" {{\n  version = \"3.6.3\"\n}}\n")
        };
        let tf = lock("registry.terraform.io");
        assert_eq!(
            infra(&[("infra/.terraform.lock.hcl", &tf), ("infra/main.tf", "")]),
            (
                vec![pin("terraform", "latest", "infra/.terraform.lock.hcl")],
                vec!["terraform".into()]
            )
        );
        let tofu = lock("registry.opentofu.org");
        assert_eq!(
            infra(&[(".terraform.lock.hcl", &tofu)]),
            (
                vec![pin("opentofu", "latest", ".terraform.lock.hcl")],
                vec!["opentofu".into()]
            )
        );
        assert_eq!(infra(&[("main.tofu", "")]).1, ["opentofu"]);
    }

    #[test]
    fn an_exact_required_version_or_a_version_file_sets_the_version() {
        let versions = |c: &str| format!("terraform {{\n  required_version = \"{c}\"\n}}\n");
        for (constraint, version) in [
            ("1.9.5", "1.9.5"),
            ("= 1.9.5", "1.9.5"),
            ("~> 1.9.0", "1.9"),
            ("~> 1.9", "latest"),
            (">= 1.5, < 2.0", "latest"),
        ] {
            let (tools, _) = infra(&[("versions.tf", &versions(constraint))]);
            assert_eq!(tools[0].1, version, "{constraint}");
        }
        // OpenTofu's version file, which mise doesn't read, is the default's version.
        let (tools, _) = infra(&[(".opentofu-version", "1.10.6\n"), ("main.tf", "")]);
        assert_eq!(tools, [pin("opentofu", "1.10.6", ".opentofu-version")]);
        // A version file mise reads pins, and no default competes with it.
        let (tools, presets) = infra(&[(".terraform-version", "1.9.8\n"), ("main.tf", "")]);
        assert_eq!(tools, [pin("terraform", "1.9.8", ".terraform-version")]);
        assert_eq!(presets, ["terraform"]);
        // Text that isn't a version stays out of the proposal.
        let (tools, _) = infra(&[(".opentofu-version", "\u{1b}[2J1.0\n")]);
        assert_eq!(tools, [pin("opentofu", "latest", ".opentofu-version")]);
    }
}
