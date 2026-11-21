//! Pull-on-stop end to end, against the container runtime this build's instance uses
//! (`luoto-dev`), with its images built (`just images`): `just e2e`. It makes one env there,
//! named `e2e-pull-<pid>`, and removes it again.
//!
//! What only a real stop shows: the env's files read from its stopped volume by the tools
//! image's own `tar` and `find` (what no pull takes left out at any depth, the files to
//! write read again by name), written under the three-way rule with what is held back
//! named, `luoto down`'s exit code, a reviewed pull of the rest, and `luoto prune --envs`
//! reading a stopped env's volume before it removes it.

#![cfg(unix)]

use std::path::Path;
use std::process::{Command, Output, Stdio};

const LUOTO: &str = env!("CARGO_BIN_EXE_luoto");

fn luoto(args: &[&str]) -> Output {
    Command::new(LUOTO)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// stdout and stderr of a luoto that must have exited with `code`.
fn said(args: &[&str], code: i32) -> String {
    let out = luoto(args);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.status.code(), Some(code), "luoto {args:?}:\n{text}");
    text
}

fn git(dir: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
        .args(args)
        .stdout(Stdio::null())
        .status()
        .unwrap()
        .success();
    assert!(ok, "git {args:?}");
}

/// Removes the env however the test ends.
struct Env(String);

impl Drop for Env {
    fn drop(&mut self) {
        let _ = luoto(&["rm", "-e", &self.0, "--yes"]);
    }
}

#[test]
#[ignore = "needs a container runtime and luoto's images; run with `just e2e`"]
fn an_envs_changes_land_when_it_stops_and_what_runs_by_itself_waits() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().canonicalize().unwrap();
    let read = |p: &str| std::fs::read_to_string(d.join(p)).unwrap_or_default();
    git(&d, &["init", "-q"]);
    std::fs::create_dir(d.join("src")).unwrap();
    std::fs::write(d.join("a.txt"), "1\n").unwrap();
    std::fs::write(d.join("yours.txt"), "1\n").unwrap();
    std::fs::write(d.join("src/main.rs"), "fn main() {}\n").unwrap();
    std::fs::write(d.join(".gitignore"), "dist/\n.env\n").unwrap();
    git(&d, &["add", "-A"]);
    git(&d, &["commit", "-qm", "init"]);

    let env = Env(format!("e2e-pull-{}", std::process::id()));
    let name = env.0.as_str();
    let folder = d.display().to_string();
    said(&["init", &folder, "--name", name, "--yes"], 0);
    said(&["pull", "--on-stop", "on", "-e", name], 0);

    // The env's work, what it may not land unreviewed, and a file changed on both sides.
    let work = r#"set -e
cd /workspace
echo 2 > a.txt
echo 2 > yours.txt
mkdir -p src/deep dist node_modules/x src/deep/node_modules/y
echo 'pub fn new() {}' > src/deep/new.rs
echo built > dist/app.js
echo 1 > node_modules/x/index.js
echo 1 > src/deep/node_modules/y/index.js
echo 'dist/' > .gitignore
echo 'presets = []' > luoto.toml
printf '[package]\nname = "x"\n' > Cargo.toml
printf '#!/bin/sh\n' > run.sh
chmod +x run.sh
ln -s /etc/passwd leak
"#;
    said(&["shell", "-e", name, "--", "sh", "-c", work], 0);
    std::fs::write(d.join("yours.txt"), "mine\n").unwrap();

    // Something was left for a review: the stop says so by its exit code.
    let report = said(&["down", "-e", name], 75);
    assert_eq!(read("a.txt"), "2\n", "{report}");
    assert_eq!(read("src/deep/new.rs"), "pub fn new() {}\n", "{report}");
    assert_eq!(read("yours.txt"), "mine\n", "a conflict keeps yours");
    assert_eq!(read(".gitignore"), "dist/\n.env\n", "{report}");
    for held in [
        "luoto.toml",
        "Cargo.toml",
        "run.sh",
        "leak",
        "dist",
        "node_modules",
    ] {
        assert!(!d.join(held).exists(), "{held} landed:\n{report}");
    }
    for line in [
        "wrote:",
        "held back for your review:",
        ".gitignore — decides what later copies into an env leave out",
        "luoto.toml — luoto applies its settings",
        "Cargo.toml — names build scripts",
        "run.sh — becomes executable",
        "changed here and in the env (yours kept):",
        "refused:",
        "never copied, so only in the env:",
        "1 file(s) your .gitignore ignores stay in the env",
        "then `luoto pull -e",
    ] {
        assert!(report.contains(line), "no `{line}` in:\n{report}");
    }
    // Left out at any depth, by the tools image's own tar and find.
    assert!(report.contains("  node_modules\n") && report.contains("  src/deep/node_modules\n"));
    assert!(!report.contains("index.js"), "{report}");

    // A stopped env's pull is done: a second stop has nothing to say.
    let again = said(&["down", "-e", name], 0);
    assert!(!again.contains("pulled"), "{again}");

    // The rest comes with a reviewed pull, which asks the running env.
    let stopped = said(&["pull", "-e", name, "--yes"], 1);
    assert!(stopped.contains("is not running"), "{stopped}");
    said(&["up", "-e", name], 0);
    let listed = said(
        &[
            "pull",
            "-e",
            name,
            "--include-risky",
            "--overwrite",
            "--yes",
        ],
        0,
    );
    assert!(listed.contains("refused  leak"), "{listed}");
    assert_eq!(read("yours.txt"), "2\n");
    assert_eq!(read("luoto.toml"), "presets = []\n");
    assert_eq!(read(".gitignore"), "dist/\n");
    // With every file in the folder, the stop leaves nothing out but what no pull takes.
    let clean = said(&["down", "-e", name], 75);
    assert!(
        clean.contains("refused:") && clean.contains("leak"),
        "{clean}"
    );
    said(&["up", "-e", name], 0);
    said(&["shell", "-e", name, "--", "rm", "/workspace/leak"], 0);
    let clean = said(&["down", "-e", name], 0);
    assert!(clean.contains("pulled 0 file(s)"), "{clean}");

    // `prune --envs` reads the stopped env's volume: it stays for what no pull takes, and
    // goes when told to take that too.
    let scoped = ["prune", "--envs", "--older-than", "0d", "--match", name];
    let kept = said(&[&scoped[..], &["--yes"]].concat(), 0);
    assert!(kept.contains("stay for the work they hold"), "{kept}");
    assert!(
        kept.contains("never copied") && kept.contains("node_modules"),
        "{kept}"
    );
    let gone = said(&[&scoped[..], &["--with-work", "--yes"]].concat(), 0);
    assert!(gone.contains("removed 1 env(s)"), "{gone}");
    assert!(!said(&["list"], 0).contains(name));
}
