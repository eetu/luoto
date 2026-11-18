#!/usr/bin/env bash
# Run, out of sight, at the start of a cast: ~/demo with three small repos and a clone of luoto, and the canned model
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

# luoto itself without the change the hello cast makes: this checkout as committed, its splash
# (cli/src/splash.rs) replaced by one that draws nothing (splash-stub.rs). The same version as
# the checkout, so the `luoto setup` the cast runs from this clone leaves luoto-dev's vault as
# it is. Built here, into a target folder of the casts' own, so the cast's last build is only
# what the change touched.
repo=$(cd "$here/../.." && pwd)
git clone -q "$repo" "$CAST/luoto"
cd "$CAST/luoto"
git remote remove origin
# The env's prompt names the branch.
git branch -qM main
cp "$here/splash-stub.rs" cli/src/splash.rs
git -c user.name=cast -c user.email=cast@example.com commit -qam "no splash"
# The UI's bundle is built, not committed, and the binary embeds its folder.
mkdir -p frontend/dist
CARGO_TARGET_DIR="${LUOTO_CAST_TARGET:?where the casts build}" cargo build --quiet -p luoto

nohup python3 -I "$here/canned.py" 18000 >/dev/null 2>&1 &
echo $! >"$CAST/.luoto-cast"
