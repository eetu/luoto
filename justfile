# luoto task runner. `just` with no args lists recipes.

yarn := "node " + (justfile_directory() / "frontend" / `awk '/^yarnPath:/{print $2}' frontend/.yarnrc.yml`)
# macOS and Windows: luoto's own VM (`luoto setup` creates it).
target := env_var_or_default("CARGO_TARGET_DIR", justfile_directory() / "target")
runtime := env_var_or_default("LUOTO_RUNTIME", if os() == "linux" { "podman" } else { "podman --connection luoto" })

default:
    @just --list

# Install frontend deps.
install:
    cd frontend && {{yarn}} install

# Build the UI bundle (embedded into the luoto binary).
ui-build:
    cd frontend && {{yarn}} build

# Build the UI, then the whole Rust workspace (release).
build: ui-build
    cargo build --release --workspace

# Install the luoto CLI from this checkout.
install-cli: ui-build
    cargo install --path cli --locked

# A source build is the `luoto-dev` instance: its own config, vault and container names, beside
# an installed release in the same VM. Debug builds read the UI from frontend/dist.
# Link ~/.local/bin/luoto-dev to this checkout's debug build, so it runs the latest build.
link-dev:
    cargo build -p luoto
    mkdir -p ~/.local/bin
    ln -sfn "{{target}}/debug/luoto" ~/.local/bin/luoto-dev

# Build the gate, vault, tools and base images where luoto runs them.
images:
    {{runtime}} build -f Containerfile --target gate -t localhost/luoto-gate:dev .
    {{runtime}} build -f Containerfile --target vault -t localhost/luoto-vault:dev .
    {{runtime}} build -f Containerfile --target tools -t localhost/luoto-tools:dev .
    {{runtime}} build -f image/Containerfile -t localhost/luoto-base:dev image

# UI development: the API on :7878 plus Vite with hot reload on :5173.
dev:
    #!/usr/bin/env bash
    set -euo pipefail
    pids=""
    cleanup() {
        trap - INT TERM EXIT
        for p in $pids; do
            pkill -P "$p" 2>/dev/null || true
            kill "$p" 2>/dev/null || true
        done
    }
    trap cleanup INT TERM EXIT
    cargo run -p luoto -- ui --no-open --port 7878 &
    pids="$pids $!"
    ( cd frontend && exec {{yarn}} dev ) &
    pids="$pids $!"
    wait

lint:
    cd frontend && {{yarn}} lint
    cargo clippy --workspace --all-targets -- -D warnings

format:
    cd frontend && {{yarn}} format
    cargo fmt --all -- --check

test:
    cargo test --workspace

# Generate the UI's TypeScript types from the API's Rust types (`cargo test` checks them).
types:
    LUOTO_WRITE_TYPES=1 cargo test -p luoto --test api_types

# Gate + vault integration tests (spawned binaries, local test upstreams).
it:
    cargo test -p luoto-integration -- --ignored --test-threads=1

# UI tests: the built SPA against fixtures of a real API (Playwright, headless Chromium).
test-ui:
    cd frontend && {{yarn}} test:ui

# README screenshots from a real env and `luoto ui` (needs the runtime; leaves nothing behind).
# The env is `demo` in a throwaway LUOTO_HOME, run by the debug build (the `luoto-dev` instance);
# it refuses to run if a `luoto-dev-demo` exists, so its cleanup can't touch an env of yours. The
# dev vault is shared with your other dev envs: the vault shot is skipped unless it holds only
# the demo's dummy credential, which stays in its memory until `luoto-dev vault lock`.
shots:
    #!/usr/bin/env bash
    set -euo pipefail
    rt="{{runtime}}"
    if $rt container inspect luoto-dev-demo >/dev/null 2>&1; then
        echo "a luoto-dev-demo container exists; remove that env first" >&2
        exit 1
    fi
    cargo build -p luoto
    luoto="$PWD/target/debug/luoto"
    real_config="$HOME/.config/luoto-dev"
    [ -f "$real_config/config.toml" ] || real_config="$HOME/.config/luoto"
    [ -n "${LUOTO_HOME:-}" ] && real_config="$LUOTO_HOME/config"
    export LUOTO_HOME="$(mktemp -d)"
    # The runtime settings (luoto's VM, gVisor) come from your setup; nothing else does.
    mkdir -p "$LUOTO_HOME/config"
    cp "$real_config/config.toml" "$LUOTO_HOME/config/" 2>/dev/null || true
    cleanup() {
        kill "${ui:-}" 2>/dev/null || true
        "$luoto" rm -e demo --yes >/dev/null 2>&1 || true
        for v in $($rt volume ls -q | grep '^luoto-dev-demo-' || true); do $rt volume rm "$v" >/dev/null; done
        rm -rf "$LUOTO_HOME"
    }
    trap cleanup EXIT
    # A dummy credential for the vault scene: the gate injects it on httpbin.org.
    export LUOTO_DEMO_TOKEN=demo-not-a-secret
    "$luoto" init "$LUOTO_HOME/demo" --yes --no-up
    printf '\n[credentials.custom.demo]\nhost = "httpbin.org"\nsecret = "env:LUOTO_DEMO_TOKEN"\n' \
        >>"$LUOTO_HOME/config/envs/demo.toml"
    "$luoto" up -e demo
    "$luoto" ui --port 7900 --no-open >"$LUOTO_HOME/ui.log" 2>&1 &
    ui=$!
    for _ in $(seq 60); do grep -q 'token=' "$LUOTO_HOME/ui.log" && break; sleep 0.5; done
    export LUOTO_UI_URL="$(grep -o 'http://[^ ]*#token=[0-9a-f]*' "$LUOTO_HOME/ui.log" | head -1)"
    export LUOTO_BIN="$luoto" LUOTO_SHOT_ENV=demo
    mkdir -p docs/screenshots
    cd frontend && {{yarn}} shots
