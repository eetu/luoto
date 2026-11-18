#!/usr/bin/env bash
# Run, out of sight, before the hello cast's last command: `luoto setup` from the clone of luoto
# the cast changed (~/demo/luoto), a source build, so the luoto-dev instance. It builds the
# clone, so the command on screen starts at once, and prints a config folder for it
# (LUOTO_HOME): config.toml there is luoto-dev's own without its runtime, which makes that
# setup a first one, and luoto-dev's own config is never written.
#
# It refuses unless the clone's build is of the version the cast's luoto-dev is: a setup by
# another version recreates luoto-dev's vault, and every env's secrets go with it.
set -eu

CAST=$HOME/demo
home=$CAST/.first-setup
real=${XDG_CONFIG_HOME:-$HOME/.config}/luoto-dev/config.toml
bin=${LUOTO_CAST_BIN:?the luoto the cast records}

cd "$CAST/luoto"
cargo build --quiet -p luoto
ours=$("${CARGO_TARGET_DIR:?where the casts build}/debug/luoto" --version)
if ! "$bin" status -e luoto | grep -q '/luoto-dev/'; then
  echo "the cast's last scene sets up luoto-dev: record it with a source build" >&2
  exit 1
fi
if [ "$ours" != "$("$bin" --version)" ]; then
  echo "the clone builds $ours, not $("$bin" --version): its setup would recreate the vault" >&2
  exit 1
fi

# With its home folder there, setup has none to announce.
mkdir -p "$home/config/home"
grep -v '^runtime = ' "$real" >"$home/config/config.toml"
echo "$home"
