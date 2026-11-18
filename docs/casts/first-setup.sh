#!/usr/bin/env bash
# Run by docs/casts/bin/luoto before a cast's `luoto setup`, which is the build of the clone of
# luoto the hello cast changes (~/demo/luoto): a source build, so the luoto-dev instance. It
# prints a new config folder for that setup (LUOTO_HOME): config.toml there is luoto-dev's own
# without its runtime, which makes the setup a first one, and luoto-dev's own config is never
# written.
#
# It refuses unless the clone's build is of the version that made luoto-dev's vault: a setup by
# another version recreates the vault, and every env's secrets go with it.
set -eu

CAST=$HOME/demo
home=$CAST/.first-setup
real=${XDG_CONFIG_HOME:-$HOME/.config}/luoto-dev/config.toml
[ -e "$CAST/.luoto-cast" ] || { echo "$CAST is not a cast's folder" >&2; exit 1; }

ours=$("${CARGO_TARGET_DIR:?where the casts build}/debug/luoto" --version | awk '{print $2}')
rt=${LUOTO_RUNTIME:-$(sed -n 's/^runtime = "\(.*\)"$/\1/p' "$real")}
vault=$("${rt:-podman}" inspect luoto-dev-vault 2>/dev/null |
  grep -o '"luoto\.version"[ ]*:[ ]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
if [ "$ours" != "$vault" ]; then
  echo "the clone builds luoto $ours and luoto-dev's vault is of ${vault:-no version read}:" \
    "its setup would recreate the vault" >&2
  exit 1
fi

rm -rf "$home"
# With its home folder there, setup has none to announce.
mkdir -p "$home/config/home"
grep -v '^runtime = ' "$real" >"$home/config/config.toml"
echo "$home"
