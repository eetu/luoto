#!/bin/sh
# Assembles the published site in a folder (default: target/site): the page's own files and
# what it shows from the rest of the repo, so no binary is in git twice.
set -eu
cd "$(dirname "$0")/.."
out="${1:-target/site}"
mkdir -p "$out"
cp -R site/index.html site/style.css site/og.png site/fonts "$out/"
cp docs/casts/hello.gif \
  docs/screenshots/egress-blocked-light.png docs/screenshots/egress-blocked-dark.png \
  frontend/static/favicon.svg "$out/"
