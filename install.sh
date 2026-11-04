#!/bin/sh
# Install luoto from a GitHub release: the build for this OS and CPU, checked against the
# release's SHA256SUMS and, when the GitHub CLI is logged in, its build provenance (that the
# release workflow of eetu/luoto built it).
#
#   curl -fsSL https://raw.githubusercontent.com/eetu/luoto/main/install.sh | sh
#
# Run it again (or `luoto upgrade`) to update. LUOTO_VERSION=0.1.0 picks a release (default:
# the latest), LUOTO_INSTALL_DIR the directory (default: ~/.local/bin). Nothing runs as root.
# Windows: use Scoop (see the README).
set -eu

repo=eetu/luoto
dir="${LUOTO_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf '%s\n' "$*" >&2; }
die() {
  say "luoto install: $*"
  exit 1
}

case "$(uname -s)" in
  Darwin) os=apple-darwin ;;
  Linux) os=unknown-linux-gnu ;;
  *) die "no build for $(uname -s); on Windows use Scoop (see the README)" ;;
esac
case "$(uname -m)" in
  arm64 | aarch64) arch=aarch64 ;;
  x86_64 | amd64) arch=x86_64 ;;
  *) die "no build for $(uname -m)" ;;
esac
target="$arch-$os"

if [ -n "${LUOTO_VERSION:-}" ]; then
  version="${LUOTO_VERSION#v}"
else
  # GitHub redirects the latest release to its tag's page.
  url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest") ||
    die "cannot reach GitHub"
  case "$url" in
    */tag/v*) version="${url##*/tag/v}" ;;
    *) die "no release published yet" ;;
  esac
fi
case "$version" in
  "" | *[!0-9A-Za-z.+-]*) die "unexpected version '$version'" ;;
esac
if [ "$("$dir/luoto" --version 2>/dev/null || true)" = "luoto $version" ]; then
  say "luoto $version is already installed in $dir"
  exit 0
fi

name="luoto-$version-$target"
base="https://github.com/$repo/releases/download/v$version"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

say "downloading luoto $version for $target"
curl -fsSL -o "$tmp/$name.tar.gz" "$base/$name.tar.gz" || die "no $target build in v$version"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS" || die "v$version has no SHA256SUMS"

want=$(awk -v f="$name.tar.gz" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")
if command -v sha256sum >/dev/null 2>&1; then
  got=$(sha256sum "$tmp/$name.tar.gz" | awk '{ print $1 }')
else
  got=$(shasum -a 256 "$tmp/$name.tar.gz" | awk '{ print $1 }')
fi
[ -n "$want" ] && [ "$want" = "$got" ] || die "checksum mismatch for $name.tar.gz"
say "checksum ok"

if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  gh attestation verify "$tmp/$name.tar.gz" --repo "$repo" >/dev/null 2>&1 ||
    die "build provenance check failed: not built by $repo's release workflow"
  say "build provenance ok"
else
  say "skipped the build provenance check (needs the GitHub CLI, logged in)"
fi

tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
mkdir -p "$dir"
# A rename replaces a running luoto safely (`luoto upgrade` runs this script).
install -m 755 "$tmp/$name/luoto" "$dir/.luoto.new"
mv -f "$dir/.luoto.new" "$dir/luoto"
say "installed luoto $version in $dir"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) say "add $dir to your PATH" ;;
esac
say "next: luoto setup"
