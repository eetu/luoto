#!/usr/bin/env bash
# Fill the Homebrew and Scoop templates.
# Usage: render.sh VERSION SHA256SUMS OUTDIR OWNER/REPO
#   VERSION without the leading "v"; OWNER/REPO is the repository hosting the release.
set -euo pipefail

[ $# -eq 4 ] || { sed -n '2,4p' "$0"; exit 2; }
version=$1 sums=$2 out=$3 repo=$4
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$out"

sedargs=(-e "s|@VERSION@|$version|g" -e "s|@REPO@|$repo|g")
for target in aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-gnu \
              x86_64-unknown-linux-gnu x86_64-pc-windows-msvc; do
  ext=tar.gz; [ "$target" = x86_64-pc-windows-msvc ] && ext=zip
  sha=$(awk -v f="luoto-$version-$target.$ext" '$2 == f || $2 == "*" f {print $1}' "$sums")
  [[ $sha =~ ^[0-9a-f]{64}$ ]] || { echo "no sha256 for $target in $sums" >&2; exit 1; }
  sedargs+=(-e "s|@SHA_$target@|$sha|g")
done

sed "${sedargs[@]}" "$here/homebrew/luoto.rb.tmpl" > "$out/luoto.rb"
sed "${sedargs[@]}" "$here/scoop/luoto.json.tmpl" > "$out/luoto.json"
if grep -n '@[A-Za-z_-]*@' "$out/luoto.rb" "$out/luoto.json"; then
  echo "unfilled placeholders" >&2; exit 1
fi
