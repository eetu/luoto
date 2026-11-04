# Packaging

Release assets come from `.github/workflows/release.yaml`; `render.sh` turns
`homebrew/luoto.rb.tmpl` and `scoop/luoto.json.tmpl` into the formula and manifest.

## One-time setup

1. Create public repos `eetu/homebrew-luoto` and `eetu/scoop-luoto`, each with a `main` branch
   (an initial commit with a README is enough). The workflow writes `Formula/luoto.rb` and
   `bucket/luoto.json`.
2. Create a fine-grained personal access token limited to those two repos with
   **Contents: read and write** (nothing else). Store it in the luoto repo as secret `TAP_TOKEN`.
3. To enable the publish job, set the luoto repo variable `PUBLISH_PACKAGES` to `true`.
4. Images publish to `ghcr.io/eetu/luoto-*`. After the first push, set each package's
   visibility to public (GitHub: Packages > package settings) so friends can pull anonymously.

## Cutting a release

1. Bump `version` in the root `Cargo.toml`, commit, then `git tag vX.Y.Z && git push --tags`.
   The first job fails if the tag and `Cargo.toml` disagree. A tag with a `-` suffix
   (`v0.2.0-beta.1`) becomes a GitHub prerelease.
2. The workflow builds the UI, five binaries, four multi-arch images (native arm64 runner),
   and creates the release with archives, `SHA256SUMS` and `images.json`.
3. Check:
   - release has five archives, `SHA256SUMS`, `images.json`;
   - `images.json` lists four `ghcr.io/eetu/luoto-*@sha256:` refs;
   - `gh attestation verify <archive> --repo eetu/luoto`;
   - `cosign verify --certificate-oidc-issuer https://token.actions.githubusercontent.com
     --certificate-identity-regexp '^https://github.com/eetu/luoto/' <image@digest>`;
   - tap and bucket got a commit (when publishing is enabled).

## First manual release (no publish job)

Leave `PUBLISH_PACKAGES` unset and tag. Then, from a checkout:

```sh
gh release download vX.Y.Z -R eetu/luoto --pattern SHA256SUMS
packaging/render.sh X.Y.Z SHA256SUMS out eetu/luoto
```

Inspect `out/luoto.rb` and `out/luoto.json`, copy them to `Formula/luoto.rb` in the tap and
`bucket/luoto.json` in the bucket, and push. Try `brew install --formula ./out/luoto.rb`
before pushing.

## Installing (friends)

luoto needs podman or Docker. Run `luoto setup` after installing.

**macOS**

```sh
brew tap eetu/luoto && brew install luoto
brew install podman   # or use Docker
```

**Linux**: Homebrew on Linux (same commands as macOS), or the tarball:

```sh
V=0.1.0 T=x86_64-unknown-linux-gnu   # or aarch64-unknown-linux-gnu
B=https://github.com/eetu/luoto/releases/download/v$V
curl -LO $B/luoto-$V-$T.tar.gz && curl -LO $B/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
tar xzf luoto-$V-$T.tar.gz && install luoto-$V-$T/luoto ~/.local/bin/
```

**Windows** (not yet verified end to end)

```powershell
scoop bucket add luoto https://github.com/eetu/scoop-luoto
scoop install luoto
```

## Private repos

The repos are public. If they ever go private, Homebrew downloads of release assets need a
token, which is impractical for friends; keep the release repo public.
