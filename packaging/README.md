# Packaging (maintainers)

Maintainer-only. Release assets come from `.github/workflows/release.yaml`; `render.sh` turns
`homebrew/luoto.rb.tmpl` and `scoop/luoto.json.tmpl` into the formula and manifest.

## One-time setup

1. Create public repos `eetu/homebrew-luoto` and `eetu/scoop-luoto`, each with a `main` branch
   (an initial commit with a README is enough). The workflow writes `Formula/luoto.rb` and
   `bucket/luoto.json`.
2. Create a fine-grained personal access token limited to those two repos with
   **Contents: read and write** (nothing else). Store it in the luoto repo as secret `TAP_TOKEN`.
3. To enable the publish job, set the luoto repo variable `PUBLISH_PACKAGES` to `true`.
4. Images publish to `ghcr.io/eetu/luoto-*`. After the first push, set each package's
   visibility to public (GitHub: Packages > package settings) so users can pull anonymously.

## Cutting a release

1. Work for a release collects on a branch named for it (`0.2.0`), whose pull request is
   squash-merged: main has one commit per release. On that branch, bump `version` in the root
   `Cargo.toml` and date the version's heading in `CHANGELOG.md` (`## X.Y.Z (YYYY-MM-DD)`).
   After the merge, `git tag vX.Y.Z` on main and `git push --tags`. The first job fails if the
   tag and `Cargo.toml` disagree or `CHANGELOG.md` has no section for the version; that
   section becomes the release notes. A tag with a `-` suffix (`v0.2.0-beta.1`) becomes a
   GitHub prerelease, with its base version's notes, and isn't published to the tap or bucket.
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

## Installing

Users follow [Install](../README.md#install) in the README.

## Private repos

The repos are public. If they ever go private, Homebrew downloads of release assets need a
token, which is impractical for users; keep the release repo public.
