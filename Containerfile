# luoto runtime images, built from one Rust build stage:
#   luoto-gate   alpine + iptables (transparent redirects), static gate binary
#   luoto-vault  scratch + static vault binary
#   luoto-tools  busybox (to populate env tool volumes): sandbox helper, init.sh, briefing,
#                Mozilla CA bundle for images without a system store
# Build one with: podman build --target gate -t localhost/luoto-gate:dev .

# cargo-chef: the dependencies compile in a layer of their own, keyed by the manifests and the
# lockfile, so a change to luoto's own code recompiles only its crates. CI keeps that layer
# in GitHub's cache (ci.yaml); locally the runtime's layer cache does the same.
FROM docker.io/library/rust:1-alpine AS chef
# On the build stages (planner and build inherit it): their images are build cache, which
# `luoto prune` tells by this label; a source build's older than its current images go.
LABEL luoto.build=cache
RUN apk add --no-cache musl-dev gcc make perl
RUN cargo install cargo-chef --locked --version 0.1.78
WORKDIR /src

FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY shared shared
COPY gate gate
COPY vault vault
COPY tools tools
COPY cli cli
COPY integration integration
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS build
COPY --from=planner /src/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json -p luoto-gate -p luoto-vault -p luoto-tools
COPY Cargo.toml Cargo.lock ./
COPY shared shared
COPY gate gate
COPY vault vault
COPY tools tools
# The host CLI and the integration tests are workspace members, not part of these images.
COPY cli/Cargo.toml cli/Cargo.toml
COPY integration/Cargo.toml integration/Cargo.toml
RUN mkdir -p cli/src integration/src && echo "fn main() {}" > cli/src/main.rs && touch integration/src/lib.rs
RUN cargo build --release --locked -p luoto-gate -p luoto-vault -p luoto-tools && \
    mkdir -p /out && cp target/release/luoto-gate target/release/luoto-vault target/release/sandbox /out/

FROM docker.io/library/alpine:3.23 AS certs
LABEL luoto.build=cache
RUN apk add --no-cache ca-certificates

FROM docker.io/library/alpine:3.23 AS gate
RUN apk add --no-cache iptables
COPY --from=build /out/luoto-gate /usr/local/bin/luoto-gate
ENV LUOTO_RUN_AS=65534
ENTRYPOINT ["/usr/local/bin/luoto-gate"]
CMD ["run"]

FROM scratch AS vault
COPY --from=build /out/luoto-vault /luoto-vault
USER 65534:65534
ENTRYPOINT ["/luoto-vault"]
CMD ["run"]

FROM docker.io/library/busybox:1.36 AS tools
COPY --from=build /out/sandbox /dist/bin/sandbox
COPY --chmod=755 tools/assets/init.sh /dist/init.sh
COPY tools/assets/AGENTS.md /dist/AGENTS.md
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /dist/ca-bundle.base.pem
