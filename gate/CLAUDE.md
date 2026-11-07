# gate

The only egress of an env. Runs as root just long enough to drop the default route podman
gives it through itself (the env network's `--route`), install iptables redirects and bind its
sockets, then drops to uid 65534 (`system.rs`).

- `proxy.rs` explicit proxy on gate:3128 (CONNECT → `mitm.rs` or an opaque tunnel for
  tunnel-mode rules; absolute-form HTTP; origin-form → `api.rs`, the in-sandbox API).
- `transparent.rs` catch-all on :15001 for TCP that bypassed the proxy; destination name from
  the fake-IP map (`dns.rs`) or SNI/Host. Never dials the client's chosen IP. `SSH-`
  connections pass through unread, only on a tunnel rule for their host and port (what
  `[credentials.ssh]` compiles); the vault signs the login.
- `handler.rs` per-request pipeline shared by every intake: one canonical path
  (`host::canonical_path`: dot and empty segments and backslashes refused, unreserved escapes
  decoded), matched and forwarded alike; upper-case methods only (`canonical_request`, which
  `/_sandbox/check` shares) → Host agreement → policy → `guards.rs`: push guard for GitHub,
  Azure DevOps and `[[credentials.git]]` hosts (granted repos, protected branches, tags, no
  deletes), GitHub GraphQL mutations, matched without case like the rules, and model API
  bodies asking for server tools (`body_denies`, read whole up to 32 MiB) → credential
  strip/inject over TLS only (`creds.rs`, vault client) → `upstream.rs` (resolve, vet every
  address, dial) → metered response + event. `body.rs` holds the body types (capped, metered, replayed prefix).
- `ctl.rs` unix socket; `state.rs` persists policy/CA/vault settings in the state volume so a
  restarted gate serves at once; secrets are never persisted.
- `test-hooks` feature (integration tests only): `LUOTO_TEST_RESOLVE` maps names to local
  test servers, bypasses the private-address check for those names and lets them get
  credentials over plain HTTP.
