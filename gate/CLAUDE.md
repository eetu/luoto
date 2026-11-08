# gate

The only egress of an env. Runs as root just long enough to drop the default route podman
gives it through itself (the env network's `--route`), install iptables redirects and bind its
sockets, then drops to uid 65534 (`system.rs`).

- `proxy.rs` explicit proxy on gate:3128 (CONNECT → `mitm.rs` or an opaque tunnel for
  tunnel-mode rules; absolute-form HTTP; origin-form → `api.rs`, the in-sandbox API).
- `transparent.rs` catch-all on :15001 for TCP that bypassed the proxy; destination name from
  the fake-IP map (`dns.rs`) or SNI/Host. Never dials the client's chosen IP. A connection
  whose name and port have a tunnel rule passes through unread before any byte is sniffed
  (any protocol, server-first ones and pinned TLS too; SSH under `[credentials.ssh]`, whose
  login the vault signs).
- `handler.rs` per-request pipeline shared by every intake: one canonical path
  (`host::canonical_path`: dot and empty segments and backslashes refused, unreserved escapes
  decoded), matched and forwarded alike; upper-case methods only (`canonical_request`, which
  `/_sandbox/check` shares) → Host agreement → policy → `guards.rs`: push guard for GitHub,
  Azure DevOps and `[[credentials.git]]` hosts (granted repos, protected branches, tags, no
  deletes), GitHub GraphQL mutations, matched without case like the rules, and model API
  bodies asking for server tools (`body_denies`, read whole up to 32 MiB) → credential
  strip/inject over TLS only (`creds.rs`, vault client) → `upstream.rs` (resolve, vet every
  address, dial) → metered response + event. `body.rs` holds the body types (capped,
  metered, replayed prefix).
- `imds.rs` for an env with an Azure identity, answers 169.254.169.254:80 `/metadata/…` from
  either intake before the policy: managed identity tokens for the granted audiences, as
  placeholders (the real token's header and claims, a signature that can't verify). The real
  token only goes out through the injections on Azure hosts.
- `limits.rs` what the sandbox can't exhaust: one cap on open client connections over every
  intake (beyond it refused, reported as `conn_limit` events), sized to the open-file limit it
  raises at start, and idle-based timeouts carried by each connection's `Activity` (response
  head, idle response, tunnel and websocket idle), which the allowing rule's `idle` replaces.
  `events.rs` queues at most 4096 lines for stdout and reports what it drops; `ca.rs` mints a
  cached leaf again after a day.
- `ctl.rs` unix socket; `state.rs` persists policy/CA/vault settings in the state volume so a
  restarted gate serves at once; secrets are never persisted.
- `test-hooks` feature (integration tests only): `LUOTO_TEST_RESOLVE` maps names to local
  test servers, bypasses the private-address check for those names and lets them get
  credentials over plain HTTP; `LUOTO_TEST_LIMITS` shrinks the limits;
  `LUOTO_TEST_TRANSPARENT=<listen>=<destination>` serves the transparent intake on a listener
  whose connections count as redirected from that destination (no iptables, also on macOS).
