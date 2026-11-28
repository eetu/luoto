# gate

The only egress of an env. Runs as root just long enough to drop the default route podman
gives it through itself (the env network's `--route`), install iptables redirects and bind its
sockets, then drops to uid 65534 (`system.rs`).

- `proxy.rs` explicit proxy on gate:3128 (CONNECT → `mitm.rs` or an opaque tunnel for
  tunnel-mode rules; absolute-form HTTP; origin-form → `api.rs`, the in-sandbox API).
- `transparent.rs` catch-all on :15001 for TCP that bypassed the proxy; destination name from
  the fake-IP map (`dns.rs`) or SNI/Host. Never dials the address the client connected to; an
  IP named as the host (no SNI, `Host: <ip>`) is dialed only where the policy allows it. A connection
  whose name and port have a tunnel rule passes through unread before any byte is sniffed
  (any protocol, server-first ones and pinned TLS too; SSH under `[credentials.ssh]`, whose
  login the vault signs); for a client that connected to an address itself (not a fake one),
  a tunnel rule naming that address does the same, as CONNECT to it would.
- `handler.rs` per-request pipeline shared by every intake: one canonical path
  (`host::canonical_path`: dot and empty segments and backslashes refused, unreserved escapes
  decoded), matched and forwarded alike; upper-case methods only (`canonical_request`, which
  `/_sandbox/check` shares) → Host agreement → policy → `guards.rs`: push guard for GitHub,
  Azure DevOps and `[[credentials.git]]` hosts (granted repos, protected branches, tags, no
  deletes, no signed pushes; each command exactly `old new ref`), GitHub GraphQL mutations,
  matched without case like the rules, and model API
  bodies asking for server tools (`body_denies`, read whole up to 32 MiB) → credential
  strip on the host, inject for the injection's paths and methods, over TLS only (`creds.rs`,
  vault client) → `upstream.rs` (resolve, vet every
  address, dial) → metered response + event. `body.rs` holds the body types (capped,
  metered, replayed prefix). `screen.rs` keeps a credential the gate added from coming back:
  a JSON response read whole and the echo taken out, any other screened as it streams
  (trailers too), holding back only a frame's end of 4+ bytes that starts a credential.
- Intercepted TLS takes HTTP/2 first (ALPN `h2, http/1.1`): `serve_http2` runs each stream as
  one request with an `Activity` of its own, so its idle limits and the rule's `idle` are its
  own; the connection waits while a stream is open, unless one sits past its limit waiting for
  the client to make room (`ConnCtx::stuck_stream`: hyper reads a body, where the stream's own
  limit is kept, only once there is room). Request trailers lose the client's credentials as
  its headers do. Upstream offers HTTP/2 only for a client
  that speaks it: one HTTP/2 connection shared by the client's streams, else at most
  `H1_UPSTREAMS` HTTP/1.1 ones (`handler::Upstreams`). A gRPC request (`application/grpc*`)
  gets `tunnel_idle`, and a refusal or failure as `grpc-status` (`respond::grpc`). A client
  offering no protocol the gate speaks is a `protocol_not_spoken` event; h2c is not served.
- `redirects.rs` keeps the permits a redirect opens: a GET or HEAD whose response, where
  `Policy::redirect_targets` names hosts, redirects to one of them lets that exact URL (scheme,
  host, port, canonical path, the query compared pair by pair with each piece decoded)
  through for GET and HEAD for ten minutes, checked before the policy (explicit denies still
  refuse it), with the client's auth headers and cookies removed. Memory only; applying a
  policy drops them, and a response to a request begun under the old one grants none.
- `imds.rs` for an env with an Azure identity, answers 169.254.169.254:80 `/metadata/…` from
  either intake before the policy: managed identity tokens for the granted audiences, as
  placeholders (the real token's header and the claims tools read, a signature that can't
  verify). The real token only goes out through the injections on Azure hosts.
- `limits.rs` what the sandbox can't exhaust: one cap on open client connections over every
  intake (beyond it refused, reported as `conn_limit` events), sized to the open-file limit it
  raises at start, and idle-based timeouts carried by each connection's `Activity` (response
  head, idle response, tunnel and websocket idle), which the allowing rule's `idle` replaces.
  `events.rs` queues at most 4096 lines for stdout and reports what it drops; `ca.rs` mints a
  cached leaf again after a day. With `LUOTO_EVENTS_FILE` (Apple, whose container logs nothing
  caps) events go to that file instead, turned over to `<file>.1` at half of
  `LUOTO_EVENTS_MB` (`eventlog.rs`; `luoto-gate events` prints and follows the pair), and
  stderr stops after 1 MiB a start.
- With `LUOTO_TUN_SOCKET` (a dev without a network card), `system::tun_link` creates tun0
  (169.254.1.1, peer 169.254.1.2) and binds that socket as root before any listener; after the
  drop a thread runs `luoto_shared::tun::serve`, and the redirects apply to tun0 unchanged.
  Only IPv4 from 169.254.1.2 reaches tun0 (the pump checks, an INPUT rule backs it), and the
  gate refuses to start with forwarding on.
- `creds.rs` asks the vault over HTTP on the env's unix socket (`LUOTO_VAULT_SOCKET`, by
  default `luoto_shared::VAULT_SOCKET`) with the env's token; a missing or refusing socket is
  an unbound env. With `LUOTO_VAULT_UPLINK` (Apple) `uplink.rs` serves that socket itself,
  pairing each connection with an idle link the host opened to the uplink socket (both bound
  as root before the drop); with none within 8 s the call fails closed. With `LUOTO_HOST_DIAL`
  (Apple) `hostdial.rs` dials an address an `allow_private` rule allows, private or
  public, since the Mac may route either over a VPN (`host::leaves_host`; not `private_only`) over a link the host opened to that socket: one
  line `dial <addr>`, one answer (`ok`, `refused` → dial it here, `failed`); no link in 8 s
  names the watcher.
- `ctl.rs` unix socket; `state.rs` persists policy/CA/vault settings in the state volume so a
  restarted gate serves at once; secrets are never persisted.
- `test-hooks` feature (integration tests only): `LUOTO_TEST_RESOLVE` maps names to local
  test servers, bypasses the private-address check for those names and lets them get
  credentials over plain HTTP; `LUOTO_TEST_LIMITS` shrinks the limits;
  `LUOTO_TEST_TRANSPARENT=<listen>=<destination>` serves the transparent intake on a listener
  whose connections count as redirected from that destination (no iptables, also on macOS).
