// Hand-mirrored from the Rust structs the API serializes (luoto-shared + cli/src/ui/api.rs).

export type Verdict = "allow" | "deny";
export type AccessLevel = "read" | "write";
export type Access = AccessLevel | string[];
export type Mode = "inspect" | "tunnel";

/** A toolchain version a project file pins (`node 22` from `.node-version`). */
export type ToolPin = { tool: string; version: string; source: string };

/** What creating an env from these choices would produce (`POST /api/detect`). */
export type Proposal = {
  name: string;
  /** The folder is missing (created with the env) or empty: nothing to detect. */
  new_folder: boolean;
  presets: { name: string; reason: string | null }[];
  tools: ToolPin[];
  /** The folder's luoto.toml as `[label, value]` lines; creating the env accepts it. */
  project: [string, string][] | null;
  /** sha256 of that luoto.toml; `createEnv` sends it back so only this text is accepted. */
  project_sha: string | null;
  project_error: string | null;
};

/** An env's standing with its project's luoto.toml (`GET /api/envs/{name}/project`). */
export type ProjectStatus = {
  state: "none" | "accepted" | "changed" | "new" | "declined" | "invalid" | "removed";
  accepted: [string, string][];
  current: [string, string][];
  diff: string[];
  error: string | null;
  needs: string[];
  /** sha256 of the current text; accepting sends it back so only this text applies. */
  sha: string | null;
};

export type LuotoEvent = {
  seq: number;
  run: string;
  ts?: string;
  source?: "gate" | "vault";
  env: string;
  kind?:
    | "dns"
    | "http"
    | "tunnel"
    | "direct"
    | "tls_reject"
    | "request"
    | "resolve"
    | "creds"
    | "lifecycle";
  intake?: "proxy" | "transparent" | "dns";
  verdict?: Verdict;
  method?: string;
  host?: string;
  port?: number;
  path?: string;
  rule?: string;
  reason?: string;
  message?: string;
  status?: number;
  bytes_up?: number;
  bytes_down?: number;
  ms?: number;
  request_id?: number;
  binding?: string;
};

export type HostSummary = {
  host: string;
  allowed: number;
  denied: number;
  dns_only: boolean;
  methods: string[];
  ports: number[];
  intakes: string[];
  top_paths: [string, number][];
  last_reason?: string;
  last_message?: string;
  last_rule?: string;
  bytes_up: number;
  bytes_down: number;
  first_seen?: string;
  last_seen?: string;
  wants_write: boolean;
  tls_rejected: boolean;
};

export type Rule = {
  id?: string;
  host: string;
  port?: number;
  access?: Access;
  paths?: string[];
  expires?: string;
  mode?: Mode;
  ws?: boolean;
  max_body?: number;
  allow_private?: boolean;
  note?: string;
};

export type CompiledRule = Rule & { id: string; origin: string };

export type AccessRequest = {
  id: number;
  host: string;
  access: AccessLevel;
  paths?: string[];
  reason: string;
  status: "pending" | "approved" | "rejected";
  created: string;
  resolved?: string;
  note?: string;
};

export type EnvRow = {
  name: string;
  dev: string;
  gate: string;
  image: string;
  presets: string[];
  agents: string[];
  ports: number[];
  dir?: string | null;
  pending: number;
  denied_recent: number;
  error?: string | null;
};

export type VaultStatus = {
  version: string;
  started: string;
  locked: boolean;
  loaded_refs: string[];
  envs: { env: string; bindings: string[]; missing: string[] }[];
};

export type Overview = {
  runtime: string;
  envs: EnvRow[];
  vault: VaultStatus | null;
};

export type GateStatus = {
  env: string;
  version: string;
  run: string;
  started: string;
  rules: number;
  ca_installed: boolean;
  vault_configured: boolean;
  pending_requests: number;
  last_seq: number;
};

export type EnvDetail = {
  name: string;
  path: string;
  rules: CompiledRule[];
  injections: { host: string; binding: string }[];
  denies: number;
  warnings: string[];
  dev: string;
  gate: string;
  gate_status: GateStatus | null;
  credentials: string[];
  missing_secrets: string[];
  sandbox_secrets: string[];
};

export type Meta = {
  presets: { name: string; description: string; hosts: string[] }[];
  agents: { name: string; description: string; providers: string[] }[];
  providers: {
    name: string;
    description: string;
    host: string;
    kinds: string[];
  }[];
};

export type RuntimeInfo = {
  name: string;
  version: [number, number, number] | null;
  version_ok: boolean;
  reachable: boolean;
  detail: string;
};

export type SetupInfo = {
  detection: {
    os: string;
    arch: string;
    distro: string | null;
    cpus: number;
    runtimes: RuntimeInfo[];
    package_manager: string | null;
    wsl: string | null;
    companions: [string, boolean][];
  };
  recommendation: {
    summary: string;
    reasons: string[];
    install: string[] | null;
    notes: string[];
  };
  images_ok: boolean;
};

export type PullPlan = {
  dir: string;
  entries: {
    path: string;
    change: string;
    size: number;
    executable: boolean;
    risky: string | null;
  }[];
  unchanged: number;
  refused: [string, string][];
  digest: string;
};
