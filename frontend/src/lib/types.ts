// Hand-mirrored from the Rust structs the API serializes (luoto-shared + cli/src/ui/api.rs).

export type Verdict = "allow" | "deny";
export type AccessLevel = "read" | "write";
export type Access = AccessLevel | string[];
export type Mode = "inspect" | "tunnel";

/** A toolchain version a project file pins (`node 22` from `.node-version`). */
export type ToolPin = { tool: string; version: string; source: string };

/** What creating an env from these choices would produce (`POST /api/detect`). */
export type Proposal = {
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
  current: [string, string][];
  diff: string[];
  error: string | null;
  needs: string[];
  /** sha256 of the current text; accepting sends it back so only this text applies. */
  sha: string | null;
};

export type LuotoEvent = {
  env: string;
  ts?: string;
  source?: "gate" | "vault";
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
  verdict?: Verdict;
  method?: string;
  path?: string;
  status?: number;
};

export type HostSummary = {
  host: string;
  allowed: number;
  denied: number;
  dns_only: boolean;
  methods: string[];
  intakes: string[];
  top_paths: [string, number][];
  last_message?: string;
  last_rule?: string;
  bytes_up: number;
  bytes_down: number;
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
};

export type EnvRow = {
  name: string;
  dev: string;
  gate: string;
  dir?: string | null;
  pending: number;
  denied_recent: number;
  error?: string | null;
};

export type VaultStatus = {
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
  rules: number;
};

export type EnvDetail = {
  name: string;
  path: string;
  rules: CompiledRule[];
  injections: { host: string; binding: string }[];
  warnings: string[];
  dev: string;
  gate: string;
  gate_status: GateStatus | null;
  credentials: string[];
  missing_secrets: string[];
  sandbox_secrets: string[];
};

export type Meta = {
  presets: { name: string; description: string }[];
  agents: { name: string; description: string }[];
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
    risky: string | null;
  }[];
  unchanged: number;
  refused: [string, string][];
  digest: string;
};

/** What `sandbox selftest` found inside the env (`POST /api/envs/{name}/selftest`). */
export type SelftestReport = {
  ok: boolean;
  checks: { name: string; ok: boolean; detail: string }[];
};
