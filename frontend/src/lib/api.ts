// The one place that talks to the luoto backend. Every call carries the per-run token that
// `luoto ui` printed in the link's fragment (kept in sessionStorage, never in a URL).

import type {
  AccessRequest,
  Approved,
  CreatedEnv,
  Decision,
  Downed,
  EnvDetail,
  EnvDisk,
  HostSummary,
  LuotoEvent,
  Meta,
  Narrowing,
  NewEnv,
  NewRule,
  Overview,
  ProjectAction,
  ProjectStatus,
  Proposal,
  PullApply,
  Pulled,
  PullPlans,
  Reloaded,
  Resolved,
  Rule,
  SelftestReport,
  SetupInfo,
  SharesView,
  Shown,
  SyncedShares,
  VaultView,
  VmDisk,
} from "./types";

const TOKEN_KEY = "luoto:token";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public data: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

/** Move a `#token=…` fragment into session storage and drop it from the address bar. */
export function bootToken(): void {
  const m = /token=([0-9a-f]+)/.exec(location.hash);
  if (m) {
    try {
      sessionStorage.setItem(TOKEN_KEY, m[1]);
    } catch {
      /* storage unavailable: requests will fail with a clear 401 */
    }
    history.replaceState(null, "", location.pathname + location.search);
  }
}

function token(): string {
  try {
    return sessionStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
}

async function request<T, B = Record<string, never>>(
  method: string,
  path: string,
  body?: B,
): Promise<T> {
  const res = await fetch(`/api${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token()}`,
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let data: unknown = text;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    /* plain-text error body */
  }
  if (!res.ok) {
    const obj = (typeof data === "object" && data !== null ? data : {}) as Record<string, unknown>;
    const msg =
      typeof obj.error === "string" ? obj.error : typeof data === "string" ? data : res.statusText;
    throw new ApiError(res.status, msg, obj);
  }
  return data as T;
}

const env = (name: string) => `/envs/${encodeURIComponent(name)}`;

/** The risks a 409 asks the user to confirm (resend with `force`), or null for any other error. */
export const risksOf = (e: unknown): string[] | null =>
  e instanceof ApiError && e.status === 409 ? ((e.data.risks as string[] | undefined) ?? []) : null;

export const api = {
  overview: () => request<Overview>("GET", "/overview"),
  meta: () => request<Meta>("GET", "/meta"),
  setup: () => request<SetupInfo>("GET", "/setup"),
  createEnv: (body: NewEnv) => request<CreatedEnv, NewEnv>("POST", "/envs", body),
  detect: (body: NewEnv) => request<Proposal, NewEnv>("POST", "/detect", body),
  env: (name: string) => request<EnvDetail>("GET", env(name)),
  disk: () => request<VmDisk>("GET", "/disk"),
  envsDisk: () => request<Record<string, EnvDisk>>("GET", "/disk/envs"),
  projectStatus: (name: string) => request<ProjectStatus>("GET", `${env(name)}/project`),
  projectAction: (name: string, action: "accept" | "forget", sha?: string) =>
    request<ProjectStatus, ProjectAction>("POST", `${env(name)}/project`, { action, sha }),
  egress: (name: string, minutes: number) =>
    request<HostSummary[]>("GET", `${env(name)}/egress?minutes=${minutes}`),
  /** What `host` resolves to on this machine: its private addresses. */
  resolve: (host: string) => request<Resolved>("GET", `/resolve?host=${encodeURIComponent(host)}`),
  events: (name: string, host: string, minutes: number) =>
    request<LuotoEvent[]>(
      "GET",
      `${env(name)}/events?minutes=${minutes}&host=${encodeURIComponent(host)}`,
    ),
  requests: (name: string) => request<AccessRequest[]>("GET", `${env(name)}/requests`),
  // `created` names the request shown: the gate numbers requests anew when it restarts.
  // `allowPrivate`: on the user's network or VPN, as the request asked unless the user chose.
  approve: (
    name: string,
    req: AccessRequest,
    ttl?: string,
    force = false,
    narrow?: Narrowing,
    allowPrivate = req.private ?? false,
  ) =>
    request<Approved, Decision>("POST", `${env(name)}/requests/${req.id}/approve`, {
      created: req.created,
      ttl,
      force,
      narrow,
      private: allowPrivate || undefined,
    }),
  /** What approving `req` so would ask to confirm; an error says why it would be refused. */
  approvalRisks: (name: string, req: AccessRequest, narrow?: Narrowing, allowPrivate = false) =>
    request<string[], Decision>("POST", `${env(name)}/requests/${req.id}/risks`, {
      created: req.created,
      narrow,
      private: allowPrivate || undefined,
    }),
  approveVar: (name: string, req: AccessRequest, value: string) =>
    request<Approved, Decision>("POST", `${env(name)}/requests/${req.id}/approve`, {
      created: req.created,
      var: value,
    }),
  reject: (name: string, req: AccessRequest) =>
    request<AccessRequest, Shown>("POST", `${env(name)}/requests/${req.id}/reject`, {
      created: req.created,
    }),
  addRule: (name: string, rule: Rule, force = false) =>
    request<Rule, NewRule>("POST", `${env(name)}/rules`, { rule, force }),
  /** Replace rule `id` with `rule` (under a new id); risks answer 409 as for `addRule`. */
  replaceRule: (name: string, id: string, rule: Rule, force = false) =>
    request<Rule, NewRule>("PUT", `${env(name)}/rules/${encodeURIComponent(id)}`, { rule, force }),
  deleteRule: (name: string, id: string) =>
    request<number>("DELETE", `${env(name)}/rules/${encodeURIComponent(id)}`),
  action: (name: string, action: "up" | "rebuild" | "open" | "close") =>
    request<unknown>("POST", `${env(name)}/${action}`, {}),
  down: (name: string) => request<Downed>("POST", `${env(name)}/down`, {}),
  selftest: (name: string) => request<SelftestReport>("POST", `${env(name)}/selftest`, {}),
  pullPlan: (name: string) => request<PullPlans>("GET", `${env(name)}/pull`),
  pull: (name: string, digest: string, includeRisky: boolean) =>
    request<Pulled, PullApply>("POST", `${env(name)}/pull`, {
      digest,
      include_risky: includeRisky,
    }),
  shares: (name: string) => request<SharesView>("GET", `${env(name)}/shares`),
  syncShares: (name: string) => request<SyncedShares>("POST", `${env(name)}/shares`, {}),
  vault: (action: "unlock" | "lock") => request<unknown>("POST", `/vault/${action}`, {}),
  reloadVault: () => request<Reloaded>("POST", "/vault/reload", {}),
  vaultView: () => request<VaultView>("GET", "/vault"),
};

/** Follow the live event stream (fetch-based SSE, so the token can travel in a header). */
export async function followEvents(
  onEvent: (e: LuotoEvent) => void,
  signal: AbortSignal,
): Promise<void> {
  const res = await fetch("/api/stream", {
    headers: { Authorization: `Bearer ${token()}` },
    signal,
  });
  if (!res.ok || !res.body) throw new ApiError(res.status, "event stream unavailable");
  const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
  let buf = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return;
    buf += value;
    let idx: number;
    while ((idx = buf.indexOf("\n\n")) >= 0) {
      const chunk = buf.slice(0, idx);
      buf = buf.slice(idx + 2);
      for (const line of chunk.split("\n")) {
        if (line.startsWith("data:")) {
          try {
            onEvent(JSON.parse(line.slice(5).trim()) as LuotoEvent);
          } catch {
            /* keep-alive or malformed line */
          }
        }
      }
    }
  }
}
