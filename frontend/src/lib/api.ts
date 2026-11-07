// The one place that talks to the luoto backend. Every call carries the per-run token that
// `luoto ui` printed in the link's fragment (kept in sessionStorage, never in a URL).

import type {
  AccessRequest,
  EnvDetail,
  HostSummary,
  LuotoEvent,
  Meta,
  Overview,
  ProjectStatus,
  Proposal,
  PullPlans,
  Rule,
  SelftestReport,
  SetupInfo,
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

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
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
  setupInstall: () => request<{ output: string }>("POST", "/setup/install", {}),
  createEnv: (body: {
    name?: string;
    dir?: string;
    presets: string[];
    agents: string[];
    ports: number[];
    project_sha?: string;
  }) => request<{ name: string }>("POST", "/envs", body),
  detect: (body: { name?: string; dir?: string }) => request<Proposal>("POST", "/detect", body),
  env: (name: string) => request<EnvDetail>("GET", env(name)),
  projectStatus: (name: string) => request<ProjectStatus>("GET", `${env(name)}/project`),
  projectAction: (name: string, action: "accept" | "forget", sha?: string) =>
    request<ProjectStatus>("POST", `${env(name)}/project`, { action, sha }),
  egress: (name: string, minutes: number) =>
    request<HostSummary[]>("GET", `${env(name)}/egress?minutes=${minutes}`),
  events: (name: string, host: string, minutes: number) =>
    request<LuotoEvent[]>(
      "GET",
      `${env(name)}/events?minutes=${minutes}&host=${encodeURIComponent(host)}`,
    ),
  requests: (name: string) => request<AccessRequest[]>("GET", `${env(name)}/requests`),
  approve: (name: string, id: number, ttl?: string, force = false) =>
    request<Rule>("POST", `${env(name)}/requests/${id}/approve`, { ttl, force }),
  reject: (name: string, id: number) =>
    request<AccessRequest>("POST", `${env(name)}/requests/${id}/reject`, {}),
  addRule: (name: string, rule: Rule, force = false) =>
    request<Rule>("POST", `${env(name)}/rules`, { rule, force }),
  deleteRule: (name: string, id: string) =>
    request<number>("DELETE", `${env(name)}/rules/${encodeURIComponent(id)}`),
  action: (name: string, action: "up" | "down" | "rebuild") =>
    request<unknown>("POST", `${env(name)}/${action}`, {}),
  selftest: (name: string) => request<SelftestReport>("POST", `${env(name)}/selftest`, {}),
  pullPlan: (name: string) => request<PullPlans>("GET", `${env(name)}/pull`),
  pull: (name: string, digest: string, includeRisky: boolean) =>
    request<{ written: number; skipped: number }>("POST", `${env(name)}/pull`, {
      digest,
      include_risky: includeRisky,
    }),
  vault: (action: "unlock" | "lock") => request<unknown>("POST", `/vault/${action}`, {}),
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
