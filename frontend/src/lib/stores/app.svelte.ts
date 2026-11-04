// App-wide state shared by the panels: what exists (overview), which env and subject are
// selected, the selected env's egress and requests, and the status line. Panels read it
// directly; nothing threads it through props.

import { api, ApiError, followEvents } from "$lib/api";
import type { AccessRequest, EnvDetail, HostSummary, LuotoEvent, Meta, Overview } from "$lib/types";

export type Subject =
  | { kind: "env" }
  | { kind: "host"; host: string }
  | { kind: "request"; id: number }
  | { kind: "vault" }
  | { kind: "new" };

export const WINDOWS = [
  { minutes: 15, label: "15 min" },
  { minutes: 60, label: "1 h" },
  { minutes: 1440, label: "24 h" },
  { minutes: 10080, label: "7 d" },
] as const;

class AppState {
  overview = $state<Overview | null>(null);
  meta = $state<Meta | null>(null);
  env = $state<string | null>(null);
  detail = $state<EnvDetail | null>(null);
  egress = $state<HostSummary[]>([]);
  requests = $state<AccessRequest[]>([]);
  subject = $state<Subject>({ kind: "env" });
  minutes = $state(60);
  deniedOnly = $state(false);
  search = $state("");
  status = $state<{ text: string; error: boolean } | null>(null);
  busy = $state<string | null>(null);
  unauthorized = $state(false);
  live = $state(false);
  lastEvent = $state<LuotoEvent | null>(null);

  pending = $derived(this.requests.filter((r) => r.status === "pending"));
  visibleEgress = $derived(
    this.egress.filter(
      (h) =>
        (!this.deniedOnly || h.denied > 0 || h.dns_only) &&
        (!this.search || h.host.includes(this.search.trim().toLowerCase())),
    ),
  );
}

export const app = new AppState();

export function say(text: string, error = false): void {
  app.status = { text, error };
}

function failed(e: unknown): void {
  if (e instanceof ApiError && e.status === 401) {
    app.unauthorized = true;
    return;
  }
  say(e instanceof Error ? e.message : String(e), true);
}

export async function refreshOverview(): Promise<void> {
  try {
    app.overview = await api.overview();
    app.unauthorized = false;
    if (!app.env && app.overview.envs.length > 0) {
      await selectEnv(app.overview.envs[0].name);
    }
    if (app.env && !app.overview.envs.some((e) => e.name === app.env)) {
      app.env = null;
      app.detail = null;
    }
  } catch (e) {
    failed(e);
  }
}

export async function refreshEnv(): Promise<void> {
  const name = app.env;
  if (!name) return;
  try {
    const [detail, egress, requests] = await Promise.all([
      api.env(name),
      api.egress(name, app.minutes),
      api.requests(name),
    ]);
    if (app.env !== name) return;
    app.detail = detail;
    app.egress = egress;
    app.requests = requests;
  } catch (e) {
    failed(e);
  }
}

export async function selectEnv(name: string): Promise<void> {
  if (app.env !== name) {
    app.env = name;
    app.detail = null;
    app.egress = [];
    app.requests = [];
    app.subject = { kind: "env" };
  }
  await refreshEnv();
}

/** Run an action with a busy label, report the outcome, refresh what it may have changed. */
export async function act(
  label: string,
  fn: () => Promise<unknown>,
  done?: string,
): Promise<boolean> {
  app.busy = label;
  try {
    await fn();
    if (done) say(done);
    await Promise.all([refreshOverview(), refreshEnv()]);
    return true;
  } catch (e) {
    failed(e);
    return false;
  } finally {
    app.busy = null;
  }
}

/** Poll as a fallback and refresh promptly on live events. Returns a stop function. */
export function startSync(): () => void {
  const ctrl = new AbortController();
  let pendingRefresh: ReturnType<typeof setTimeout> | null = null;
  const onEvent = (e: LuotoEvent) => {
    app.lastEvent = e;
    if (e.env === app.env || e.source === "vault") {
      pendingRefresh ??= setTimeout(() => {
        pendingRefresh = null;
        void refreshEnv();
      }, 400);
    }
  };
  const connect = async () => {
    while (!ctrl.signal.aborted) {
      try {
        app.live = true;
        await followEvents(onEvent, ctrl.signal);
      } catch {
        /* reconnect below */
      }
      app.live = false;
      await new Promise((r) => setTimeout(r, 3000));
    }
  };
  void connect();
  void refreshOverview();
  void api.meta().then((m) => (app.meta = m), failed);
  const overviewTimer = setInterval(() => void refreshOverview(), 5000);
  const envTimer = setInterval(() => void refreshEnv(), 8000);
  return () => {
    ctrl.abort();
    clearInterval(overviewTimer);
    clearInterval(envTimer);
  };
}

export function ago(ts?: string | null): string {
  if (!ts) return "";
  const s = Math.max(0, (Date.now() - Date.parse(ts)) / 1000);
  if (s < 60) return `${Math.round(s)}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} kB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function accessText(a: unknown): string {
  if (a === "write") return "any method";
  if (Array.isArray(a)) return a.join(", ");
  return "read-only";
}
