// App-wide state shared by the panels: what exists (overview), what the surface shows (an
// env's egress or the vault), which env and subject are selected, the selected env's egress,
// requests and project status, the vault's credentials, disk use, and the status line.

import { api, ApiError, followEvents, risksOf } from "$lib/api";
import type {
  AccessRequest,
  EnvDetail,
  EnvDisk,
  HostSummary,
  Install,
  LuotoEvent,
  Meta,
  OpenEgress,
  Overview,
  ProjectStatus,
  VaultView,
  VmDisk,
} from "$lib/types";

export type Subject =
  | { kind: "env" }
  | { kind: "host"; host: string }
  | { kind: "request"; id: number }
  /** The vault as a whole, or one of its credentials: the surface shows the vault. */
  | { kind: "vault" }
  | { kind: "credential"; env: string; binding: string };

export const WINDOWS = [
  { minutes: 15, label: "15 min" },
  { minutes: 60, label: "1 h" },
  { minutes: 1440, label: "24 h" },
  { minutes: 10080, label: "7 d" },
] as const;

/** Access durations: `minutes` 0 means until revoked. */
export const TTLS = [
  { minutes: 15, label: "15 min" },
  { minutes: 60, label: "1 hour" },
  { minutes: 1440, label: "1 day" },
  { minutes: 0, label: "until revoked" },
] as const;

/** The expiry timestamp for a rule that lasts `minutes`, or undefined for no expiry. */
export const expiresIn = (minutes: number): string | undefined =>
  // eslint-disable-next-line svelte/prefer-svelte-reactivity -- a timestamp, not reactive state
  minutes ? new Date(Date.now() + minutes * 60_000).toISOString() : undefined;

class AppState {
  overview = $state<Overview | null>(null);
  meta = $state<Meta | null>(null);
  env = $state<string | null>(null);
  detail = $state<EnvDetail | null>(null);
  project = $state<ProjectStatus | null>(null);
  egress = $state<HostSummary[]>([]);
  requests = $state<AccessRequest[]>([]);
  subject = $state<Subject>({ kind: "env" });
  /** What the surface shows: the selected env's egress, or the vault across envs. */
  view = $state<"env" | "vault">("env");
  vault = $state<VaultView | null>(null);
  minutes = $state(60);
  deniedOnly = $state(false);
  search = $state("");
  status = $state<{ text: string; error: boolean } | null>(null);
  busy = $state<string | null>(null);
  unauthorized = $state(false);
  live = $state(false);
  vmDisk = $state<VmDisk | null>(null);
  /** Every env's disk use, read in one walk of the runtime's storage. */
  envDisk = $state<Record<string, EnvDisk> | null>(null);
  envDiskBusy = $state(false);
  envDiskError = $state<string | null>(null);

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

export const errorText = (e: unknown): string => (e instanceof Error ? e.message : String(e));

export const copyText = (text: string): void => {
  // The clipboard API is missing outside a secure context, and a browser can deny the write.
  void Promise.resolve()
    .then(() => navigator.clipboard.writeText(text))
    .then(
      () => say(`copied: ${text}`),
      () => say(`the browser denied the clipboard: select and copy ${text}`, true),
    );
};

/** A count and its noun: `1 file`, `3 files`. */
export const plural = (n: number, word: string): string => `${n} ${n === 1 ? word : `${word}s`}`;

function failed(e: unknown): void {
  if (e instanceof ApiError && e.status === 401) {
    app.unauthorized = true;
    return;
  }
  say(errorText(e), true);
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
      app.project = null;
    }
  } catch (e) {
    failed(e);
  }
}

export async function refreshEnv(): Promise<void> {
  const name = app.env;
  if (!name) return;
  try {
    const [detail, egress, requests, project] = await Promise.all([
      api.env(name),
      api.egress(name, app.minutes),
      api.requests(name),
      api.projectStatus(name).catch(() => null),
    ]);
    if (app.env !== name) return;
    app.detail = detail;
    app.project = project;
    app.egress = egress;
    app.requests = requests;
  } catch (e) {
    failed(e);
  }
}

/** Every env's credentials and what the vault holds: a compile per env, so only while shown. */
export async function refreshVault(): Promise<void> {
  try {
    app.vault = await api.vaultView();
  } catch (e) {
    failed(e);
  }
}

/** Show the vault on the surface, with one of its credentials as the subject if given. */
export function openVault(credential?: { env: string; binding: string }): void {
  app.view = "vault";
  app.subject = credential ? { kind: "credential", ...credential } : { kind: "vault" };
  void refreshVault();
}

export async function selectEnv(name: string): Promise<void> {
  if (app.env !== name) {
    app.env = name;
    app.detail = null;
    app.project = null;
    app.egress = [];
    app.requests = [];
  }
  // Picking the env shown already brings its egress and panel back (from the vault, a host).
  app.view = "env";
  app.subject = { kind: "env" };
  await refreshEnv();
}

const refreshAll = (): Promise<unknown> => Promise.all([refreshOverview(), refreshEnv()]);

/** The disk holding envs: several runtime calls, so read on start and every few minutes. */
export const refreshVmDisk = async (): Promise<void> => {
  try {
    app.vmDisk = await api.disk();
  } catch (e) {
    failed(e);
  }
};

/** Every env's disk use. The runtime walks every volume for it: read on demand, never polled. */
export const loadEnvDisk = async (): Promise<void> => {
  if (app.envDiskBusy) return;
  app.envDiskBusy = true;
  app.envDiskError = null;
  try {
    app.envDisk = await api.envsDisk();
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) failed(e);
    else app.envDiskError = errorText(e);
  } finally {
    app.envDiskBusy = false;
  }
};

/**
 * Run `fn` under a busy label and report a failure. Returns its value, or null when it failed.
 * A 409 carrying risks goes to `onRisks` for the user to confirm instead of being reported.
 */
export async function busyWhile<T>(
  label: string,
  fn: () => Promise<T>,
  onRisks?: (risks: string[]) => void,
): Promise<T | null> {
  app.busy = label;
  // The outcome of an earlier action no longer describes what is on screen.
  app.status = null;
  try {
    return await fn();
  } catch (e) {
    const risks = onRisks && risksOf(e);
    if (risks) onRisks(risks);
    else failed(e);
    return null;
  } finally {
    app.busy = null;
  }
}

/** `busyWhile`, then report `done` and refresh what the action may have changed. */
export const act = <T>(
  label: string,
  fn: () => Promise<T>,
  done?: string,
  onRisks?: (risks: string[]) => void,
): Promise<T | null> =>
  busyWhile(
    label,
    async () => {
      const result = await fn();
      if (done) say(done);
      await refreshAll();
      return result;
    },
    onRisks,
  );

export type VaultAction = "unlock" | "lock" | "reload";

/** Unlock, lock or reload the vault, report what came of it, and refresh the vault view. */
export const vaultAction = async (action: VaultAction): Promise<void> => {
  if (action === "reload") {
    const r = await act("reading secrets again… (your secret store may ask)", api.reloadVault);
    if (r) {
      const failed = r.failed.length ? `; not read: ${r.failed.join("; ")}` : "";
      say(`read ${r.read}: ${r.changed} changed${failed}`, r.failed.length > 0);
    }
  } else if (action === "unlock") {
    await act(
      "unlocking… (your secret store may ask to authorize)",
      () => api.vault("unlock"),
      "vault unlocked",
    );
  } else {
    await act("locking…", () => api.vault("lock"), "vault locked; credentialed hosts now get 403");
  }
  if (app.view === "vault") await refreshVault();
};

/** Poll as a fallback and refresh promptly on live events. Returns a stop function. */
export function startSync(): () => void {
  const ctrl = new AbortController();
  let pendingRefresh: ReturnType<typeof setTimeout> | null = null;
  const onEvent = (e: LuotoEvent) => {
    if (e.env === app.env || e.source === "vault") {
      pendingRefresh ??= setTimeout(() => {
        pendingRefresh = null;
        void refreshEnv();
        if (app.view === "vault") void refreshVault();
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
  void refreshVmDisk();
  const overviewTimer = setInterval(() => void refreshOverview(), 5000);
  const envTimer = setInterval(() => {
    void refreshEnv();
    if (app.view === "vault") void refreshVault();
  }, 8000);
  const diskTimer = setInterval(() => void refreshVmDisk(), 300_000);
  return () => {
    ctrl.abort();
    clearInterval(overviewTimer);
    clearInterval(envTimer);
    clearInterval(diskTimer);
  };
}

/** What an install request asks for: `postgresql-client`, `node 24 (mise)`, `the npm preset`. */
export function installLabel(i: Install): string {
  if (i.kind === "package") return i.name;
  if (i.kind === "preset") return `the ${i.name} preset`;
  if (i.kind === "var") return `the variable ${i.name}`;
  // Backends other than mise's registry and aqua's take anyone's code.
  const backend = i.name.split(":", 2);
  if (backend.length === 2 && backend[0] !== "aqua")
    return `${i.name} ${i.version} (mise, an unvetted ${backend[0]} source)`;
  return `${i.name} ${i.version} (mise)`;
}

/** Where an access request asks to go: its host, or `host:port` for a tunnel. */
export function requestTarget(r: AccessRequest): string {
  if (!r.port) return r.host;
  return r.host.includes(":") ? `[${r.host}]:${r.port}` : `${r.host}:${r.port}`;
}

/** How long open egress has left: `52m`, `3h`, or empty when it has no end. */
export function openLeft(open: OpenEgress): string {
  if (!open.until) return "";
  const m = Math.max(0, Math.ceil((Date.parse(open.until) - Date.now()) / 60_000));
  return m < 60 ? `${m}m` : `${Math.floor(m / 60)}h`;
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

/** Disk sizes in the runtimes' decimal units, as the CLI prints them: `4.2 GB`. */
export const diskSize = (n: number): string => {
  if (n < 1000) return `${n} B`;
  const units = ["kB", "MB", "GB", "TB", "PB"];
  let v = n / 1000;
  let unit = 0;
  while (v >= 999.95 && unit < units.length - 1) {
    v /= 1000;
    unit += 1;
  }
  return `${v.toFixed(1)} ${units[unit]}`;
};

export function accessText(a: unknown): string {
  if (a === "write") return "any method";
  if (Array.isArray(a)) return a.join(", ");
  return "read-only";
}
