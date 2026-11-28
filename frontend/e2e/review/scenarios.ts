import type { Page, Request } from "@playwright/test";

import type {
  AccessRequest,
  CompiledRule,
  Credential,
  EnvDetail,
  EnvDisk,
  EnvRow,
  HostSummary,
  LuotoEvent,
  Overview,
  ProjectStatus,
  Proposal,
  SetupInfo,
  SharesView,
  VaultStatus,
  VaultView,
  VmDisk,
} from "../../src/lib/types";
import { fixture, type Route } from "../mock";

// The UI's corner cases, each a set of routes over the fixtures' and the views to render of
// it. Every body is a fixture with fields replaced, typed as the API's, so one that drifts
// from the Rust types fails `yarn typecheck` as the fixtures do.

export type View = {
  name: string;
  /** Bring the page to the view, from any view before it, and wait for what it shows. */
  open: (page: Page) => Promise<void>;
};

export type Scenario = {
  name: string;
  about: string;
  routes: Route[];
  views: View[];
  /** Statuses it answers with on purpose: the browser's console line for one is no finding. */
  statuses?: number[];
};

// Bodies

/** A timestamp `minutes` from now. */
const at = (minutes: number): string => new Date(Date.now() + minutes * 60_000).toISOString();
const list = <T>(n: number, of: (i: number) => T): T[] =>
  Array.from({ length: n }, (_, i) => of(i));

const row = (o: Partial<EnvRow> = {}): EnvRow => ({ ...fixture("overview").envs[0], ...o });
const detail = (o: Partial<EnvDetail> = {}): EnvDetail => ({ ...fixture("env"), ...o });
const host = (o: Partial<HostSummary>): HostSummary => ({ ...fixture("egress")[1], ...o });
const blocked = (o: Partial<HostSummary>): HostSummary => ({ ...fixture("egress")[0], ...o });
const rule = (o: Partial<CompiledRule>): CompiledRule => ({ ...fixture("env").rules[0], ...o });
const credential = (o: Partial<Credential>): Credential => ({
  ...fixture("vault").credentials[0],
  ...o,
});
const vaultStatus = (o: Partial<VaultStatus> = {}): VaultStatus => ({
  ...fixture("vault").status,
  ...o,
});
const request = (o: Partial<AccessRequest>): AccessRequest => ({
  id: 1,
  host: "example.com",
  access: "read",
  reason: "fetch the release notes",
  status: "pending",
  created: at(-3),
  ...o,
});
const event = (o: Partial<LuotoEvent>): LuotoEvent => ({
  seq: 1,
  run: "a",
  ts: at(-5),
  source: "gate",
  env: "web",
  kind: "http",
  verdict: "allow",
  method: "GET",
  host: "example.com",
  path: "/",
  status: 200,
  ...o,
});

// Routes

const get = (path: RegExp, body: unknown): Route => ({
  method: "GET",
  path,
  body: () => structuredClone(body),
});
const fail = (method: string, path: RegExp, status: number, error: string): Route => ({
  method,
  path,
  body: () => ({ error }),
  status: () => status,
});
const hang = (method: string, path: RegExp): Route => ({
  method,
  path,
  body: () => null,
  hang: true,
});

const overview = (o: Partial<Overview> = {}): Route =>
  get(/^\/api\/overview$/, { ...fixture("overview"), ...o } satisfies Overview);
const vault = (v: VaultView): Route => get(/^\/api\/vault$/, v);
const setup = (s: SetupInfo): Route => get(/^\/api\/setup$/, s);
const disk = (d: Partial<VmDisk>): Route =>
  get(/^\/api\/disk$/, { ...fixture("disk"), ...d } satisfies VmDisk);
const envDisk = (names: string[]): Route =>
  get(
    /^\/api\/disk\/envs$/,
    Object.fromEntries(names.map((n) => [n, fixture("envDisk").web])) satisfies Record<
      string,
      EnvDisk
    >,
  );
const detect = (p: Partial<Proposal> = {}): Route => ({
  method: "POST",
  path: /^\/api\/detect$/,
  body: () => ({ ...fixture("detect"), ...p }) satisfies Proposal,
});

type EnvData = {
  detail: EnvDetail;
  egress: HostSummary[];
  requests: AccessRequest[];
  project: ProjectStatus;
  shares: SharesView;
  events: LuotoEvent[];
};

/** Every env's own routes: the fixtures' answers under its name, with what `of` replaces. */
const envs = (of: (name: string) => Partial<EnvData> = () => ({})): Route[] => {
  const data = (req: Request): EnvData => {
    const name = decodeURIComponent(new URL(req.url()).pathname.split("/")[3]);
    const d: EnvData = {
      detail: fixture("env"),
      egress: fixture("egress"),
      requests: fixture("requests"),
      project: fixture("project"),
      shares: fixture("shares"),
      events: [],
      ...of(name),
    };
    return { ...d, detail: { ...d.detail, name } };
  };
  const one = (rest: string, pick: (d: EnvData) => unknown): Route => ({
    method: "GET",
    path: new RegExp(`^/api/envs/[^/]+${rest}$`),
    body: (req) => pick(data(req)),
  });
  return [
    one("", (d) => d.detail),
    one("/egress", (d) => d.egress),
    one("/requests", (d) => d.requests),
    one("/project", (d) => d.project),
    one("/shares", (d) => d.shares),
    one("/events", (d) => d.events),
  ];
};

// Views

const envRows = (page: Page) => page.locator("nav.nav button.row:has(.dot)");
const surface = (page: Page, name: "egress" | "rules") =>
  page.getByRole("group", { name: "env view" }).getByRole("button", { name });
const subject = (page: Page) => page.locator("aside.subject");

/** The first env's egress; `shows` is what it has once its answers are in. */
const egress = (shows = "main .table-wrap"): View => ({
  name: "egress",
  open: async (page) => {
    await envRows(page).first().click();
    await surface(page, "egress").click();
    await page.locator(shows).first().waitFor();
  },
});

const hostPanel: View = {
  name: "host",
  open: async (page) => {
    await envRows(page).first().click();
    await surface(page, "egress").click();
    await page.locator("main .table-wrap tbody tr").first().click();
    await subject(page)
      .locator("p.label", { hasText: /^host$/ })
      .waitFor();
  },
};

const requestPanel = (nth = 0, name = "request"): View => ({
  name,
  open: async (page) => {
    await envRows(page).first().click();
    await surface(page, "egress").click();
    await page.locator(".request button.open").nth(nth).click();
    await subject(page).getByRole("button", { name: "Reject" }).waitFor();
  },
});

const rules: View = {
  name: "rules",
  open: async (page) => {
    await envRows(page).first().click();
    await surface(page, "rules").click();
    await page.locator("main section.card").first().waitFor();
  },
};

const vaultView = (shows: string | RegExp): View => ({
  name: "vault",
  open: async (page) => {
    await page.locator("nav.nav button.row").last().click();
    await page.locator("main").getByText(shows).first().waitFor();
  },
});

/** The context menu of the last env in the list, the one nearest the window's edge. */
const envMenu: View = {
  name: "menu",
  open: async (page) => {
    await envRows(page).last().click({ button: "right" });
    await page.getByRole("menu").waitFor();
  },
};

const newEnv = (shows: string | RegExp): View => ({
  name: "new-env",
  open: async (page) => {
    await page.getByRole("button", { name: "New env" }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByPlaceholder("~/dev/my-project").fill("~/dev/api");
    await dialog.getByText(shows).first().waitFor();
  },
});

const landing = (shows: string | RegExp): View => ({
  name: "landing",
  open: async (page) => {
    await page.getByText(shows).first().waitFor();
  },
});

// Crowded

const NAMES = ["web", "api", "billing", "docs", "infra", "mobile", "search", "ml", "data", "ops"];
const crowdNames = list(30, (i) => (i < NAMES.length ? NAMES[i] : `${NAMES[i % 10]}-${i}`));
const ORIGINS = ["user", "preset:npm", "preset:pypi", "agent:claude", "provider:anthropic"];
const BASE_RULES = fixture("env").rules;

const crowdRules = list(200, (i): CompiledRule => {
  const origin = ORIGINS[i % ORIGINS.length];
  return {
    ...BASE_RULES[i % BASE_RULES.length],
    id: `${origin.replace(":", "-")}-${i}`,
    origin,
    host: `r${i}.${BASE_RULES[i % BASE_RULES.length].host}`,
    ...(origin === "user" && i % 2 ? { expires: at(7 * i) } : {}),
  };
});

const crowdRequests = list(50, (i): AccessRequest => {
  const base = { id: i + 1, created: at(-i * 4 - 1) };
  const kinds: Partial<AccessRequest>[] = [
    { host: `cdn-${i}.example.com` },
    { host: `api-${i}.example.com`, access: "write", paths: ["/v1/uploads/**", "/v1/jobs/*"] },
    { host: `db-${i}.example.com`, port: 5432, access: "write" },
    { host: `wiki-${i}.corp.example`, private: true },
    { host: "", install: { kind: "package", name: `libfoo${i}-dev` } },
    { host: "", install: { kind: "tool", name: "node", version: `${20 + (i % 5)}` } },
    { host: "", install: { kind: "preset", name: "npm" } },
    { host: "", install: { kind: "var", name: `FEATURE_${i}`, value: "on" } },
  ];
  return request({ ...base, ...kinds[i % kinds.length] });
});

const crowdEgress = list(500, (i): HostSummary => {
  const name = `h${i}.zone-${i % 17}.example.net`;
  if (i % 3 === 0) {
    return blocked({
      host: name,
      denied: 1 + (i % 40),
      last_message: `no rule allows ${name}`,
      last_seen: at(-i),
    });
  }
  return host({
    host: name,
    allowed: 1 + i * 3,
    denied: i % 7 === 0 ? 2 : 0,
    methods: i % 4 ? ["GET"] : ["GET", "POST", "PUT", "DELETE"],
    bytes_up: i * 911,
    bytes_down: i * 104_729,
    last_seen: at(-i),
  });
});

const crowdCredentials = crowdNames.flatMap((env, i): Credential[] => [
  credential({ env, change: `luoto agent auth -e ${env} claude` }),
  credential({
    env,
    binding: "github",
    what: `GitHub token for acme/${env}`,
    kept: "keyring:luoto/github-pat",
    hosts: ["api.github.com", "github.com"],
    state: i % 4 === 0 ? "missing" : "loaded",
    change: `luoto repo auth -e ${env} acme/${env}`,
  }),
  credential({
    env,
    binding: "custom.billing",
    what: "custom credential billing",
    kept: "op://Dev/billing/key",
    hosts: ["api.example.com"],
    state: i % 5 === 0 ? "not_up" : "loaded",
    change: null,
  }),
]);

const crowded: Scenario = {
  name: "crowded",
  about: "30 envs, 200 rules, 50 pending requests, 500 hosts, 90 credentials",
  routes: [
    overview({
      envs: crowdNames.map((name, i) =>
        row({
          name,
          dir: `/home/me/dev/${name}`,
          dev: i % 3 === 2 ? "stopped" : "running",
          gate: i % 3 === 2 ? "stopped" : "running",
          pending: i % 4 === 0 ? 50 - i : 0,
          denied_recent: (i * 37) % 140,
          open: i % 9 === 4 ? { until: at(52) } : null,
        }),
      ),
      vault: vaultStatus({
        loaded_refs: list(40, (i) => `op://Dev/secret-${i}/value`),
        envs: crowdNames.map((env) => ({ env, bindings: ["github"], missing: [] })),
      }),
    }),
    ...envs(() => ({
      detail: detail({
        rules: crowdRules,
        denies: 4127,
        credentials: crowdCredentials.slice(0, 3),
        variables: list(24, (i) =>
          i % 2
            ? { kind: "plain", name: `SETTING_${i}`, value: `value-${i}` }
            : { kind: "secret", name: `SECRET_${i}`, kept: `op://Dev/secret-${i}/value` },
        ),
        luoto_variables: list(12, (i) => `LUOTO_SETS_${i}`),
        ports: {
          published: [8080, 8443],
          forwarded: list(12, (i) => 3000 + i),
          temporary: list(8, (i) => 54_800 + i),
          taken: [5432, 6379, 9200],
        },
      }),
      egress: crowdEgress,
      requests: crowdRequests,
      events: list(120, (i) =>
        event({
          seq: i,
          ts: at(-i),
          path: `/v1/items/${i}`,
          status: i % 5 ? 200 : 502,
          verdict: i % 6 ? "allow" : "deny",
        }),
      ),
      shares: {
        shares: list(8, (i) => ({ ...fixture("shares").shares[0], name: `share-${i}` })),
        fix: null,
      },
    })),
    vault({
      status: vaultStatus({ loaded_refs: list(40, (i) => `op://Dev/secret-${i}/value`) }),
      credentials: crowdCredentials,
      unused: list(12, (i) => `op://Old/retired-${i}/credential`),
      errors: [],
    }),
    envDisk(crowdNames),
    detect(),
  ],
  views: [
    egress("main .table-wrap tbody tr"),
    hostPanel,
    requestPanel(),
    rules,
    vaultView("unlocked since"),
    envMenu,
    newEnv("api.stripe.com (read)"),
  ],
};

// Hostile text

const LABEL = "a-very-long-dns-label-that-runs-to-the-sixty-three-character-limit".slice(0, 63);
/** A host name of 253 characters, the longest DNS allows. */
const LONG_HOST = [LABEL, LABEL, LABEL, LABEL.slice(0, 61)].join(".");
/** Markup that leaves a mark on the page if any of it is rendered as HTML. */
const MARKUP =
  '<img src=x onerror="window.__pwn=1"><script>window.__pwn=1</script><b data-pwn>bold</b> &lt;i&gt;';
const ESCAPES = "\u001b[31mred\u001b[0m bell\u0007 tab\there\r\nnext line \u0000 nul";
const BIDI = "‮gnp.exe‬ مرحبا بالعالم שלום עולם";
const EMOJI = "👩‍👩‍👧‍👦 🏳️‍🌈 🧑🏽‍🚀 Z̸̢̛a̴l̷g̶o̵ 日本語のテキスト";
const UNBROKEN = "x".repeat(400);
const LONG_ENV = "customer-portal-frontend-monorepo-with-a-name-that-keeps-going-and-going";
const LONG_PATH = `/home/me/${"deeply/nested/".repeat(12)}project with spaces/日本語`;
const HOSTILE = [MARKUP, ESCAPES, BIDI, EMOJI, UNBROKEN];

const hostile: Scenario = {
  name: "hostile",
  about:
    "253-char hosts, long names and paths, bidi and emoji, escapes and markup from the sandbox",
  routes: [
    overview({
      envs: [
        row({ name: LONG_ENV, dir: LONG_PATH, pending: 12_345, denied_recent: 98_765 }),
        row({ name: "日本語-👩‍👩‍👧‍👦-env", dir: null, remote: `acme/${UNBROKEN}`, branch: BIDI }),
        row({ name: "broken", dev: "stopped", gate: "stopped", error: `${MARKUP} ${ESCAPES}` }),
      ],
    }),
    ...envs(() => ({
      detail: detail({
        path: `${LONG_PATH}/envs/${LONG_ENV}.toml`,
        rules: [
          rule({ id: "u1", origin: "user", host: LONG_HOST, note: MARKUP, expires: at(600) }),
          rule({
            id: "u2",
            origin: "user",
            host: "bücher.example",
            access: ["GET", "POST", "PUT", "PATCH", "DELETE", "PROPFIND", "REPORT"],
            paths: list(6, (i) => `/${"segment/".repeat(10)}${i}/**`),
            note: EMOJI,
          }),
          rule({ id: "p1", origin: `preset:${LABEL}`, host: `*.${LONG_HOST.slice(2)}` }),
        ],
        warnings: HOSTILE,
        credentials: [
          credential({ what: MARKUP, kept: `op://${UNBROKEN}`, hosts: [LONG_HOST, LONG_HOST] }),
        ],
        variables: [
          {
            kind: "plain",
            name: "A_VARIABLE_NAME_THAT_IS_MUCH_LONGER_THAN_ANY_SHOULD_BE",
            value: MARKUP,
          },
          { kind: "plain", name: "UNBROKEN", value: UNBROKEN },
          { kind: "secret", name: "SECRET", kept: `op://Vault ${EMOJI}/item/${UNBROKEN}` },
        ],
        isolation: `${ESCAPES} ${UNBROKEN}`,
        pull_on_stop: true,
        last_pull: { at: at(-90), line: `${MARKUP} ${UNBROKEN}`, incomplete: true },
      }),
      egress: [
        blocked({ host: LONG_HOST, last_message: `${MARKUP} ${ESCAPES}`, denied: 1_234_567 }),
        blocked({ host: "xn--bcher-kva.example", last_message: BIDI }),
        host({
          host: "2001:db8:85a3::8a2e:370:7334",
          methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "PROPFIND"],
          intakes: ["proxy", "transparent", "dns"],
          allowed: 987_654_321,
        }),
        host({ host: `${EMOJI}.example`, top_paths: [[MARKUP, 3]] }),
      ],
      requests: [
        request({ id: 1, host: LONG_HOST, access: "write", reason: MARKUP }),
        request({ id: 2, host: "example.com", reason: ESCAPES, paths: [`/${UNBROKEN}`] }),
        request({ id: 3, host: LONG_HOST, port: 65_535, access: "write", reason: BIDI }),
        request({ id: 4, host: "example.org", reason: `${EMOJI} ${UNBROKEN}` }),
        request({ id: 5, host: "", install: { kind: "package", name: MARKUP }, reason: MARKUP }),
        request({ id: 6, host: "", install: { kind: "var", name: "PWN", value: MARKUP } }),
      ],
      events: [
        event({ path: `/${MARKUP}` }),
        event({ path: `/${UNBROKEN}`, status: 502, message: `${ESCAPES} ${MARKUP}` }),
        event({ path: `/${BIDI}`, verdict: "deny", message: EMOJI }),
      ],
      project: {
        state: "changed",
        accepted: [["presets", "npm"]],
        current: [
          ["allow", `${LONG_HOST} (read)`],
          ["note", MARKUP],
        ],
        diff: [`+ allow ${LONG_HOST}`, `- ${MARKUP}`, `+ ${ESCAPES}`],
        error: null,
        needs: [`[credentials.custom.${LABEL}]\nhost = "${LONG_HOST}"`],
        sha: "ab".repeat(32),
      },
      shares: {
        shares: [
          { ...fixture("shares").shares[0], name: LABEL, folder: LONG_PATH },
          { ...fixture("shares").shares[0], name: "gone", error: `${MARKUP} ${UNBROKEN}` },
        ],
        fix: `luoto share sync -e ${LONG_ENV}`,
      },
    })),
    vault({
      status: vaultStatus({ loaded_refs: [`op://${UNBROKEN}`] }),
      credentials: [
        credential({ env: LONG_ENV, what: MARKUP, kept: `op://${UNBROKEN}`, hosts: [LONG_HOST] }),
        credential({ env: LONG_ENV, binding: LABEL, what: `${EMOJI} ${BIDI}`, state: "missing" }),
      ],
      unused: [`op://${UNBROKEN}`, MARKUP],
      errors: [`${LONG_ENV}: ${MARKUP} ${ESCAPES}`],
    }),
    detect({
      name: LONG_ENV,
      presets: [{ name: "npm", reason: `${LONG_PATH}/package.json` }],
      tools: [{ tool: "node", version: UNBROKEN.slice(0, 80), source: LONG_PATH }],
      project: [
        ["allow", `${LONG_HOST} (read)`],
        ["note", MARKUP],
        ["note", ESCAPES],
      ],
    }),
  ],
  views: [
    egress("main .table-wrap tbody tr"),
    hostPanel,
    requestPanel(),
    rules,
    vaultView("unlocked since"),
    newEnv("luoto.toml, written in the repository"),
  ],
};

// States

const states: Scenario = {
  name: "states",
  about: "gate down, stopped, failing and open envs; expired rules; every egress verdict",
  routes: [
    overview({
      envs: [
        row({ name: "gate-down", gate: "exited", pending: 2, denied_recent: 14 }),
        row({ name: "stopped", dev: "stopped", gate: "stopped", denied_recent: 0 }),
        row({ name: "failing", dev: "exited", gate: "exited", error: "podman: no such container" }),
        row({ name: "open-timed", open: { until: at(52) } }),
        row({ name: "open-forever", open: {} }),
        fixture("remote"),
      ],
      vault: vaultStatus({
        envs: [{ env: "gate-down", bindings: ["github"], missing: ["op://Dev/billing/key"] }],
      }),
    }),
    ...envs((name) => ({
      detail: detail({
        dev: name === "stopped" ? "stopped" : "running",
        gate: name === "stopped" ? "stopped" : "exited",
        gate_status: null,
        denies: 14,
        warnings: [
          "the gate is not running: nothing leaves the env until `luoto up -e gate-down`",
          "rule u-expired expired 30 minutes ago",
        ],
        rules: [
          rule({ id: "u-expired", origin: "user", host: "expired.example.com", expires: at(-30) }),
          rule({ id: "u-soon", origin: "user", host: "soon.example.com", expires: at(4) }),
          rule({ id: "u-hours", origin: "user", host: "hours.example.com", expires: at(300) }),
          rule({
            id: "u-tunnel",
            origin: "user",
            host: "pinned.example.com",
            port: 8443,
            access: "write",
            mode: "tunnel",
            allow_private: true,
          }),
          ...fixture("env").rules.slice(0, 6),
        ],
        credentials: fixture("vault").credentials,
        pull_on_stop: true,
        last_pull: {
          at: at(-200),
          line: "pulled 12 files into ~/dev/web; 3 held back for review",
          incomplete: true,
        },
      }),
      egress: [
        blocked({ host: "blocked.example.com", denied: 14 }),
        blocked({ host: "muted.example.com", denied: 3, muted: 3 }),
        host({ host: "lookup-only.example.com", allowed: 0, dns_only: true, methods: [] }),
        host({ host: "through-open.example.com", allowed: 2, opened: 2, last_rule: "open" }),
        blocked({ host: "pinned.example.com", tls_rejected: true }),
        blocked({ host: "now-allowed.example.com", allowed: 1, allowed_now: "u-soon" }),
        blocked({
          host: "db.corp.internal",
          allowed_not_private: "u-hours",
          last_reason: "private_address",
          last_message: "db.corp.internal resolves to a private address",
        }),
        host({ host: "partly.example.com", allowed: 5, denied: 2, wants_write: true }),
      ],
      requests: [request({ id: 1 }), request({ id: 2, host: "db.corp.internal", private: true })],
      events: [
        event({
          verdict: "deny",
          status: undefined,
          message: "no rule allows blocked.example.com",
        }),
      ],
      project: {
        state: "changed",
        accepted: [["presets", "npm"]],
        current: [
          ["presets", "npm, pypi"],
          ["allow", "api.stripe.com (read)"],
        ],
        diff: ["+ presets pypi", "+ allow api.stripe.com (read)"],
        error: null,
        needs: ['[credentials.custom.stripe]\nhost = "api.stripe.com"\nsecret = "…"'],
        sha: "ab".repeat(32),
      },
      shares: {
        shares: [
          fixture("shares").shares[0],
          { ...fixture("shares").shares[0], name: "gone", error: "the folder is gone" },
        ],
        fix: "luoto share sync -e gate-down",
      },
    })),
    vault({
      status: vaultStatus(),
      credentials: [
        credential({ env: "gate-down" }),
        credential({ env: "gate-down", binding: "custom.billing", state: "missing", change: null }),
        credential({ env: "stopped", binding: "github", state: "not_up" }),
        credential({ env: "failing", binding: "github", state: "locked" }),
      ],
      unused: ["op://Old/retired/credential"],
      errors: ["failing: envs/failing.toml: unknown key `egres` at line 4"],
    }),
    disk({
      space: { size: 106_769_133_568, used: 101_245_800_448, free: 5_523_333_120 },
      low: true,
    }),
  ],
  views: [
    egress("main .table-wrap tbody tr"),
    hostPanel,
    rules,
    {
      name: "stopped",
      open: async (page) => {
        await envRows(page).nth(1).click();
        await subject(page).getByRole("button", { name: "Start" }).waitFor();
      },
    },
    vaultView("unlocked since"),
  ],
};

// Private access and the risks a 409 asks about, as `validate_rule` words them

const PRIVATE = "reaches private addresses: hosts on your network or VPN";
const RISKS = [PRIVATE];
/** The risks of approving each request as it asks. */
const REQUEST_RISKS: Record<string, string[]> = {
  "1": [
    "`*.corp.internal` covers every host under corp.internal",
    PRIVATE,
    "write access lets code in the sandbox upload data to *.corp.internal",
  ],
  "2": [
    "a tunnel to db.corp.internal:5432 is not inspected: code in the sandbox gets full access to it, any protocol and any data",
    PRIVATE,
  ],
};
const forced = (req: Request): boolean => !!(req.postDataJSON() as { force?: boolean }).force;

const risks: Scenario = {
  name: "risks",
  about: "requests for private access and tunnels; approving and allowing answer 409 with risks",
  statuses: [409],
  routes: [
    overview({ envs: [row({ pending: 3 })] }),
    ...envs(() => ({
      egress: [
        blocked({
          host: "db.corp.internal",
          last_reason: "private_address",
          last_message: "db.corp.internal resolves to a private address",
        }),
      ],
      requests: [
        request({ id: 1, host: "*.corp.internal", access: "write", private: true }),
        request({ id: 2, host: "db.corp.internal", port: 5432, access: "write", private: true }),
        request({ id: 3, host: "", install: { kind: "preset", name: "npm" } }),
      ],
    })),
    get(/^\/api\/resolve$/, { private: ["10.0.12.7", "fd00::7"], never: false }),
    {
      method: "POST",
      path: /^\/api\/envs\/[^/]+\/requests\/\d+\/risks$/,
      body: (req) => REQUEST_RISKS[/requests\/(\d+)/.exec(req.url())?.[1] ?? ""] ?? [],
    },
    {
      method: "POST",
      path: /^\/api\/envs\/[^/]+\/(rules|requests\/\d+\/approve)$/,
      body: (req) =>
        forced(req)
          ? { host: "db.corp.internal", access: "read" }
          : { error: "the rule has risks", risks: RISKS },
      status: (req) => (forced(req) ? 200 : 409),
    },
  ],
  views: [
    egress(".request"),
    {
      name: "request-risks",
      open: async (page) => {
        await page.locator(".request button.open").first().click();
        await subject(page).getByText(REQUEST_RISKS["1"][0]).waitFor();
      },
    },
    requestPanel(1, "tunnel"),
    {
      name: "rule-risks",
      open: async (page) => {
        await envRows(page).first().click();
        await page.getByRole("button", { name: "Add rule" }).click();
        await subject(page).getByPlaceholder("api.example.com").fill("db.corp.internal");
        await subject(page).getByText("resolves to 10.0.12.7").waitFor();
        await subject(page).getByRole("button", { name: "Allow", exact: true }).click();
        await subject(page).getByRole("alertdialog").waitFor();
      },
    },
  ],
};

// Empty

const firstRun: Scenario = {
  name: "first-run",
  about: "no envs, no vault: setup, then the first env",
  routes: [overview({ envs: [], vault: null }), detect()],
  views: [landing("run envs on"), newEnv("api.stripe.com (read)")],
};

const noRuntime: Scenario = {
  name: "no-runtime",
  about: "first run on a machine with no runtime luoto can use",
  routes: [
    overview({ envs: [], vault: null, runtime: "" }),
    setup({
      ...fixture("setup"),
      detection: { ...fixture("setup").detection, os: "linux", distro: "Fedora 43", runtimes: [] },
      runtimes: fixture("setup").runtimes.map((r) => ({
        ...r,
        status: r.runtime === "podman" ? "4.9.3, older than 5.2.0" : "not installed",
        ready: false,
        selected: false,
      })),
    }),
  ],
  views: [landing("install one, then, in a terminal")],
};

const empty: Scenario = {
  name: "empty",
  about: "one env with no rules, no egress and no requests; the vault locked, holding nothing",
  routes: [
    overview(),
    ...envs(() => ({
      detail: detail({
        rules: [],
        credentials: [],
        variables: [],
        luoto_variables: [],
        ports: { published: [], forwarded: [], temporary: [], taken: [] },
        gate_status: { ...fixture("env").gate_status, rules: 0 },
      }),
      egress: [],
      shares: { shares: [], fix: null },
    })),
    vault({
      status: vaultStatus({ locked: true, loaded_refs: [], envs: [] }),
      credentials: [],
      unused: [],
      errors: [],
    }),
    disk({ space: null, prunable: 0, prunable_bytes: 0 }),
  ],
  views: [egress("main .table-wrap .empty"), rules, vaultView("locked: every env"), envMenu],
};

// Failures

const ERROR =
  "runtime: podman --connection luoto inspect luoto-dev-web: exit status 125: Error: " +
  "unable to connect to Podman socket: failed to connect: dial tcp 127.0.0.1:53418: connection refused";

const errors: Scenario = {
  name: "errors",
  about: "the overview answers; every env, vault and disk call and every write is a 500",
  statuses: [500],
  routes: [
    overview(),
    fail("GET", /^\/api\/(envs\/.+|vault|disk|disk\/envs)$/, 500, ERROR),
    fail("POST", /^\/api\//, 500, ERROR),
  ],
  views: [
    egress("footer.status .error"),
    vaultView("reading…"),
    {
      name: "rule-fails",
      open: async (page) => {
        await envRows(page).first().click();
        await page.getByRole("button", { name: "Add rule" }).click();
        await subject(page).getByPlaceholder("api.example.com").fill("example.com");
        await subject(page).getByRole("button", { name: "Allow", exact: true }).click();
        await page.locator("footer.status .error").waitFor();
      },
    },
    newEnv("connection refused"),
  ],
};

const apiDown: Scenario = {
  name: "api-down",
  about: "every call is a 500",
  statuses: [500],
  routes: [fail("GET", /^\/api\//, 500, ERROR)],
  views: [landing("connection refused")],
};

const unauthorized: Scenario = {
  name: "unauthorized",
  about: "the link's token is not this run's",
  statuses: [401],
  routes: [fail("GET", /^\/api\//, 401, "unauthorized")],
  views: [landing("Open the link printed by")],
};

// Runtimes: the fixtures are podman's

const apple: Scenario = {
  name: "apple",
  about: "Apple's container, where every container is a VM",
  routes: [
    overview({ runtime: "Apple's container 1.7.1: each container its own VM" }),
    ...envs(() => ({
      detail: detail({
        isolation: "a VM of its own (Apple's container; `isolation` doesn't apply)",
      }),
    })),
    disk({ place: "the runtime's disk", space: null }),
  ],
  views: [egress("main .table-wrap tbody tr")],
};

// Loading

const slow: Scenario = {
  name: "slow",
  about: "the overview answers; every env, vault, disk and detect call never does",
  routes: [
    overview(),
    hang("GET", /^\/api\/(envs\/.+|vault|disk|disk\/envs|meta)$/),
    hang("POST", /^\/api\/detect$/),
  ],
  views: [egress(), vaultView("reading…"), newEnv("Copied in, git history included")],
};

const busy: Scenario = {
  name: "busy",
  about: "an approval that never answers",
  routes: [
    overview({ envs: [row({ pending: 1 })] }),
    ...envs(() => ({ requests: [request({ id: 1, access: "write" })] })),
    hang("POST", /\/approve$/),
  ],
  views: [
    {
      name: "approving",
      open: async (page) => {
        await page.locator(".request button.open").first().click();
        await subject(page).getByRole("button", { name: "Approve", exact: true }).click();
        await page.locator("header.top .busy").waitFor();
      },
    },
  ],
};

const connecting: Scenario = {
  name: "connecting",
  about: "the overview never answers",
  routes: [hang("GET", /^\/api\/overview$/)],
  views: [landing("connecting…")],
};

export const SCENARIOS: Scenario[] = [
  firstRun,
  noRuntime,
  empty,
  crowded,
  hostile,
  states,
  risks,
  errors,
  apiDown,
  unauthorized,
  apple,
  slow,
  busy,
  connecting,
];
