import { expect, test } from "@playwright/test";

import type { Pulled, PullPlans, Reloaded, SelftestReport } from "../src/lib/types";
import egressHosts from "./fixtures/egress";
import { fixture, mockApi } from "./mock";

const open = (page: import("@playwright/test").Page) => page.goto(`/#token=${"ab".repeat(16)}`);

test("a host a rule allows since it was blocked reads as allowed", async ({ page }) => {
  await mockApi(page);
  const [blocked] = egressHosts;
  await page.route(
    (url) => url.pathname === "/api/envs/web/egress",
    (route) =>
      route.fulfill({ json: [{ ...blocked, allowed: 1, last_rule: "r1", allowed_now: "r1" }] }),
  );
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();

  const row = page.getByRole("row", { name: /example\.com/ });
  await expect(row).toContainText("allowed");
  await expect(row).toContainText("blocked before rule r1");
  await expect(row).not.toContainText("no rule allows");
  await row.click();
  await expect(page.getByText("allowed now by rule r1, blocked once before it")).toBeVisible();
});

test("a blocked host is allowed from the egress view", async ({ page }) => {
  const writes = await mockApi(page);
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();

  const blocked = page.getByRole("row", { name: /example\.com/ });
  await expect(blocked).toContainText("blocked");
  await expect(page.getByRole("row", { name: /deb\.debian\.org/ })).toContainText("allowed");

  await blocked.click();
  await expect(page.getByRole("heading", { name: "example.com" })).toBeVisible();
  // Offered for any host, since a blocked name was never resolved; off unless picked.
  await expect(page.getByRole("switch", { name: "allow private address" })).toHaveAttribute(
    "aria-checked",
    "false",
  );
  await page.getByRole("button", { name: "Allow", exact: true }).click();

  await expect.poll(() => writes.length).toBe(1);
  expect(writes[0]).toMatchObject({
    method: "POST",
    path: "/api/envs/web/rules",
    body: { rule: { host: "example.com", access: "read" } },
  });
  expect(
    (writes[0].body as { rule: { allow_private?: boolean } }).rule.allow_private,
  ).toBeUndefined();
});

test("open egress shows on the env and its hosts, kept until revoked", async ({ page }) => {
  const writes = await mockApi(page);
  const overview = fixture("overview");
  const until = new Date(Date.now() + 52 * 60_000 - 5_000).toISOString();
  await page.route(
    (url) => url.pathname === "/api/overview",
    (route) =>
      route.fulfill({
        json: { ...overview, envs: overview.envs.map((e) => ({ ...e, open: { until } })) },
      }),
  );
  const [reached, ...rest] = fixture("egress");
  const egress = [
    {
      ...reached,
      allowed: 2,
      opened: 2,
      denied: 0,
      methods: ["GET", "PUT"],
      last_reason: null,
      last_message: null,
      last_rule: "open",
    },
    ...rest,
  ];
  await page.route(
    (url) => url.pathname === "/api/envs/web/egress",
    (route) => route.fulfill({ json: egress }),
  );
  await open(page);
  const env = page.getByRole("button", { name: /^web/ });
  await expect(env).toContainText("open, 52m");
  await env.click();

  const row = page.getByRole("row", { name: /example\.com/ });
  await expect(row.locator(".chip")).toHaveText("open");
  await row.click();
  await expect(page.getByText("let through by open egress")).toBeVisible();
  await page.getByRole("button", { name: "Keep", exact: true }).click();

  await expect.poll(() => writes.length).toBe(1);
  expect(writes[0]).toMatchObject({
    path: "/api/envs/web/rules",
    body: { rule: { host: "example.com", access: "write", note: "kept from open egress" } },
  });
  expect((writes[0].body as { rule: { expires?: string } }).rule.expires).toBeUndefined();
});

test("the env panel shows how to connect", async ({ page }) => {
  await mockApi(page);
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();
  await expect(page.getByText("luoto open -e web", { exact: true })).toBeVisible();
});

test("a new env waits until its folder's luoto.toml is on screen", async ({ page }) => {
  const writes = await mockApi(page);
  const proposal = fixture("detect");
  let answer = () => {};
  const answered = new Promise<void>((resolve) => (answer = resolve));
  await page.route("**/api/detect", async (route) => {
    await answered;
    await route.fulfill({ json: proposal });
  });
  await open(page);
  await page.getByRole("button", { name: "New env" }).click();

  const folder = page.getByPlaceholder("~/dev/my-project");
  await folder.fill("~/dev/api");
  const create = page.getByRole("button", { name: "Create", exact: true });
  await expect(create).toBeDisabled();
  await folder.press("Enter");

  answer();
  await expect(page.getByText("api.stripe.com (read)")).toBeVisible();
  await expect(create).toBeEnabled();
  expect(writes).toHaveLength(0);
  await create.click();

  await expect.poll(() => writes.length).toBe(1);
  expect(writes[0]).toMatchObject({
    path: "/api/envs",
    body: { dir: "~/dev/api", project_sha: proposal.project_sha },
  });
});

test("an env cloned from a remote shows where it comes from and pulls only in a terminal", async ({
  page,
}) => {
  await mockApi(page);
  const overview = fixture("overview");
  await page.route(
    (url) => url.pathname === "/api/overview",
    (route) =>
      route.fulfill({ json: { ...overview, envs: [...overview.envs, fixture("remote")] } }),
  );
  const detail = { ...fixture("env"), name: "api", path: "/home/me/.config/luoto/envs/api.toml" };
  await page.route(
    (url) => url.pathname === "/api/envs/api",
    (route) => route.fulfill({ json: detail }),
  );
  await page.route(
    (url) => /^\/api\/envs\/api\/(egress|requests)$/.test(url.pathname),
    (route) => route.fulfill({ json: [] }),
  );
  await page.route(
    (url) => url.pathname === "/api/envs/api/project",
    (route) =>
      route.fulfill({
        json: {
          ...fixture("project"),
          state: "unread",
          accepted: [["presets", "npm"]],
        },
      }),
  );
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();
  await expect(page.getByRole("button", { name: "Pull changes…" })).toBeVisible();

  await page.getByRole("button", { name: /^api/ }).click();
  await expect(page.getByText("cloned from", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("acme/api", { exact: true })).toBeVisible();
  await expect(page.getByText("(develop)")).toBeVisible();
  await expect(page.getByText("luoto pull -e api --to <new folder>")).toBeVisible();
  await expect(page.getByRole("button", { name: "Pull changes…" })).toHaveCount(0);
  await expect(page.getByText(/in the env's clone, read when it starts/)).toBeVisible();
});

test("a remote in the new-env dialog is made in a terminal", async ({ page }) => {
  const writes = await mockApi(page);
  await page.route("**/api/detect", (route) =>
    route.fulfill({
      json: {
        ...fixture("detect"),
        name: "web",
        remote: "acme/web",
        presets: [],
        tools: [],
        project: null,
        project_sha: null,
      },
    }),
  );
  await open(page);
  await page.getByRole("button", { name: "New env" }).click();
  await page.getByPlaceholder("~/dev/my-project").fill("acme/web");

  await expect(page.getByText("luoto init acme/web")).toBeVisible();
  await expect(page.getByRole("button", { name: "Create", exact: true })).toBeDisabled();
  expect(writes).toHaveLength(0);
});

test("applying luoto.toml names the text that was reviewed", async ({ page }) => {
  await mockApi(page);
  const status = {
    state: "new",
    accepted: [],
    current: [["allow", "api.stripe.com (read)"]],
    diff: [],
    error: null,
    needs: [],
    sha: "ab".repeat(32),
  };
  const posted: unknown[] = [];
  await page.route("**/api/envs/web/project", async (route, req) => {
    if (req.method() === "POST") posted.push(req.postDataJSON());
    await route.fulfill({ json: status });
  });
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();
  await page.getByRole("button", { name: "Apply", exact: true }).click();

  await expect.poll(() => posted).toEqual([{ action: "accept", sha: status.sha }]);
});

test("a TLS reject hints at a tunnel without choosing one", async ({ page }) => {
  const writes = await mockApi(page);
  const [blocked] = fixture("egress");
  await page.route(
    (url) => url.pathname === "/api/envs/web/egress",
    (route) =>
      route.fulfill({ json: [{ ...blocked, host: "pinned.example", tls_rejected: true }] }),
  );
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();
  await page.getByRole("row", { name: /pinned\.example/ }).click();

  await expect(page.getByText(/rejected our certificate/)).toBeVisible();
  await expect(page.getByRole("switch", { name: "opaque tunnel" })).toHaveAttribute(
    "aria-checked",
    "false",
  );
  await page.getByRole("button", { name: "Allow", exact: true }).click();

  await expect.poll(() => writes.length).toBe(1);
  const body = writes[0].body as { rule: { host: string; access: string; mode?: string } };
  expect(body.rule).toMatchObject({ host: "pinned.example", access: "read" });
  expect(body.rule.mode).toBeUndefined();
});

test("a name the gate found private offers a private rule, off until chosen", async ({ page }) => {
  const writes = await mockApi(page);
  const [blocked] = fixture("egress");
  await page.route(
    (url) => url.pathname === "/api/envs/web/egress",
    (route) =>
      route.fulfill({
        json: [{ ...blocked, host: "kb.example", last_reason: "private_address" }],
      }),
  );
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();
  await page.getByRole("row", { name: /kb\.example/ }).click();

  const private_ = page.getByRole("switch", { name: "allow private address" });
  await expect(private_).toHaveAttribute("aria-checked", "false");
  await expect(page.getByText(/without this, the rule doesn't reach it/)).toBeVisible();
  await private_.click();
  await page.getByRole("button", { name: "Allow", exact: true }).click();
  // luoto reports the rule's risk; the one question, then it is saved with the yes.
  const ask = page.getByRole("alertdialog");
  await expect(ask).toContainText("reach private addresses");
  await expect(ask).not.toContainText("private/host addresses");
  await ask.getByRole("button", { name: "Allow", exact: true }).click();

  await expect.poll(() => writes.length).toBe(2);
  expect(writes[1].body).toMatchObject({
    rule: { host: "kb.example", allow_private: true },
    force: true,
  });
});

test("a rule without the private address reads as blocked, naming the rule", async ({ page }) => {
  await mockApi(page);
  const [blocked] = fixture("egress");
  await page.route(
    (url) => url.pathname === "/api/envs/web/egress",
    (route) =>
      route.fulfill({
        json: [
          {
            ...blocked,
            host: "kb.example",
            last_reason: "private_address",
            allowed_not_private: "r1",
          },
        ],
      }),
  );
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();

  const row = page.getByRole("row", { name: /kb\.example/ });
  await expect(row).toContainText("blocked");
  await expect(row).toContainText("rule r1 doesn't allow its private address");
  await row.click();
  await expect(page.getByText(/allows this host, not the private address/)).toBeVisible();
});

test("approving a request whose rule has risks shows them and resends with force", async ({
  page,
}) => {
  await mockApi(page);
  const request = {
    id: 7,
    host: "*.example.com",
    access: "write",
    reason: "upload build artifacts",
    status: "pending",
    created: new Date().toISOString(),
  };
  await page.route(
    (url) => url.pathname === "/api/envs/web/requests",
    (route) => route.fulfill({ json: [request] }),
  );
  const risks = ["a wildcard covers every subdomain"];
  const forced: boolean[] = [];
  await page.route(
    (url) => url.pathname === "/api/envs/web/requests/7/approve",
    (route, req) => {
      const { force, created } = req.postDataJSON() as { force: boolean; created: string };
      expect(created).toBe(request.created);
      forced.push(force);
      return force
        ? route.fulfill({ json: { host: request.host, access: "write" } })
        : route.fulfill({ status: 409, json: { error: "confirm risks", risks } });
    },
  );
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();
  await page.getByRole("button", { name: /access to \*\.example\.com/ }).click();
  await page.getByRole("button", { name: "Approve", exact: true }).click();

  await expect(page.getByText(risks[0])).toBeVisible();
  await page.getByRole("button", { name: "Approve anyway" }).click();

  await expect.poll(() => forced).toEqual([false, true]);
});

test("a port request reads as an uninspected tunnel and needs its risk confirmed", async ({
  page,
}) => {
  await mockApi(page);
  const request = {
    id: 8,
    host: "db.example.com",
    port: 5432,
    access: "write",
    reason: "run the migrations",
    status: "pending",
    created: new Date().toISOString(),
  };
  await page.route(
    (url) => url.pathname === "/api/envs/web/requests",
    (route) => route.fulfill({ json: [request] }),
  );
  const risks = [
    "a tunnel to db.example.com:5432 is not inspected: code in the sandbox gets full access to it, any protocol and any data",
  ];
  const bodies: { force: boolean; narrow?: unknown }[] = [];
  await page.route(
    (url) => url.pathname === "/api/envs/web/requests/8/approve",
    (route, req) => {
      const body = req.postDataJSON() as { force: boolean; narrow?: unknown };
      bodies.push(body);
      return body.force
        ? route.fulfill({ json: { host: request.host, port: 5432, mode: "tunnel" } })
        : route.fulfill({ status: 409, json: { error: "confirm risks", risks } });
    },
  );
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();
  await page.getByRole("button", { name: /tunnel to db\.example\.com:5432/ }).click();

  await expect(page.getByRole("heading", { name: "db.example.com:5432" })).toBeVisible();
  await expect(page.getByRole("group", { name: "grant" })).toHaveCount(0);
  await page.getByRole("button", { name: "Approve", exact: true }).click();
  await expect(page.getByText(risks[0])).toBeVisible();
  await page.getByRole("button", { name: "Approve anyway" }).click();

  await expect.poll(() => bodies.map((b) => b.force)).toEqual([false, true]);
  expect(bodies.every((b) => b.narrow === undefined)).toBe(true);
});

test("a write request can be approved as read-only on some of its paths", async ({ page }) => {
  await mockApi(page);
  const request = {
    id: 9,
    host: "api.example.com",
    access: "write",
    reason: "post the results",
    status: "pending",
    created: new Date().toISOString(),
  };
  await page.route(
    (url) => url.pathname === "/api/envs/web/requests",
    (route) => route.fulfill({ json: [request] }),
  );
  const sent: unknown[] = [];
  await page.route(
    (url) => url.pathname === "/api/envs/web/requests/9/approve",
    (route, req) => {
      sent.push(req.postDataJSON());
      return route.fulfill({ json: { host: request.host, access: "read", paths: ["/v1/**"] } });
    },
  );
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();
  await page.getByRole("button", { name: /access to api\.example\.com/ }).click();
  await page
    .getByRole("group", { name: "grant" })
    .getByRole("button", { name: "read-only" })
    .click();
  await expect(page.getByText(/Write access lets anything/)).toHaveCount(0);
  await page.getByRole("textbox", { name: "paths" }).fill("/v1/**");
  await page.getByRole("button", { name: "Approve", exact: true }).click();

  await expect.poll(() => sent.length).toBe(1);
  expect(sent[0]).toMatchObject({
    created: request.created,
    narrow: { read: true, paths: ["/v1/**"] },
  });
});

test("a tunnel request reaches a private address only when that is picked", async ({ page }) => {
  await mockApi(page);
  const request = {
    id: 10,
    host: "k8s.internal.example",
    port: 7443,
    access: "write",
    reason: "the cluster API, on my VPN",
    status: "pending",
    created: new Date().toISOString(),
  };
  await page.route(
    (url) => url.pathname === "/api/envs/web/requests",
    (route) => route.fulfill({ json: [request] }),
  );
  const looked: string[] = [];
  await page.route(
    (url) => url.pathname === "/api/resolve",
    (route, req) => {
      looked.push(req.url());
      return route.fulfill({ json: { private: [], never: false } });
    },
  );
  const sent: unknown[] = [];
  await page.route(
    (url) => url.pathname === "/api/envs/web/requests/10/approve",
    (route, req) => {
      sent.push(req.postDataJSON());
      return route.fulfill({
        json: { host: request.host, port: 7443, mode: "tunnel", allow_private: true },
      });
    },
  );
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();
  await page.getByRole("button", { name: /k8s\.internal\.example/ }).click();
  const private_ = page.getByRole("switch", { name: "allow private address" });
  await expect(private_).toHaveAttribute("aria-checked", "false");
  await private_.click();
  await page.getByRole("button", { name: "Approve", exact: true }).click();

  await expect.poll(() => sent.length).toBe(1);
  expect(sent[0]).toMatchObject({ created: request.created, private: true });
  // The sandbox chose the name: this machine never looks it up before it is approved.
  expect(looked).toEqual([]);
});

test("selected requests are approved together, each as it was shown", async ({ page }) => {
  await mockApi(page);
  const created = new Date().toISOString();
  const requests = [
    { id: 3, host: "a.example", access: "read", reason: "docs", status: "pending", created },
    {
      id: 4,
      host: "",
      access: "read",
      reason: "tests need it",
      status: "pending",
      created,
      install: { kind: "package", name: "jq" },
    },
  ];
  await page.route(
    (url) => url.pathname === "/api/envs/web/requests",
    (route) => route.fulfill({ json: requests }),
  );
  const sent: { id: string; body: unknown }[] = [];
  await page.route(
    (url) => /^\/api\/envs\/web\/requests\/\d+\/approve$/.test(url.pathname),
    (route, req) => {
      sent.push({ id: new URL(req.url()).pathname.split("/")[5], body: req.postDataJSON() });
      return route.fulfill({ json: { installed: "installed" } });
    },
  );
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();
  await page.getByRole("checkbox", { name: "select all" }).check();
  await page.getByRole("button", { name: "Approve 2" }).click();

  await expect.poll(() => sent.length).toBe(2);
  expect(sent[0]).toMatchObject({ id: "3", body: { created, ttl: "60m" } });
  expect(sent[1]).toMatchObject({ id: "4", body: { created } });
  expect((sent[1].body as { ttl?: string }).ttl).toBeUndefined();
});

test("a variable request takes a value, the one it suggests filled in", async ({ page }) => {
  await mockApi(page);
  const created = new Date().toISOString();
  const asked = { host: "", access: "read", status: "pending", created };
  const requests = [
    { ...asked, id: 5, reason: "the app reads it", install: { kind: "var", name: "APP_MODE" } },
    {
      ...asked,
      id: 6,
      reason: "more logs",
      install: { kind: "var", name: "RUST_LOG", value: "debug" },
    },
  ];
  await page.route(
    (url) => url.pathname === "/api/envs/web/requests",
    (route) => route.fulfill({ json: requests }),
  );
  const sent: { id: string; body: unknown }[] = [];
  await page.route(
    (url) => /^\/api\/envs\/web\/requests\/\d+\/approve$/.test(url.pathname),
    (route, req) => {
      sent.push({ id: new URL(req.url()).pathname.split("/")[5], body: req.postDataJSON() });
      return route.fulfill({ json: { installed: "set" } });
    },
  );
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();
  // A variable request takes a value of its own: none is ticked for a batch.
  await expect(page.getByRole("checkbox", { name: "select all" })).toHaveCount(0);

  await page.getByRole("button", { name: /the variable APP_MODE/ }).click();
  const value = page.getByRole("textbox", { name: "value" });
  await expect(value).toHaveValue("");
  await page.getByRole("button", { name: "Approve" }).click();
  await expect(page.getByText("give the value first")).toBeVisible();
  await expect(value).toBeFocused();
  expect(sent).toHaveLength(0);
  await value.fill("staging");
  await value.press("Enter");
  await expect.poll(() => sent.length).toBe(1);
  expect(sent[0]).toEqual({ id: "5", body: { created, var: "staging" } });

  // On to the next request, its suggested value filled in and shown as the sandbox's.
  await expect(page.getByText("variable request #6")).toBeVisible();
  await expect(value).toHaveValue("debug");
  await expect(page.getByText("value it suggests — written by code in the sandbox")).toBeVisible();
  await page.getByRole("button", { name: "Approve" }).click();
  await expect.poll(() => sent.length).toBe(2);
  expect(sent[1]).toEqual({ id: "6", body: { created, var: "debug" } });
});

test("the env panel lists its variables, a secret by where it is kept", async ({ page }) => {
  await mockApi(page);
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();

  await expect(page.getByText("RUST_LOG", { exact: true })).toBeVisible();
  await expect(page.getByText("debug", { exact: true })).toBeVisible();
  await expect(page.getByText("op://Dev/local-db/url")).toBeVisible();
  await expect(page.getByText("Any code in the env can read them.")).toBeVisible();
  await expect(page.getByText("set by luoto: GIT_TERMINAL_PROMPT")).toBeVisible();
});

test("the env panel shows its shares, what changed on this machine, and syncs them", async ({
  page,
}) => {
  const writes = await mockApi(page);
  await page.route(
    (url) => url.pathname === "/api/envs/web/shares",
    async (route, req) => {
      if (req.method() === "POST") {
        writes.push({ method: "POST", path: "/api/envs/web/shares", body: null });
        await route.fulfill({
          json: {
            said: ["share recordings: 1 file(s) updated; 3 file(s), 1.5 GB in all"],
            failed: false,
          },
        });
        return;
      }
      const synced = writes.some((w) => w.path === "/api/envs/web/shares");
      const view = fixture("shares");
      if (synced) view.shares[0].changed = 0;
      await route.fulfill({ json: view });
    },
  );
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();

  await expect(page.getByText("/shares/recordings")).toBeVisible();
  await expect(page.getByText("1 changed on this machine since the last sync")).toBeVisible();
  await page.getByRole("button", { name: "Sync", exact: true }).click();
  await expect(page.getByText("3 files, 1.5 GB, up to date")).toBeVisible();
  await expect(page.getByText("share recordings: 1 file(s) updated")).toBeVisible();
});

test("the vault is a view of every env's credentials, each with how to change it", async ({
  page,
}) => {
  await mockApi(page);
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();
  await page.getByRole("button", { name: "no secrets in use" }).click();

  // The surface is the vault now, not the env's egress.
  await expect(page.getByRole("heading", { name: "vault", exact: true })).toBeVisible();
  await expect(page.getByText("web egress")).toHaveCount(0);
  const github = page.getByRole("row", { name: /github/ });
  await expect(github).toContainText("keyring:luoto/github-pat");
  await expect(page.getByRole("row", { name: /custom\.billing/ })).toContainText("missing");
  await expect(page.getByRole("row", { name: /op:\/\/Old\/retired/ })).toContainText("unused");

  await github.click();
  await expect(page.getByText("web: github")).toBeVisible();
  await expect(
    page.getByRole("button", { name: /luoto repo auth -e web acme\/web/ }),
  ).toBeVisible();
  await page.getByRole("row", { name: /custom\.billing/ }).click({ button: "right" });
  await expect(page.getByRole("menuitem", { name: /Copy change command/ })).toBeDisabled();
  await page.keyboard.press("Escape");
  await page.keyboard.press("Escape");
  await expect(page.getByText("Pick a credential")).toBeVisible();

  // Picking the env brings its egress and panel back.
  await page.getByRole("button", { name: /^web/ }).click();
  await expect(page.getByRole("heading", { name: "vault", exact: true })).toHaveCount(0);
  await expect(page.getByText("set by luoto: GIT_TERMINAL_PROMPT")).toBeVisible();
});

test("the env panel links the ports forwarded from the env", async ({ page }) => {
  await mockApi(page);
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();

  await expect(page.getByRole("link", { name: "http://localhost:5173" })).toHaveAttribute(
    "href",
    "http://localhost:5173",
  );
  await expect(page.getByText("3000 is taken on this machine")).toBeVisible();
  await expect(page.getByText("luoto forward -e web <port>:3000")).toBeVisible();
  // A port picked for a server (a login's callback) is forwarded, folded away.
  const picked = page.getByRole("link", { name: "http://localhost:54815" });
  await expect(picked).toBeHidden();
  await page.getByText("and 1 port picked for a server").click();
  await expect(picked).toBeVisible();
});

test("a new access request notifies once the user turned notifications on", async ({ page }) => {
  // A stand-in for the browser's notifications, and a tab out of sight.
  await page.addInitScript(() => {
    const w = window as unknown as { shown: string[]; asked: number };
    w.shown = [];
    w.asked = 0;
    class Stub {
      static permission = "default";
      static requestPermission = () => {
        w.asked += 1;
        Stub.permission = "granted";
        return Promise.resolve("granted");
      };
      onclick: (() => void) | null = null;
      constructor(title: string) {
        w.shown.push(title);
      }
      close() {}
    }
    Object.defineProperty(window, "Notification", { value: Stub });
    document.hasFocus = () => false;
  });
  await mockApi(page);
  let pending = 0;
  const overview = fixture("overview");
  await page.route(
    (url) => url.pathname === "/api/overview",
    (route) =>
      route.fulfill({
        json: { ...overview, envs: overview.envs.map((e) => ({ ...e, pending })) },
      }),
  );
  await open(page);
  const bell = page.getByRole("button", { name: "browser notifications" });
  await expect(bell).toHaveAttribute("aria-pressed", "false");
  expect(await page.evaluate(() => (window as unknown as { asked: number }).asked)).toBe(0);

  await bell.click();
  await expect(bell).toHaveAttribute("aria-pressed", "true");
  pending = 1;

  await expect
    .poll(() => page.evaluate(() => (window as unknown as { shown: string[] }).shown), {
      timeout: 10_000,
    })
    .toEqual(["luoto: web has a request"]);
});

test("with desktop notifications on, the page shows none of its own", async ({ page }) => {
  await mockApi(page);
  await page.route(
    (url) => url.pathname === "/api/overview",
    (route) => route.fulfill({ json: { ...fixture("overview"), desktop_notifications: true } }),
  );
  await open(page);
  await expect(page.getByRole("button", { name: /^web/ })).toBeVisible();
  await expect(page.getByRole("button", { name: "browser notifications" })).toHaveCount(0);
});

test("an env's disk use is measured when its panel shows and on refresh", async ({ page }) => {
  await mockApi(page);
  let reads = 0;
  await page.route(
    (url) => url.pathname === "/api/disk/envs",
    (route) => {
      reads += 1;
      return route.fulfill({ json: fixture("envDisk") });
    },
  );
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();

  const parts = page.locator("dl.parts");
  await expect(page.getByText("3.0 GB", { exact: true })).toBeVisible();
  await expect(parts).toContainText("workspace");
  await expect(parts).toContainText("2.1 GB");
  await expect(page.getByText("45.5 GB free of 106.8 GB")).toBeVisible();
  await expect(page.getByText(/nearly full/)).toHaveCount(0);
  expect(reads).toBe(1);

  await page.getByRole("button", { name: "measure disk use again" }).click();
  await expect.poll(() => reads).toBe(2);
});

test("a nearly full VM disk is flagged beside the envs, with what frees it", async ({ page }) => {
  await mockApi(page);
  await page.route(
    (url) => url.pathname === "/api/disk",
    (route) =>
      route.fulfill({
        json: {
          ...fixture("disk"),
          space: { size: 106769133568, used: 102569133568, free: 4200000000 },
          low: true,
        },
      }),
  );
  await open(page);
  await expect(page.getByText("4.2 GB free of 106.8 GB")).toBeVisible();
  await expect(page.getByText(/nearly full, and a full disk stops every env/)).toBeVisible();
  await expect(page.getByText(/41 superseded images, up to 18\.3 GB/)).toBeVisible();
  await expect(page.getByText("luoto prune", { exact: true })).toBeVisible();
});

test("first setup lists every runtime, offers the ready ones and runs no install", async ({
  page,
}) => {
  await mockApi(page);
  await page.route(
    (url) => url.pathname === "/api/overview",
    (route) => route.fulfill({ json: { ...fixture("overview"), envs: [] } }),
  );
  await open(page);

  // Listed in setup's order; one that isn't installed is no choice and links to its own page.
  const radios = page.getByRole("radio");
  await expect(radios).toHaveCount(3);
  const apple = page.getByRole("radio", { name: /Apple's container/ });
  const podman = page.getByRole("radio", { name: /podman/ });
  const docker = page.getByRole("radio", { name: /Docker/ });
  await expect(apple).toBeDisabled();
  await expect(docker).toBeDisabled();
  await expect(podman).toBeChecked();
  await expect(page.getByText("every container is a VM of its own")).toBeVisible();
  await expect(page.getByText("luoto runs on 1.7.1 or later:")).toBeVisible();
  await expect(
    page.getByRole("link", { name: "https://github.com/apple/container/releases" }),
  ).toBeVisible();
  await expect(
    page.getByRole("link", { name: "https://docs.docker.com/engine/install/" }),
  ).toBeVisible();
  await expect(page.getByText("luoto setup --runtime podman")).toBeVisible();

  await expect(page.getByText("recommended")).toHaveCount(0);
  await expect(page.getByRole("button", { name: /Install/ })).toHaveCount(0);
  await expect(page.getByText(/brew|winget|sudo/)).toHaveCount(0);
});

test("setup with several runtimes ready starts at the first and follows the pick", async ({
  page,
}) => {
  await mockApi(page);
  await page.route(
    (url) => url.pathname === "/api/overview",
    (route) => route.fulfill({ json: { ...fixture("overview"), envs: [] } }),
  );
  const base = fixture("setup");
  await page.route(
    (url) => url.pathname === "/api/setup",
    (route) =>
      route.fulfill({
        json: {
          ...base,
          runtimes: base.runtimes.map((o, i) => ({
            ...o,
            status: o.ready ? o.status : "29.1.0",
            ready: true,
            selected: i === 0,
          })),
        },
      }),
  );
  await open(page);

  await expect(page.getByRole("radio", { name: /Apple's container/ })).toBeChecked();
  await expect(page.getByText("luoto setup --runtime container")).toBeVisible();
  await page.getByRole("radio", { name: /Docker/ }).check();
  await expect(page.getByText("luoto setup --runtime docker")).toBeVisible();
  await expect(page.getByRole("link")).toHaveCount(0);
});

test("on Apple's container the status bar and the env say each container is its own VM", async ({
  page,
}) => {
  await mockApi(page);
  await page.route(
    (url) => url.pathname === "/api/overview",
    (route) =>
      route.fulfill({
        json: {
          ...fixture("overview"),
          runtime: "Apple's container 1.7.1: each container its own VM",
        },
      }),
  );
  await page.route(
    (url) => url.pathname === "/api/envs/web",
    (route) =>
      route.fulfill({
        json: {
          ...fixture("env"),
          isolation: "a VM of its own (Apple's container; `isolation` doesn't apply)",
        },
      }),
  );
  await open(page);
  await expect(page.getByText("Apple's container 1.7.1: each container its own VM")).toBeVisible();
  await page.getByRole("button", { name: /^web/ }).click();
  await expect(page.getByText(/isolation: a VM of its own \(Apple's container/)).toBeVisible();
});

test("a pull is reviewed, then written, risky files only when ticked", async ({ page }) => {
  await mockApi(page);
  const applied: unknown[] = [];
  const plan = {
    dir: "/home/me/dev/web",
    repo: null,
    entries: [
      { path: "src/app.ts", change: "changed", size: 120, executable: false, risky: null },
      {
        path: ".git/hooks/pre-commit",
        change: "new",
        size: 40,
        executable: true,
        risky: "git runs it",
      },
      { path: "src/mine.ts", change: "conflict", size: 9, executable: false, risky: null },
    ],
    unchanged: 12,
    yours: 1,
    deleted: ["old.ts"],
    refused: [],
    unread: null,
    based: true,
    head_moved: null,
    digest: "d1",
  };
  await page.route(
    (url) => url.pathname === "/api/envs/web/pull",
    (route, req) => {
      if (req.method() !== "POST") {
        return route.fulfill({ json: { plans: [plan], digest: "all" } satisfies PullPlans });
      }
      applied.push(req.postDataJSON());
      return route.fulfill({
        json: { written: 2, skipped: 0, conflicts: 1, failed: [] } satisfies Pulled,
      });
    },
  );
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();
  await page.getByRole("button", { name: "Pull changes…" }).click();

  await expect(
    page.getByText("3 new or changed, 12 unchanged, 1 changed only in your folder"),
  ).toBeVisible();
  await expect(page.getByText("changed src/app.ts")).toBeVisible();
  await expect(page.getByText("changed in your folder too")).toBeVisible();
  await expect(page.getByText("src/mine.ts")).toBeVisible();
  await expect(page.getByText("1 file deleted in the env, kept in your folder")).toBeVisible();
  await expect(page.getByText("— git runs it")).toBeVisible();
  const risky = page.getByRole("checkbox", { name: "also write risky files" });
  await expect(risky).not.toBeChecked();
  await risky.check();
  await page.getByRole("button", { name: "Write to folder" }).click();

  await expect.poll(() => applied).toEqual([{ digest: "all", include_risky: true }]);
  await expect(page.getByRole("status")).toHaveText("wrote 2 files, kept 1 of yours");
  await expect(page.getByRole("button", { name: "Pull changes…" })).toBeVisible();
});

test("a pull with only risky files writes nothing until they are ticked", async ({ page }) => {
  await mockApi(page);
  const entry = { path: ".envrc", change: "new", size: 9, executable: false, risky: "direnv" };
  await page.route(
    (url) => url.pathname === "/api/envs/web/pull",
    (route) =>
      route.fulfill({
        json: {
          plans: [
            {
              dir: "/d",
              repo: null,
              entries: [entry],
              unchanged: 0,
              yours: 0,
              deleted: [],
              refused: [],
              unread: null,
              based: true,
              head_moved: null,
              digest: "x",
            },
          ],
          digest: "x",
        } satisfies PullPlans,
      }),
  );
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();
  await page.getByRole("button", { name: "Pull changes…" }).click();

  const write = page.getByRole("button", { name: "Write to folder" });
  await expect(write).toBeDisabled();
  await page.getByRole("checkbox", { name: "also write risky files" }).check();
  await expect(write).toBeEnabled();
  await page.getByRole("button", { name: "Cancel" }).click();
  await expect(write).toHaveCount(0);
});

test("a stopped env greys pull and self-test, saying why", async ({ page }) => {
  await mockApi(page);
  await page.route(
    (url) => url.pathname === "/api/envs/web",
    (route) => route.fulfill({ json: { ...fixture("env"), dev: "stopped" } }),
  );
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();

  for (const name of ["Pull changes…", "Self-test"]) {
    const button = page.getByRole("button", { name });
    await expect(button).toBeDisabled();
    await expect(button).toHaveAttribute("title", "start the env first");
  }
});

test("an env that pulls when it stops says so, and its stop says what the pull did", async ({
  page,
}) => {
  await mockApi(page);
  const last = "pulled 2 file(s) from `web` into ~/dev/web";
  const now =
    "pulled 3 file(s) from `web` into ~/dev/web; 1 left for you: `luoto up -e web`, then " +
    "`luoto pull -e web` reviews";
  await page.route(
    (url) => url.pathname === "/api/envs/web",
    (route) =>
      route.fulfill({
        json: {
          ...fixture("env"),
          pull_on_stop: true,
          last_pull: { at: "2026-11-20T10:00:00Z", line: last, incomplete: false },
        },
      }),
  );
  await page.route(
    (url) => url.pathname === "/api/envs/web/down",
    (route) =>
      route.fulfill({
        json: { pull: { at: "2026-11-20T11:00:00Z", line: now, incomplete: true } },
      }),
  );
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();

  await expect(
    page.getByText(/pulls when it stops: what the env changed is written/),
  ).toBeVisible();
  await expect(page.getByText("luoto pull --on-stop off -e web")).toBeVisible();
  await expect(page.getByText(`last pull at a stop: ${last}`)).toBeVisible();

  // Something left to review is said as a problem, in the pull's own words.
  await page.getByRole("button", { name: "Stop", exact: true }).click();
  const status = page.getByRole("status");
  await expect(status).toHaveText(now);
  await expect(status).toHaveClass(/error/);
});

test("an env that doesn't pull when it stops shows no pull of its own", async ({ page }) => {
  await mockApi(page);
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();
  await expect(page.getByText("copied in: the sandbox never writes here")).toBeVisible();
  await expect(page.getByText(/pulls when it stops/)).toHaveCount(0);
  await expect(page.getByText(/last pull at a stop/)).toHaveCount(0);
});

test("the self-test report lists each check, a failure flagged", async ({ page }) => {
  await mockApi(page);
  await page.route(
    (url) => url.pathname === "/api/envs/web/selftest",
    (route) =>
      route.fulfill({
        json: {
          ok: false,
          checks: [
            { name: "egress", ok: true, detail: "example.com refused" },
            { name: "metadata", ok: false, detail: "169.254.169.254 answered" },
          ],
        } satisfies SelftestReport,
      }),
  );
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();
  await page.getByRole("button", { name: "Self-test" }).click();

  await expect(page.getByRole("status")).toHaveText("isolation self-test FAILED");
  const checks = page.locator("ul.checks li");
  await expect(checks.filter({ hasText: "egress" })).toContainText("ok");
  const failed = checks.filter({ hasText: "metadata" });
  await expect(failed).toContainText("FAIL");
  await expect(failed).toContainText("169.254.169.254 answered");
});

test("a rule of yours is revoked by its button or its menu", async ({ page }) => {
  await mockApi(page);
  const env = fixture("env");
  const mine = { origin: "user", access: "read" } as const;
  await page.route(
    (url) => url.pathname === "/api/envs/web",
    (route) =>
      route.fulfill({
        json: {
          ...env,
          rules: [
            { ...mine, id: "u1", host: "api.example.com" },
            { ...mine, id: "u2", host: "cdn.example.com" },
            ...env.rules,
          ],
        },
      }),
  );
  const deleted: string[] = [];
  await page.route(
    (url) => url.pathname.startsWith("/api/envs/web/rules/"),
    (route, req) => {
      deleted.push(`${req.method()} ${new URL(req.url()).pathname}`);
      return route.fulfill({ json: 1 });
    },
  );
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();
  // The env panel counts them; the rules view lists every one.
  await expect(page.getByText("2 of yours")).toBeVisible();
  await page.getByRole("button", { name: "Show rules" }).click();

  await page.getByRole("button", { name: "revoke api.example.com" }).click();
  await expect.poll(() => deleted).toEqual(["DELETE /api/envs/web/rules/u1"]);
  await expect(page.getByRole("status")).toHaveText("revoked api.example.com");

  await page.getByRole("row").filter({ hasText: "cdn.example.com" }).click({ button: "right" });
  await page.getByRole("menuitem", { name: "Revoke" }).click();
  await expect.poll(() => deleted).toHaveLength(2);
  expect(deleted[1]).toBe("DELETE /api/envs/web/rules/u2");

  // A preset's rule is listed under its origin, with nothing to edit or revoke.
  await expect(page.getByRole("region", { name: "preset:debian" })).toBeVisible();
  const preset = page.getByRole("row").filter({ hasText: "deb.debian.org" }).first();
  await expect(preset.getByRole("button")).toHaveCount(0);
  await preset.click({ button: "right" });
  await expect(page.getByRole("menuitem", { name: /Revoke/ })).toBeDisabled();
  await page.keyboard.press("Escape");
  // Its row shows it in the panel, as it is.
  await preset.click();
  await expect(page.getByText("From preset:debian: luoto's own data")).toBeVisible();
  await expect(page.getByRole("button", { name: "Save", exact: true })).toHaveCount(0);
  // Its egress, and back to it: by the button, and by Escape.
  await page.getByRole("button", { name: "Show its egress" }).click();
  await expect(page.getByRole("heading", { name: "deb.debian.org" })).toBeVisible();
  await page.getByRole("button", { name: "Back to the rule" }).click();
  await expect(page.getByText("From preset:debian: luoto's own data")).toBeVisible();
  await page.getByRole("button", { name: "Show its egress" }).click();
  await page.keyboard.press("Escape");
  await expect(page.getByText("From preset:debian: luoto's own data")).toBeVisible();
});

test("attempts alike are one row, newest first, wrapped and expandable", async ({ page }) => {
  await mockApi(page);
  const [blocked] = fixture("egress");
  const long = "/.well-known/oauth-protected-resource/mcp/with/a/rather/long/path";
  const ev = (status: number, ts: string, path: string) => ({
    seq: 1,
    run: "a",
    ts,
    source: null,
    env: "web",
    kind: "http" as const,
    verdict: "allow" as const,
    method: "GET",
    host: "example.com",
    path,
    status,
    message: status === 502 ? "could not connect to example.com:443" : undefined,
  });
  const now = Date.now();
  const at = (minAgo: number) => new Date(now - minAgo * 60_000).toISOString();
  await page.route(
    (url) => url.pathname === "/api/envs/web/events",
    (route) =>
      route.fulfill({
        // Out of order on purpose: the rows sort newest first whatever order they come in.
        json: [
          ev(200, at(52), "/<b>raw</b>"),
          ev(502, at(50), long),
          ev(200, at(6), `${long}?poll=2`),
          ev(502, at(51), long),
          ev(200, at(5), `${long}?poll=3`),
        ],
      }),
  );
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();
  await page.getByRole("row", { name: new RegExp(blocked.host.replace(".", "\\.")) }).click();

  const rows = page.locator(".attempt");
  await expect(rows).toHaveCount(3);
  await expect(rows.nth(0)).toContainText(`GET ${long} 2×`);
  await expect(rows.nth(1)).toContainText("502");
  // Sandbox-written paths are text, never markup.
  await expect(rows.nth(2)).toContainText("GET /<b>raw</b>");

  await rows.nth(1).click();
  await expect(rows.nth(1)).toHaveAttribute("aria-expanded", "true");
  await expect(page.getByText("could not connect to example.com:443")).toBeVisible();
});

test("a host with a rule of yours offers it to edit, not a second allow", async ({ page }) => {
  await mockApi(page);
  const env = fixture("env");
  const mine = { id: "u1", origin: "user", host: "example.com", access: "read" } as const;
  await page.route(
    (url) => url.pathname === "/api/envs/web",
    (route) => route.fulfill({ json: { ...env, rules: [mine, ...env.rules] } }),
  );
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();
  await page.getByRole("row", { name: /example\.com/ }).click();

  await expect(page.getByText("your rule", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Allow", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Add another rule" }).click();
  await expect(page.getByRole("button", { name: "Allow", exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Edit", exact: true }).click();
  await expect(page.getByRole("button", { name: "Save", exact: true })).toBeDisabled();
  // Cancel, and Escape, go back to the host it was opened from.
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(page.getByText("your rule", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  await page.keyboard.press("Escape");
  await expect(page.getByText("your rule", { exact: true })).toBeVisible();
});

test("a rule is added for any host from the rules list", async ({ page }) => {
  const writes = await mockApi(page);
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();
  await page.getByRole("button", { name: "Add rule" }).first().click();

  await expect(page.getByRole("heading", { name: "new rule" })).toBeVisible();
  const allow = page.getByRole("button", { name: "Allow", exact: true });
  await expect(allow).toBeDisabled();
  await page.getByRole("textbox", { name: "host", exact: true }).fill("kb.example");
  await page.getByRole("switch", { name: "allow private address" }).click();
  await allow.click();
  await page.getByRole("alertdialog").getByRole("button", { name: "Allow", exact: true }).click();

  await expect.poll(() => writes.length).toBe(2);
  expect(writes[1]).toMatchObject({
    method: "POST",
    path: "/api/envs/web/rules",
    body: { rule: { host: "kb.example", access: "read", allow_private: true }, force: true },
  });
  // Saved: back to the env.
  await expect(page.getByRole("heading", { name: "new rule" })).toBeHidden();
});

test("a name on a private address gets the private switch on, and Allow asks first", async ({
  page,
}) => {
  const writes = await mockApi(page);
  await page.route(
    (url) => url.pathname === "/api/resolve",
    (route) => route.fulfill({ json: { private: ["10.10.0.8"], never: false } }),
  );
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();
  await page.getByRole("button", { name: "Add rule" }).first().click();
  await page.getByRole("textbox", { name: "host", exact: true }).fill("kb.example");

  const private_ = page.getByRole("switch", { name: "allow private address" });
  await expect(private_).toHaveAttribute("aria-checked", "true");
  await expect(page.getByText("resolves to 10.10.0.8, a private address")).toBeVisible();
  await page.getByRole("button", { name: "Allow", exact: true }).click();
  const ask = page.getByRole("alertdialog");
  await expect(ask).toContainText("reach its private address 10.10.0.8");

  // Without it: saved as a plain rule.
  await ask.getByRole("button", { name: "Allow without private" }).click();
  await expect.poll(() => writes.length).toBe(2);
  const rule = (writes[1].body as { rule: { host: string; allow_private?: boolean } }).rule;
  expect(rule.host).toBe("kb.example");
  expect(rule.allow_private).toBeUndefined();
});

test("a rule of yours is edited in place, its expiry and hidden fields kept", async ({ page }) => {
  await mockApi(page);
  const env = fixture("env");
  const expires = new Date(Date.now() + 38 * 60_000).toISOString();
  const mine = {
    id: "u1",
    origin: "user",
    host: "api.example.com",
    access: "read",
    paths: ["/v1/**"],
    expires,
    idle: "2h",
  } as const;
  await page.route(
    (url) => url.pathname === "/api/envs/web",
    (route) => route.fulfill({ json: { ...env, rules: [mine, ...env.rules] } }),
  );
  const puts: { path: string; body: { rule: Record<string, unknown>; force: boolean } }[] = [];
  await page.route(
    (url) => url.pathname === "/api/envs/web/rules/u1",
    (route, req) => {
      const body = req.postDataJSON() as { rule: Record<string, unknown>; force: boolean };
      puts.push({ path: new URL(req.url()).pathname, body });
      return body.force
        ? route.fulfill({ json: { ...body.rule, id: "u2" } })
        : route.fulfill({ status: 409, json: { error: "risks", risks: ["write to a forge"] } });
    },
  );
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();
  await page.getByRole("button", { name: "rules", exact: true }).click();
  await expect(page.getByText("read-only, /v1/**")).toBeVisible();

  // Escape leaves the form with nothing written.
  await page.getByRole("button", { name: "edit api.example.com" }).click();
  await expect(page.getByRole("heading", { name: "api.example.com" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("heading", { name: "api.example.com" })).toBeHidden();
  expect(puts).toHaveLength(0);

  await page.getByRole("button", { name: "edit api.example.com" }).click();
  await expect(page.getByRole("combobox", { name: "paths" })).toHaveValue("/v1/**");
  await expect(
    page.getByRole("group", { name: "for" }).getByRole("button", { name: "keep" }),
  ).toHaveAttribute("aria-pressed", "true");
  // Nothing changed yet: nothing to save.
  await expect(page.getByRole("button", { name: "Save", exact: true })).toBeDisabled();
  await page.getByRole("button", { name: "write", exact: true }).click();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText("write to a forge")).toBeVisible();
  await page.getByRole("button", { name: "Save anyway" }).click();

  await expect.poll(() => puts.length).toBe(2);
  expect(puts[1].body.force).toBe(true);
  expect(puts[1].body.rule).toMatchObject({
    host: "api.example.com",
    access: "write",
    paths: ["/v1/**"],
    expires,
    idle: "2h",
  });
  expect(puts[1].body.rule.id).toBeUndefined();
});

test("the vault's unlock, reload and lock each report what came of them", async ({ page }) => {
  await mockApi(page);
  const reloaded = {
    read: 3,
    changed: 1,
    failed: ["op://Dev/billing/key: not found"],
    expires: {},
  } satisfies Reloaded;
  await page.route(
    (url) => /^\/api\/vault\/(unlock|lock|reload)$/.test(url.pathname),
    (route, req) =>
      route.fulfill({ json: req.url().endsWith("/reload") ? reloaded : { ok: true } }),
  );
  await open(page);
  await page.getByRole("button", { name: "no secrets in use" }).click();
  const status = page.getByRole("status");

  await page.getByRole("button", { name: "Reload" }).click();
  await expect(status).toHaveText("read 3: 1 changed; not read: op://Dev/billing/key: not found");
  await expect(status).toHaveClass(/error/);

  await page.getByRole("button", { name: "Unlock", exact: true }).click();
  await expect(status).toHaveText("vault unlocked");
  await expect(status).not.toHaveClass(/error/);

  await page.getByRole("button", { name: "Lock", exact: true }).click();
  await expect(status).toHaveText("vault locked; credentialed hosts now get 403");

  // The env list's vault menu does the same.
  await page.getByRole("button", { name: "no secrets in use" }).click({ button: "right" });
  await expect(page.getByRole("menuitem", { name: /Read secrets again/ })).toBeDisabled();
});

test("the env row's menu starts, stops and copies, a denied clipboard said", async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText: () => Promise.reject(new Error("denied")) },
    });
  });
  await mockApi(page);
  const actions: string[] = [];
  await page.route(
    (url) => /^\/api\/envs\/web\/(up|down|open)$/.test(url.pathname),
    (route, req) => {
      actions.push(new URL(req.url()).pathname);
      return route.fulfill({ json: {} });
    },
  );
  await open(page);
  const row = page.getByRole("button", { name: /^web/ });

  await row.click({ button: "right" });
  await expect(page.getByRole("menuitem", { name: /^Start/ })).toBeDisabled();
  await page.getByRole("menuitem", { name: /^Stop/ }).click();
  await expect(page.getByRole("status")).toHaveText("web stopped");
  expect(actions).toEqual(["/api/envs/web/down"]);

  await row.click({ button: "right" });
  await page.getByRole("menuitem", { name: "Open egress for 1 h" }).click();
  await expect.poll(() => actions).toContain("/api/envs/web/open");

  await row.click({ button: "right" });
  await page.getByRole("menuitem", { name: "Copy shell command" }).click();
  await expect(page.getByRole("status")).toHaveText(/denied the clipboard.*luoto shell -e web/);
});

test("a request card's menu approves for an hour, rejects, or opens it", async ({ page }) => {
  await mockApi(page);
  const created = new Date().toISOString();
  const request = { id: 3, host: "a.example", access: "read", reason: "docs", status: "pending" };
  await page.route(
    (url) => url.pathname === "/api/envs/web/requests",
    (route) => route.fulfill({ json: [{ ...request, created }] }),
  );
  const sent: { path: string; body: unknown }[] = [];
  await page.route(
    (url) => /^\/api\/envs\/web\/requests\/3\/(approve|reject)$/.test(url.pathname),
    (route, req) => {
      sent.push({ path: new URL(req.url()).pathname, body: req.postDataJSON() });
      return route.fulfill({ json: { host: "a.example", access: "read" } });
    },
  );
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();
  const card = page.getByRole("listitem").filter({ hasText: "a.example" });

  await card.click({ button: "right" });
  await page.getByRole("menuitem", { name: "Review…" }).click();
  await expect(page.getByText("access request #3")).toBeVisible();

  await card.click({ button: "right" });
  await page.getByRole("menuitem", { name: /^Approve/ }).click();
  await expect.poll(() => sent).toHaveLength(1);
  expect(sent[0]).toMatchObject({
    path: "/api/envs/web/requests/3/approve",
    body: { created, ttl: "60m" },
  });

  await card.click({ button: "right" });
  await page.getByRole("menuitem", { name: "Reject" }).click();
  await expect.poll(() => sent.map((s) => s.path)).toContain("/api/envs/web/requests/3/reject");
});

test("the new-env dialog says why it can't create yet", async ({ page }) => {
  await mockApi(page);
  await open(page);
  await page.getByRole("button", { name: "New env" }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText("pick a folder")).toBeVisible();
  await page.getByPlaceholder("~/dev/my-project").press("Enter");
  await expect(page.getByRole("status")).toHaveText("pick a folder");
});
