import { expect, test } from "@playwright/test";

import { fixture, mockApi } from "./mock";

const open = (page: import("@playwright/test").Page) => page.goto(`/#token=${"ab".repeat(16)}`);

test("a blocked host is allowed from the egress view", async ({ page }) => {
  const writes = await mockApi(page);
  await open(page);
  await page.getByRole("button", { name: /^web/ }).click();

  const blocked = page.getByRole("row", { name: /example\.com/ });
  await expect(blocked).toContainText("blocked");
  await expect(page.getByRole("row", { name: /deb\.debian\.org/ })).toContainText("allowed");

  await blocked.click();
  await expect(page.getByRole("heading", { name: "example.com" })).toBeVisible();
  await page.getByRole("button", { name: "allow", exact: true }).click();

  await expect.poll(() => writes.length).toBe(1);
  expect(writes[0]).toMatchObject({
    method: "POST",
    path: "/api/envs/web/rules",
    body: { rule: { host: "example.com", access: "read" } },
  });
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
  await page.getByRole("button", { name: "new env" }).click();

  const folder = page.getByPlaceholder("~/dev/my-project");
  await folder.fill("~/dev/api");
  const create = page.getByRole("button", { name: "create", exact: true });
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
    (route) => route.fulfill({ json: { ...overview, envs: [...overview.envs, fixture("remote")] } }),
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
  await expect(page.getByRole("button", { name: "pull changes…" })).toBeVisible();

  await page.getByRole("button", { name: /^api/ }).click();
  await expect(page.getByText("cloned from", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("acme/api", { exact: true })).toBeVisible();
  await expect(page.getByText("(develop)")).toBeVisible();
  await expect(page.getByText("luoto pull --to <new folder>")).toBeVisible();
  await expect(page.getByRole("button", { name: "pull changes…" })).toHaveCount(0);
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
  await page.getByRole("button", { name: "new env" }).click();
  await page.getByPlaceholder("~/dev/my-project").fill("acme/web");

  await expect(page.getByText("luoto init acme/web")).toBeVisible();
  await expect(page.getByRole("button", { name: "create", exact: true })).toBeDisabled();
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
  await page.getByRole("button", { name: "apply", exact: true }).click();

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
  await page.getByRole("button", { name: "allow", exact: true }).click();

  await expect.poll(() => writes.length).toBe(1);
  const body = writes[0].body as { rule: { host: string; access: string; mode?: string } };
  expect(body.rule).toMatchObject({ host: "pinned.example", access: "read" });
  expect(body.rule.mode).toBeUndefined();
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
  await page.getByRole("button", { name: "approve", exact: true }).click();

  await expect(page.getByText(risks[0])).toBeVisible();
  await page.getByRole("button", { name: "approve anyway" }).click();

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
  await page.getByRole("button", { name: "approve", exact: true }).click();
  await expect(page.getByText(risks[0])).toBeVisible();
  await page.getByRole("button", { name: "approve anyway" }).click();

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
  await page.getByRole("button", { name: "approve", exact: true }).click();

  await expect.poll(() => sent.length).toBe(1);
  expect(sent[0]).toMatchObject({
    created: request.created,
    narrow: { read: true, paths: ["/v1/**"] },
  });
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
  await page.getByRole("button", { name: "approve 2" }).click();

  await expect.poll(() => sent.length).toBe(2);
  expect(sent[0]).toMatchObject({ id: "3", body: { created, ttl: "60m" } });
  expect(sent[1]).toMatchObject({ id: "4", body: { created } });
  expect((sent[1].body as { ttl?: string }).ttl).toBeUndefined();
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
    .toEqual(["luoto: web asks for access"]);
});

test("with desktop notifications on, the page shows none of its own", async ({ page }) => {
  await mockApi(page);
  await page.route(
    (url) => url.pathname === "/api/overview",
    (route) =>
      route.fulfill({ json: { ...fixture("overview"), desktop_notifications: true } }),
  );
  await open(page);
  const bell = page.getByRole("button", { name: "browser notifications" });
  await expect(bell).toBeDisabled();
  await expect(bell).toHaveAttribute("title", /notifications = false/);
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
  await expect(page.getByText(/41 superseded image\(s\), up to 18\.3 GB/)).toBeVisible();
  await expect(page.getByText("luoto prune", { exact: true })).toBeVisible();
});
