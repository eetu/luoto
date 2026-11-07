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
  const proposal = fixture("detect") as { project_sha: string };
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
  const [blocked] = fixture("egress") as object[];
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
