import { execFileSync } from "node:child_process";
import { join } from "node:path";

import { expect, test } from "@playwright/test";

import type { Overview, VaultView } from "../src/lib/types";

// The README screenshots, taken from a real `luoto ui` and env (`just shots` provides both):
// a request blocked, allowed from the UI and through on the retry; then a credential the
// sandbox never sees, injected by the gate from the vault.
const url = process.env.LUOTO_UI_URL;
const bin = process.env.LUOTO_BIN ?? "luoto";
const env = process.env.LUOTO_SHOT_ENV ?? "web";
/** The demo credential's ref (`just shots` sets LUOTO_DEMO_TOKEN). */
const DEMO_REF = "env:LUOTO_DEMO_TOKEN";
const out = (name: string) => join(import.meta.dirname, "..", "..", "docs", "screenshots", name);

test.describe.configure({ mode: "serial" });

/** HTTP status of a request made from inside the sandbox. */
const fetchInside = (target: string) =>
  execFileSync(bin, [
    "shell",
    "-e",
    env,
    "--",
    "curl",
    "-s",
    "-o",
    "/dev/null",
    "-w",
    "%{http_code}",
    target,
  ]).toString();

test("blocked, allowed from the UI, then through", async ({ page }) => {
  test.skip(!url, "needs a running `luoto ui` and env (`just shots`)");
  expect(fetchInside("https://example.com/")).toBe("403");

  for (const scheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme: scheme });
    await page.goto(url!);
    await page.getByRole("button", { name: new RegExp(`^${env}`) }).click();
    const row = page.getByRole("row", { name: /example\.com/ });
    await expect(row).toContainText("blocked", { timeout: 30_000 });
    await row.click();
    await expect(page.getByRole("heading", { name: "example.com" })).toBeVisible();
    await page.screenshot({ path: out(`egress-blocked-${scheme}.png`) });
  }

  await page.emulateMedia({ colorScheme: "light" });
  await page.getByRole("button", { name: "allow", exact: true }).click();
  await expect(page.getByText(/allowed example\.com/)).toBeVisible();
  expect(fetchInside("https://example.com/")).toBe("200");
  // The rule allows what was blocked before it: the row reads as allowed, its denial as history.
  await expect(page.getByRole("row", { name: /example\.com/ })).toContainText(
    "blocked before rule",
    { timeout: 30_000 },
  );
  await page.screenshot({ path: out("egress-allowed.png") });
});

test("a credential the sandbox never sees", async ({ page }) => {
  test.skip(!url, "needs a running `luoto ui` and env (`just shots`)");
  // The sandbox sends no token; httpbin answers 200 only because the gate injected the demo
  // credential (`[credentials.custom.demo]`, a dummy value from LUOTO_DEMO_TOKEN).
  expect(fetchInside("https://httpbin.org/bearer")).toBe("200");

  // The vault is shared by every env on this machine, not just this LUOTO_HOME's: the page
  // gets it (the overview's and the vault view's) with only this env's rows and the demo
  // secret's ref, so no real env names or secret refs reach the README.
  await page.route("**/api/overview", async (route) => {
    const response = await route.fetch();
    const body = (await response.json()) as Overview;
    if (body.vault) {
      body.vault.envs = body.vault.envs.filter((e) => e.env === env);
      body.vault.loaded_refs = body.vault.loaded_refs.filter((r) => r === DEMO_REF);
    }
    await route.fulfill({ response, json: body });
  });
  await page.route("**/api/vault", async (route) => {
    const response = await route.fetch();
    const body = (await response.json()) as VaultView;
    body.credentials = body.credentials.filter((c) => c.env === env);
    body.unused = [];
    if (body.status) {
      body.status.envs = body.status.envs.filter((e) => e.env === env);
      body.status.loaded_refs = body.status.loaded_refs.filter((r) => r === DEMO_REF);
    }
    await route.fulfill({ response, json: body });
  });

  for (const scheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme: scheme });
    await page.goto(url!);
    await page.getByRole("button", { name: new RegExp(`^${env}`) }).click();
    await expect(page.getByRole("row", { name: /httpbin\.org/ })).toContainText("allowed", {
      timeout: 30_000,
    });
    await page.getByRole("button", { name: /unlocked/ }).click();
    await expect(page.getByText("custom.demo")).toBeVisible();
    await page.screenshot({ path: out(`vault-${scheme}.png`) });
  }
});
