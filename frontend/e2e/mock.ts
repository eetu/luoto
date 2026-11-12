import type { Page, Request } from "@playwright/test";

import detect from "./fixtures/detect";
import disk from "./fixtures/disk";
import egress from "./fixtures/egress";
import env from "./fixtures/env";
import envDisk from "./fixtures/envDisk";
import meta from "./fixtures/meta";
import overview from "./fixtures/overview";
import project from "./fixtures/project";
import remote from "./fixtures/remote";
import requests from "./fixtures/requests";
import setup from "./fixtures/setup";

// Fixtures are real `luoto ui` responses (env renamed to `web`), each checked against its
// generated API type by `yarn typecheck`, so one that drifts from the Rust types fails there.
const fixtures = {
  detect,
  disk,
  egress,
  env,
  envDisk,
  meta,
  overview,
  project,
  remote,
  requests,
  setup,
};

export const fixture = <K extends keyof typeof fixtures>(name: K): (typeof fixtures)[K] =>
  structuredClone(fixtures[name]);

type Route = { method: string; path: RegExp; body: (req: Request) => unknown };

const routes: Route[] = [
  { method: "GET", path: /^\/api\/overview$/, body: () => fixture("overview") },
  { method: "GET", path: /^\/api\/meta$/, body: () => fixture("meta") },
  { method: "GET", path: /^\/api\/setup$/, body: () => fixture("setup") },
  { method: "GET", path: /^\/api\/disk$/, body: () => fixture("disk") },
  { method: "GET", path: /^\/api\/disk\/envs$/, body: () => fixture("envDisk") },
  { method: "GET", path: /^\/api\/envs\/web$/, body: () => fixture("env") },
  { method: "GET", path: /^\/api\/envs\/web\/egress$/, body: () => fixture("egress") },
  { method: "GET", path: /^\/api\/envs\/web\/requests$/, body: () => fixture("requests") },
  { method: "GET", path: /^\/api\/envs\/web\/project$/, body: () => fixture("project") },
  {
    method: "POST",
    path: /^\/api\/envs\/web\/rules$/,
    body: (req) => ({ ...(req.postDataJSON() as { rule: object }).rule, id: "r1" }),
  },
];

/** Serve the API from fixtures; returns the bodies of every write the UI made. */
export async function mockApi(
  page: Page,
): Promise<{ method: string; path: string; body: unknown }[]> {
  const writes: { method: string; path: string; body: unknown }[] = [];
  await page.route("**/api/**", async (route, req) => {
    const path = new URL(req.url()).pathname;
    if (path === "/api/stream") {
      await route.fulfill({ status: 200, contentType: "text/event-stream", body: "" });
      return;
    }
    if (req.method() !== "GET") {
      writes.push({ method: req.method(), path, body: req.postDataJSON() });
    }
    const hit = routes.find((r) => r.method === req.method() && r.path.test(path));
    await route.fulfill(
      hit
        ? { status: 200, contentType: "application/json", body: JSON.stringify(hit.body(req)) }
        : { status: 404, contentType: "application/json", body: '{"error":"not mocked"}' },
    );
  });
  return writes;
}
