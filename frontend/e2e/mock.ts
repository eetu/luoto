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
import shares from "./fixtures/shares";
import vault from "./fixtures/vault";

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
  shares,
  vault,
};

export const fixture = <K extends keyof typeof fixtures>(name: K): (typeof fixtures)[K] =>
  structuredClone(fixtures[name]);

export type Route = {
  method: string;
  path: RegExp;
  body: (req: Request) => unknown;
  /** The status to answer with, 200 unless given. */
  status?: (req: Request) => number;
  /** Never answered: what waits for it stays in its loading state. */
  hang?: boolean;
};

type NewRuleBody = { rule: { allow_private?: boolean }; force?: boolean };

/** As luoto answers a rule that reaches private addresses: its risk, until forced. */
const privateRisk = (req: Request): boolean => {
  const b = req.postDataJSON() as NewRuleBody;
  return !!b.rule.allow_private && !b.force;
};

const routes: Route[] = [
  { method: "GET", path: /^\/api\/overview$/, body: () => fixture("overview") },
  { method: "GET", path: /^\/api\/meta$/, body: () => fixture("meta") },
  { method: "GET", path: /^\/api\/vault$/, body: () => fixture("vault") },
  { method: "GET", path: /^\/api\/setup$/, body: () => fixture("setup") },
  { method: "GET", path: /^\/api\/disk$/, body: () => fixture("disk") },
  { method: "GET", path: /^\/api\/disk\/envs$/, body: () => fixture("envDisk") },
  { method: "GET", path: /^\/api\/envs\/web$/, body: () => fixture("env") },
  { method: "GET", path: /^\/api\/envs\/web\/egress$/, body: () => fixture("egress") },
  { method: "GET", path: /^\/api\/envs\/web\/requests$/, body: () => fixture("requests") },
  { method: "GET", path: /^\/api\/envs\/web\/project$/, body: () => fixture("project") },
  { method: "GET", path: /^\/api\/envs\/web\/shares$/, body: () => fixture("shares") },
  // A public name, unless a test says otherwise.
  { method: "GET", path: /^\/api\/resolve$/, body: () => ({ private: [], never: false }) },
  {
    method: "POST",
    path: /^\/api\/envs\/web\/rules$/,
    body: (req) =>
      privateRisk(req)
        ? {
            error: "the rule has risks",
            risks: ["allows dialing private/host addresses (e.g. services on your machine)"],
          }
        : { ...(req.postDataJSON() as { rule: object }).rule, id: "r1" },
    status: (req) => (privateRisk(req) ? 409 : 200),
  },
];

/**
 * Serve the API from fixtures; returns the bodies of every write the UI made. A route in
 * `overrides` answers in place of the fixtures' route for the same request.
 */
export async function mockApi(
  page: Page,
  overrides: Route[] = [],
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
    const hit = [...overrides, ...routes].find(
      (r) => r.method === req.method() && r.path.test(path),
    );
    if (hit?.hang) return;
    await route.fulfill(
      hit
        ? {
            status: hit.status?.(req) ?? 200,
            contentType: "application/json",
            body: JSON.stringify(hit.body(req)),
          }
        : { status: 404, contentType: "application/json", body: '{"error":"not mocked"}' },
    );
  });
  return writes;
}
