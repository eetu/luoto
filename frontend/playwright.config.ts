import { defineConfig } from "@playwright/test";

// Two projects:
// - `ui`: the built SPA against a mocked API (fixtures captured from a real `luoto ui`);
//   deterministic, runs in CI.
// - `showcase`: drives a real `luoto ui` and env (`just shots` sets it up) and writes the
//   README screenshots; needs podman, so it stays out of the test gate.
export default defineConfig({
  testDir: "e2e",
  fullyParallel: true,
  reporter: process.env.CI ? "github" : "list",
  use: { trace: "retain-on-failure" },
  projects: [
    {
      name: "ui",
      testMatch: "ui.spec.ts",
      use: { baseURL: "http://127.0.0.1:4173", viewport: { width: 1280, height: 800 } },
    },
    {
      name: "showcase",
      testMatch: "showcase.spec.ts",
      timeout: 120_000,
      // GitHub shows README images about 850px wide: a narrow window at 2x keeps the text
      // readable there and sharp on high-density screens.
      use: { viewport: { width: 1180, height: 720 }, deviceScaleFactor: 2 },
    },
  ],
  webServer: process.env.LUOTO_UI_URL
    ? undefined
    : {
        // Explicit IPv4: `localhost` resolves to ::1 first, where the URL below never answers.
        command: "yarn build && yarn preview --host 127.0.0.1 --port 4173 --strictPort",
        url: "http://127.0.0.1:4173",
        reuseExistingServer: !process.env.CI,
        timeout: 120_000,
      },
});
