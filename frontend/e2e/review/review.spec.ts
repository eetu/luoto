import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { expect, test } from "@playwright/test";

import { mockApi } from "../mock";
import { knownAs } from "./known";
import { type Found, gather, inspect, keyboard } from "./probes";
import { SCENARIOS } from "./scenarios";
import { SETTINGS } from "./settings";
import { OUT, type Result } from "./sheet.ts";

// Every scenario's views under every setting: a screenshot and the probes' findings of each,
// written for the contact sheet. A finding that isn't a known problem fails its test.

for (const dir of ["results", "shots", "thumbs"]) mkdirSync(join(OUT, dir), { recursive: true });

for (const [column, setting] of SETTINGS.entries()) {
  test.describe(setting.name, () => {
    test.use(setting.use);

    for (const [row, scenario] of SCENARIOS.entries()) {
      test(scenario.name, async ({ page }) => {
        // What the page says while a view is up: script errors, and console errors other than
        // the browser's line for a status the scenario answers with on purpose.
        const said: Found[] = [];
        page.on("pageerror", (e) =>
          said.push({ probe: "pageerror", target: "page", detail: e.message }),
        );
        page.on("console", (m) => {
          if (m.type() !== "error") return;
          const status = Number(/status of (\d+)/.exec(m.text())?.[1]);
          if (scenario.statuses?.includes(status)) return;
          const url = m.location().url;
          said.push({
            probe: "console",
            target: url ? new URL(url).pathname : "page",
            detail: m.text(),
          });
        });

        await mockApi(page, scenario.routes);
        await page.goto(`/#token=${"ab".repeat(16)}`);

        const result: Result = {
          scenario: scenario.name,
          about: scenario.about,
          row,
          setting: setting.name,
          settingAbout: setting.about,
          column,
          shots: [],
        };
        for (const view of scenario.views) {
          const found: Found[] = [];
          const opened = await view.open(page).then(
            () => true,
            (e: Error) => {
              found.push({
                probe: "unreachable",
                target: view.name,
                detail: e.message.split("\n")[0],
              });
              return false;
            },
          );
          await page.evaluate(() => document.fonts.ready);
          // The family's reveals take 150 ms.
          await page.waitForTimeout(250);

          const file = `${scenario.name}--${view.name}--${setting.name}`;
          const png = `shots/${file}.png`;
          const jpeg = `thumbs/${file}.jpg`;
          await page.screenshot({ path: join(OUT, png) });
          await page.screenshot({ path: join(OUT, jpeg), type: "jpeg", quality: 55 });

          if (opened) {
            found.push(
              ...(await inspect(page, {
                reducedMotion: setting.use.reducedMotion === "reduce",
                forcedColors: setting.use.forcedColors === "active",
              })),
            );
            found.push(...(await keyboard(page)));
          }
          found.push(...said.splice(0));
          const where = `${scenario.name}/${view.name}/${setting.name}`;
          result.shots.push({
            view: view.name,
            png,
            jpeg,
            violations: gather(found).map((v) => ({ ...v, known: knownAs(v, where)?.reason })),
          });
          // A view that didn't open may have left a dialog up, which the next can't get past.
          if (!opened) await page.keyboard.press("Escape");
        }
        writeFileSync(
          join(OUT, "results", `${scenario.name}--${setting.name}.json`),
          JSON.stringify(result, null, 1),
        );

        const fresh = result.shots.flatMap((s) =>
          s.violations
            .filter((v) => !v.known)
            .map((v) => `${s.view}: ${v.probe} on ${v.target}: ${v.detail}`),
        );
        expect(fresh, "findings that e2e/review/known.ts doesn't list").toEqual([]);
      });
    }
  });
}
