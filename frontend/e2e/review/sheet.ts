import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { KNOWN } from "./known.ts";
import type { Violation } from "./probes.ts";

// The contact sheet: every render of a review run in one HTML file, a scenario's views down
// and the settings across, each with what the probes found on it. Read by Node as it is
// (`claude.ts`), so its imports name their files and its syntax is types only.

/** Where a review run writes: `results/`, `shots/`, `thumbs/`, then `index.html`. */
export const OUT = fileURLToPath(new URL("../../playwright-report/review/", import.meta.url));

/** A finding, with the reason of the known problem it is. */
export type Judged = Violation & { known?: string };

export type Shot = { view: string; png: string; jpeg: string; violations: Judged[] };

/** One scenario under one setting: a test's result, as `results/<scenario>--<setting>.json`. */
export type Result = {
  scenario: string;
  about: string;
  /** Its place among the scenarios, and its setting's among the settings. */
  row: number;
  setting: string;
  settingAbout: string;
  column: number;
  shots: Shot[];
};

/** What Claude suspects of a screenshot, by its `png`: `claude.json`. */
export type Suspicions = Record<string, { severity: string; problem: string; rule: string }[]>;

export const readResults = (): Result[] => {
  const dir = join(OUT, "results");
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .map((f) => JSON.parse(readFileSync(join(dir, f), "utf8")) as Result)
    .sort((a, b) => a.row - b.row || a.column - b.column);
};

const esc = (s: string): string =>
  s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c] ?? c);

const STYLE = `
:root { color-scheme: light dark; --bg: #f4f4f4; --card: #fff; --text: #222; --muted: #767676;
  --line: #e2e2e2; --accent: #f78f08; --bad: #c62828; }
@media (prefers-color-scheme: dark) { :root { --bg: #1b1b1b; --card: #262626; --text: #e8e8e8;
  --muted: #9a9a9a; --line: #3a3a3a; --bad: #ff8a80; } }
body { margin: 0; padding: 20px; background: var(--bg); color: var(--text);
  font: 13px/1.4 Inter, system-ui, sans-serif; }
h1 { margin: 0; font-size: 18px; } h1 b { color: var(--accent); }
h2 { margin: 28px 0 2px; font-size: 15px; }
p { margin: 2px 0 10px; } .muted, figcaption small { color: var(--muted); }
.scroll { overflow-x: auto; }
table { border-collapse: separate; border-spacing: 8px; }
th { color: var(--muted); font-size: 11px; font-weight: 500; text-align: left;
  text-transform: uppercase; letter-spacing: 0.04em; }
th[scope=row] { min-width: 80px; vertical-align: top; }
td { width: 230px; min-width: 230px; padding: 8px; border-radius: 6px; background: var(--card);
  vertical-align: top; }
td.new { outline: 2px solid var(--bad); }
figure { margin: 0; } img { display: block; max-width: 100%; max-height: 190px; margin: 0 auto;
  border: 1px solid var(--line); cursor: zoom-in; }
ul { margin: 6px 0 0; padding: 0; list-style: none; font-size: 11px; }
li { margin-top: 3px; overflow-wrap: anywhere; }
li.new { color: var(--bad); } li.known { color: var(--muted); }
li.claude::before { content: "claude "; color: var(--accent); }
code { font: 11px ui-monospace, Menlo, monospace; }
.backlog td { width: auto; min-width: 0; }
dialog { max-width: 96vw; max-height: 96vh; padding: 0; border: 0; }
dialog img { max-height: 96vh; cursor: zoom-out; }
`;

const SCRIPT = `
const zoom = document.querySelector("dialog");
document.addEventListener("click", (e) => {
  if (zoom.open) return zoom.close();
  if (!e.target.matches("td img")) return;
  zoom.querySelector("img").src = e.target.src;
  zoom.showModal();
});
`;

const finding = (v: Judged): string =>
  `<li class="${v.known ? "known" : "new"}" title="${esc(v.known ?? "new")}"><code>${esc(v.probe)}</code> ${esc(v.target)}${v.count > 1 ? ` ×${v.count}` : ""}: ${esc(v.detail)}</li>`;

const cell = (shot: Shot | undefined, suspicions: Suspicions): string => {
  if (!shot) return "<td></td>";
  const fresh = shot.violations.some((v) => !v.known);
  const jpeg = readFileSync(join(OUT, shot.jpeg)).toString("base64");
  const suspected = (suspicions[shot.png] ?? []).map(
    (s) =>
      `<li class="claude" title="${esc(s.rule)}"><code>${esc(s.severity)}</code> ${esc(s.problem)}</li>`,
  );
  return `<td${fresh ? ' class="new"' : ""}><figure>
<img loading="lazy" alt="" src="data:image/jpeg;base64,${jpeg}">
<figcaption><small>${esc(shot.png)}</small><ul>${[...shot.violations.map(finding), ...suspected].join("")}</ul></figcaption>
</figure></td>`;
};

/** A scenario's table: a row per view, a column per setting. */
const section = (results: Result[], suspicions: Suspicions): string => {
  const [{ scenario, about }] = results;
  const views = [...new Set(results.flatMap((r) => r.shots.map((s) => s.view)))];
  const head = results.map((r) => `<th>${esc(r.setting)}<br>${esc(r.settingAbout)}</th>`).join("");
  const rows = views.map(
    (view) =>
      `<tr><th scope="row">${esc(view)}</th>${results
        .map((r) =>
          cell(
            r.shots.find((s) => s.view === view),
            suspicions,
          ),
        )
        .join("")}</tr>`,
  );
  return `<h2>${esc(scenario)}</h2><p class="muted">${esc(about)}</p>
<div class="scroll"><table><tr><th></th>${head}</tr>${rows.join("")}</table></div>`;
};

/** The known problems, each with how many renders had it; then the ones no render had. */
const backlog = (results: Result[]): string => {
  const seen = new Map<string, number>();
  for (const shot of results.flatMap((r) => r.shots)) {
    for (const v of shot.violations) {
      if (v.known) seen.set(v.known, (seen.get(v.known) ?? 0) + 1);
    }
  }
  const rows = KNOWN.map(
    (k) =>
      `<tr><td><code>${esc(k.probe)}</code></td><td>${esc(String(k.target))}</td><td>${esc(k.reason)}</td><td>${seen.get(k.reason) ?? "not seen in this run"}</td></tr>`,
  );
  return `<h2>known problems</h2><p class="muted">skipped by the probes (e2e/review/known.ts), with the renders each was found in</p>
<div class="scroll"><table class="backlog">${rows.join("")}</table></div>`;
};

/** Write `index.html` from the run's results; returns its path and how many findings are new. */
export function writeSheet(): { path: string; renders: number; fresh: number } {
  const results = readResults();
  const claude = join(OUT, "claude.json");
  const suspicions = existsSync(claude)
    ? (JSON.parse(readFileSync(claude, "utf8")) as Suspicions)
    : {};
  const shots = results.flatMap((r) => r.shots);
  const fresh = shots.flatMap((s) => s.violations).filter((v) => !v.known).length;
  const suspected = Object.values(suspicions).flat().length;
  const scenarios = [...new Set(results.map((r) => r.scenario))];
  const html = `<!doctype html><meta charset="utf-8"><title>luoto UI review</title><style>${STYLE}</style>
<h1>luoto<b>.</b> UI review</h1>
<p class="muted">${shots.length} renders of ${scenarios.length} scenarios, ${new Date().toLocaleString()}:
${fresh} new findings (red)${suspected ? `, ${suspected} suspected by Claude` : ""}. Click a render to enlarge it.</p>
${scenarios
  .map((s) =>
    section(
      results.filter((r) => r.scenario === s),
      suspicions,
    ),
  )
  .join("\n")}
${backlog(results)}
<dialog><img alt=""></dialog><script>${SCRIPT}</script>`;
  const path = join(OUT, "index.html");
  writeFileSync(path, html);
  return { path, renders: shots.length, fresh };
}
