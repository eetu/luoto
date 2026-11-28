import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import Anthropic from "@anthropic-ai/sdk";

import { OUT, readResults, type Suspicions, writeSheet } from "./sheet.ts";

// The optional Claude pass over a review run: the run's screenshots go to the Anthropic
// Messages API with `rubric.md`, a scenario at a time, and what it suspects joins the contact
// sheet. `node e2e/review/claude.ts [--dry-run]`; `--dry-run` builds the requests and sends
// none.

const MODEL = process.env.LUOTO_REVIEW_MODEL ?? "claude-opus-5-5";
const DRY = process.argv.includes("--dry-run");
/** Credentials the SDK finds: a key or token in the environment, or an `ant auth login` profile. */
const SIGNED_IN =
  !!process.env.ANTHROPIC_API_KEY ||
  !!process.env.ANTHROPIC_AUTH_TOKEN ||
  !!process.env.ANTHROPIC_PROFILE ||
  existsSync(join(homedir(), ".config", "anthropic"));
/** Screenshots per request. */
const BATCH = 20;
// Under reduced motion a still frame is the 1280-light one again.
const SKIP = ["motion"];
/** The models that take a server-side fallback for a request their safety classifiers decline. */
const FALLBACKS = /^claude-(opus-5|fable-5|sonnet-5-5)/;

const SCHEMA = {
  type: "object",
  properties: {
    findings: {
      type: "array",
      items: {
        type: "object",
        properties: {
          image: { type: "integer", description: "The number the image was labelled with." },
          severity: { type: "string", enum: ["high", "medium", "low"] },
          problem: { type: "string" },
          rule: { type: "string" },
        },
        required: ["image", "severity", "problem", "rule"],
        additionalProperties: false,
      },
    },
  },
  required: ["findings"],
  additionalProperties: false,
};

type Image = { png: string; label: string };
type Batch = { scenario: string; about: string; images: Image[] };
type Finding = { image: number; severity: string; problem: string; rule: string };

const batches = (): Batch[] => {
  const by = new Map<string, Batch>();
  for (const r of readResults()) {
    if (SKIP.includes(r.setting)) continue;
    const batch = by.get(r.scenario) ?? { scenario: r.scenario, about: r.about, images: [] };
    by.set(r.scenario, batch);
    for (const shot of r.shots) {
      batch.images.push({
        png: shot.png,
        label: `${r.scenario} / ${shot.view} / ${r.setting} (${r.settingAbout})`,
      });
    }
  }
  return [...by.values()].flatMap((b) =>
    Array.from({ length: Math.ceil(b.images.length / BATCH) }, (_, i) => ({
      ...b,
      images: b.images.slice(i * BATCH, (i + 1) * BATCH),
    })),
  );
};

const body = (batch: Batch, rubric: string) => ({
  model: MODEL,
  max_tokens: 16_000,
  system: rubric,
  output_config: { effort: "high", format: { type: "json_schema", schema: SCHEMA } },
  ...(FALLBACKS.test(MODEL)
    ? { betas: ["server-side-fallback-2026-07-01"], fallbacks: "default" }
    : {}),
  messages: [
    {
      role: "user",
      content: [
        { type: "text", text: `Scenario \`${batch.scenario}\`: ${batch.about}.` },
        ...batch.images.flatMap((image, i) => [
          { type: "text", text: `Image ${i + 1}: ${image.label}` },
          {
            type: "image",
            source: {
              type: "base64",
              media_type: "image/png",
              data: readFileSync(join(OUT, image.png)).toString("base64"),
            },
          },
        ]),
        { type: "text", text: "Report the UX problems these screenshots show, by the rubric." },
      ],
    },
  ],
});

/** Send one request, streamed, and return the text of its answer. */
async function ask(client: Anthropic, request: ReturnType<typeof body>): Promise<string> {
  const message = await client.beta.messages.stream(request).finalMessage();
  if (message.stop_reason !== "end_turn") {
    const why = message.stop_details?.explanation ?? "";
    throw new Error(`stopped with ${message.stop_reason ?? "no stop reason"} ${why}`.trim());
  }
  let text = "";
  for (const block of message.content) {
    // A fallback block is where another model took the request over: its answer starts anew.
    if (block.type === "fallback") text = "";
    if (block.type === "text") text += block.text;
  }
  return text;
}

async function main(): Promise<void> {
  if (!DRY && !SIGNED_IN) {
    console.log(
      "no Anthropic credentials (ANTHROPIC_API_KEY, or `ant auth login`): no screenshots " +
        "sent, the contact sheet is as it was",
    );
    return;
  }
  const all = batches();
  const images = all.reduce((n, b) => n + b.images.length, 0);
  if (images === 0) {
    console.error("no review run to read: `yarn review` first");
    process.exitCode = 1;
    return;
  }
  const rubric = readFileSync(new URL("rubric.md", import.meta.url), "utf8");
  console.log(`${images} screenshots in ${all.length} requests to ${MODEL}`);
  if (DRY) {
    for (const batch of all) {
      const bytes = JSON.stringify(body(batch, rubric)).length;
      console.log(
        `  ${batch.scenario}: ${batch.images.length} images, ${(bytes / 1e6).toFixed(1)} MB`,
      );
    }
    // The first request as it would be sent, its image data left out.
    const first = JSON.stringify(
      body(all[0], rubric),
      (k, v: unknown) => (k === "data" && typeof v === "string" ? `<${v.length} base64 chars>` : v),
      1,
    );
    console.log(`dry run, nothing sent. The first request:\n${first}`);
    return;
  }

  const client = new Anthropic();
  const suspicions: Suspicions = {};
  let failed = 0;
  for (const [i, batch] of all.entries()) {
    process.stdout.write(`  ${i + 1}/${all.length} ${batch.scenario} `);
    try {
      const { findings } = JSON.parse(await ask(client, body(batch, rubric))) as {
        findings: Finding[];
      };
      for (const { image, ...finding } of findings) {
        const png = batch.images[image - 1]?.png;
        if (png) (suspicions[png] ??= []).push(finding);
      }
      console.log(`${findings.length} suspected`);
    } catch (e) {
      failed += 1;
      console.log(`failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  writeFileSync(join(OUT, "claude.json"), JSON.stringify(suspicions, null, 1));
  const { path } = writeSheet();
  console.log(`${Object.values(suspicions).flat().length} suspected problems in ${path}`);
  if (failed) process.exitCode = 1;
}

await main();
