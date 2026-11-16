<script lang="ts">
  import ChevronLeft from "@lucide/svelte/icons/chevron-left";

  import { api } from "$lib/api";
  import Chevron from "$lib/components/Chevron.svelte";
  import RuleBuilder from "$lib/components/RuleBuilder.svelte";
  import { openMenu } from "$lib/menu.svelte";
  import { act, ago, app, bytes, copyText, leftText, ruleText } from "$lib/stores/app.svelte";
  import type { CompiledRule, LuotoEvent } from "$lib/types";

  let { host, back }: { host: string; back?: { kind: "rule"; id: string } } = $props();

  const summary = $derived(app.egress.find((h) => h.host === host) ?? null);
  // Reached through open egress: no rule allows it, so the form keeps it.
  const opened = $derived((summary?.opened ?? 0) > 0);
  const wrote = $derived(
    summary?.methods.some((m) => !["GET", "HEAD", "OPTIONS"].includes(m)) ?? false,
  );
  // A name that resolves to a private address only the gate's denial tells.
  const resolvesPrivate = $derived(summary?.last_reason === "private_address");
  const isPrivate = $derived(
    resolvesPrivate ||
      host.endsWith(".internal") ||
      /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host) ||
      host === "localhost",
  );
  // Newest first, as the API returns them.
  let attempts = $state<LuotoEvent[]>([]);
  let expanded = $state<Record<string, boolean>>({});
  /** A path picked from an attempt for the rule form; a new object each pick. */
  let pathHint = $state<{ path: string }>();

  $effect(() => {
    const env = app.env;
    const h = host;
    // Re-fetch when the summary changes (new events arrived for this host).
    void summary?.last_seen;
    if (!env) return;
    void api.events(env, h, app.minutes).then((evs) => {
      if (app.env === env) attempts = evs;
    });
  });

  /** The user's rules for exactly this host. */
  const mine = $derived(
    app.detail?.rules.filter((r) => r.origin === "user" && r.host === host) ?? [],
  );
  /** A rule beside the host's own is being added. */
  let adding = $state(false);

  function revoke(r: CompiledRule) {
    const env = app.env;
    if (!env) return;
    void act("revoking…", () => api.deleteRule(env, r.id), `revoked ${r.host}`);
  }

  $effect(() => {
    void host;
    expanded = {};
    pathHint = undefined;
    adding = false;
  });

  // Picking a path from an attempt is for a rule: open the form if the host's rules hid it.
  $effect(() => {
    if (pathHint) adding = true;
  });

  type Group = {
    key: string;
    outcome: string;
    deny: boolean;
    /** Method (or kind) and path, without the query, which varies between polls. */
    what: string;
    path: string;
    count: number;
    /** The newest attempt, whose details the row shows. */
    latest: LuotoEvent;
    first: string | null;
  };

  // Attempts alike in outcome, method and path are one row, the newest group first: whether
  // a fix took effect reads as a recent 200 above an older 502.
  const groups = $derived.by(() => {
    const at = (ts: string | null): number => (ts ? Date.parse(ts) : 0);
    const by: Record<string, Group> = {};
    for (const e of attempts) {
      const deny = e.verdict === "deny";
      const outcome = deny ? "blocked" : e.kind === "dns" ? "lookup" : String(e.status ?? "");
      const path = (e.path ?? "").split("?")[0];
      const what = `${e.method ?? e.kind ?? ""} ${path}`.trim();
      const key = `${outcome}|${deny ? (e.reason ?? "") : ""}|${what}`;
      const g = by[key];
      if (!g) {
        by[key] = { key, outcome, deny, what, path, count: 1, latest: e, first: e.ts };
        continue;
      }
      g.count += 1;
      if (at(e.ts) > at(g.latest.ts)) g.latest = e;
      if (at(e.ts) < at(g.first)) g.first = e.ts;
    }
    return Object.values(by).sort((a, b) => at(b.latest.ts) - at(a.latest.ts));
  });

  function attemptMenu(ev: MouseEvent, g: Group) {
    openMenu(ev, g.what, [
      { label: "Copy path", run: () => copyText(g.path), disabled: !g.path },
      {
        label: "Allow this path…",
        run: () => (pathHint = { path: g.path }),
        disabled: !g.path.startsWith("/"),
      },
    ]);
  }
</script>

<div class="panel">
  {#if back}
    {@const to = back}
    <button class="back" onclick={() => (app.subject = to)}
      ><ChevronLeft size={13} /> Back to the rule</button
    >
  {/if}
  <p class="label">host</p>
  <h2>{host}</h2>
  {#if summary}
    <p class="facts">
      {summary.allowed} allowed, {summary.denied} blocked{#if summary.intakes.length}, via
        {summary.intakes.join(" and ")}{/if}{#if summary.bytes_up || summary.bytes_down}, ↑{bytes(
          summary.bytes_up,
        )} ↓{bytes(summary.bytes_down)}{/if}
    </p>
    {#if summary.dns_only}
      <p class="muted">
        Something in the sandbox looked this name up but never connected. Nothing left the sandbox.
      </p>
    {/if}
    {#if summary.allowed_now}
      <!-- What was blocked a rule allows now: the denials are history, not the state. -->
      <p class="muted small">
        allowed now by rule <code>{summary.allowed_now}</code>, blocked {summary.denied === 1
          ? "once"
          : `${summary.denied} times`} before it
      </p>
    {:else}
      {#if summary.allowed_not_private}
        <p class="why">
          Rule <code>{summary.allowed_not_private}</code> allows this host, not the private address it
          resolves to. Allow it again with "allow private address" on.
        </p>
      {:else if summary.last_message && summary.denied > 0}
        <p class="why">{summary.last_message}</p>
      {/if}
      {#if opened}
        <p class="muted small">
          {summary.opened} let through by open egress: no rule allows it, and it closes with the window
        </p>
      {:else if summary.last_rule && attempts[0]?.verdict !== "deny"}
        <!-- Only while the newest attempt was allowed: a rule revoked since allows nothing. -->
        <p class="muted small">
          allowed by rule <code>{summary.last_rule}</code>
        </p>
      {/if}
    {/if}
  {/if}

  {#if mine.length > 0}
    <!-- The host has rules of yours: change one rather than stack another beside it. -->
    <div class="section">
      <p class="label">{mine.length === 1 ? "your rule" : "your rules"}</p>
      {#each mine as r (r.id)}
        <div class="mine">
          <span class="small"
            >{ruleText(r)}<span class="muted">
              {r.expires ? leftText(r.expires) : "until revoked"}</span
            ></span
          >
          <button
            class="btn"
            onclick={() => (app.subject = { kind: "rule", id: r.id, back: { kind: "host", host } })}
            >Edit</button
          >
          <button class="btn danger" onclick={() => revoke(r)}>Revoke</button>
        </div>
      {/each}
      {#if !adding}
        <button class="link" onclick={() => (adding = true)}>Add another rule</button>
      {/if}
    </div>
  {/if}

  {#if mine.length === 0 || adding}
    <div class="section">
      <RuleBuilder
        {host}
        keep={opened}
        wantsWrite={opened ? wrote : (summary?.wants_write ?? false)}
        paths={summary?.top_paths.map(([p]) => p) ?? []}
        privateHost={isPrivate}
        {resolvesPrivate}
        tlsRejected={summary?.tls_rejected ?? false}
        {pathHint}
        ondone={() => (adding = false)}
      />
    </div>
  {/if}

  <div class="section">
    <p class="label">recent attempts</p>
    {#each groups as g (g.key)}
      {@const e = g.latest}
      <button
        class="attempt"
        class:open={!!expanded[g.key]}
        aria-expanded={!!expanded[g.key]}
        onclick={() => (expanded[g.key] = !expanded[g.key])}
        oncontextmenu={(ev) => attemptMenu(ev, g)}
      >
        <Chevron open={!!expanded[g.key]} />
        <span class="v" class:deny={g.deny}>{g.outcome}</span>
        <span class="mono what">{g.what}</span>
        <span class="muted when">{g.count > 1 ? `${g.count}× ` : ""}{ago(e.ts)}</span>
      </button>
      {#if expanded[g.key]}
        <div class="detail small">
          {#if e.message}<p>{e.message}</p>{/if}
          <p class="muted">
            {[
              e.rule && `rule ${e.rule}`,
              e.intake && `via ${e.intake}`,
              e.port && `port ${e.port}`,
              e.ms != null && `${e.ms} ms`,
              (e.bytes_up || e.bytes_down) &&
                `↑${bytes(e.bytes_up ?? 0)} ↓${bytes(e.bytes_down ?? 0)}`,
            ]
              .filter(Boolean)
              .join(", ")}
          </p>
          {#if g.count > 1}
            <p class="muted">first {ago(g.first)}, last {ago(e.ts)}</p>
          {/if}
        </div>
      {/if}
    {:else}
      <p class="muted small">none in this window</p>
    {/each}
  </div>
</div>

<style>
  .mine {
    display: flex;
    flex-wrap: wrap;
    gap: 6px 8px;
    align-items: center;
    padding: 4px 0;
  }

  .mine .small {
    flex: 1;
    min-width: 140px;
    overflow-wrap: anywhere;
  }

  .link {
    align-self: flex-start;
    padding: 0;
    border: none;
    background: transparent;
    color: var(--halo-accent);
    font-size: 12px;
    cursor: pointer;
  }

  .back {
    align-self: flex-start;
    display: inline-flex;
    gap: 2px;
    align-items: center;
    margin: 0 0 10px -3px;
    padding: 0;
    border: none;
    background: transparent;
    color: var(--halo-accent);
    font-size: 12px;
    cursor: pointer;
  }

  h2 {
    margin: 0;
    font-size: 15px;
    word-break: break-all;
  }

  .facts {
    margin: 0;
    color: var(--halo-text-muted);
    font-size: 12px;
  }

  .why {
    margin: 4px 0 0;
    padding: 6px 8px;
    border-left: 2px solid var(--halo-error);
    font-size: 13px;
  }

  .attempt {
    display: grid;
    grid-template-columns: 12px 44px 1fr auto;
    gap: 6px;
    align-items: start;
    width: 100%;
    padding: 4px 6px;
    border: none;
    border-radius: 4px;
    background: transparent;
    color: var(--halo-text-main);
    font-size: 12px;
    text-align: left;
    cursor: pointer;
  }

  .attempt :global(.chevron) {
    margin-top: 2px;
  }

  .attempt:hover,
  .attempt.open {
    background: var(--halo-accent-soft);
  }

  .attempt.open {
    border-radius: 4px 4px 0 0;
  }

  .detail {
    margin: 0 0 6px;
    padding: 4px 6px 6px 24px;
    border-radius: 0 0 4px 4px;
    background: var(--halo-accent-soft);
    overflow-wrap: anywhere;
  }

  .detail p {
    margin: 2px 0;
  }

  .v {
    color: var(--halo-text-muted);
  }

  .v.deny {
    color: var(--halo-error);
  }

  .what {
    overflow-wrap: anywhere;
  }

  .when {
    font-size: 11px;
  }
</style>
