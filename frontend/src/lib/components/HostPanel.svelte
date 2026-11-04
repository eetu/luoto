<script lang="ts">
  import { api } from "$lib/api";
  import RuleBuilder from "$lib/components/RuleBuilder.svelte";
  import { ago, app, bytes } from "$lib/stores/app.svelte";
  import type { LuotoEvent } from "$lib/types";

  let { host }: { host: string } = $props();

  const summary = $derived(app.egress.find((h) => h.host === host) ?? null);
  const isPrivate = $derived(
    host.endsWith(".internal") ||
      /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host) ||
      host === "localhost",
  );
  let attempts = $state<LuotoEvent[]>([]);

  $effect(() => {
    const env = app.env;
    const h = host;
    // Re-fetch when the summary changes (new events arrived for this host).
    void summary?.last_seen;
    if (!env) return;
    void api.events(env, h, app.minutes).then((evs) => {
      if (app.env === env) attempts = evs.slice(-40).reverse();
    });
  });
</script>

<div class="panel">
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
    {#if summary.last_message && summary.denied > 0}
      <p class="why">{summary.last_message}</p>
    {/if}
    {#if summary.last_rule}
      <p class="muted small">
        allowed by rule <code>{summary.last_rule}</code>
      </p>
    {/if}
  {/if}

  <div class="section">
    <RuleBuilder
      {host}
      wantsWrite={summary?.wants_write ?? false}
      paths={summary?.top_paths.map(([p]) => p) ?? []}
      privateHost={isPrivate}
      tlsRejected={summary?.tls_rejected ?? false}
    />
  </div>

  <div class="section">
    <p class="label">recent attempts</p>
    {#each attempts as e, n (n)}
      <div class="attempt">
        <span class="v" class:deny={e.verdict === "deny"}
          >{e.verdict === "deny" ? "blocked" : e.kind === "dns" ? "lookup" : (e.status ?? "")}</span
        >
        <span class="mono what">{e.method ?? e.kind} {e.path ?? ""}</span>
        <span class="muted when">{ago(e.ts)}</span>
      </div>
    {:else}
      <p class="muted small">none in this window</p>
    {/each}
  </div>
</div>

<style>
  .panel {
    display: flex;
    flex-direction: column;
    gap: 6px;
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

  .small {
    margin: 0;
    font-size: 12px;
  }

  .section {
    margin-top: 14px;
    padding-top: 12px;
    border-top: 1px solid var(--halo-border);
  }

  .attempt {
    display: grid;
    grid-template-columns: 52px 1fr auto;
    gap: 8px;
    padding: 3px 0;
    font-size: 12px;
  }

  .v {
    color: var(--halo-text-muted);
  }

  .v.deny {
    color: var(--halo-error);
  }

  .what {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .when {
    font-size: 11px;
  }
</style>
