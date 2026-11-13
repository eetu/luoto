<script lang="ts">
  import X from "@lucide/svelte/icons/x";

  import { api } from "$lib/api";
  import { openMenu } from "$lib/menu.svelte";
  import { accessText, act, app } from "$lib/stores/app.svelte";
  import type { CompiledRule } from "$lib/types";

  const d = $derived(app.detail);
  const userRules = $derived(d?.rules.filter((r) => r.origin === "user") ?? []);
  const groups = $derived.by(() => {
    const by: Record<string, CompiledRule[]> = {};
    for (const r of d?.rules ?? []) {
      if (r.origin !== "user") (by[r.origin] ??= []).push(r);
    }
    return Object.entries(by);
  });
  let open = $state<Record<string, boolean>>({});

  function revoke(r: CompiledRule) {
    const env = app.env;
    if (!env) return;
    void act("revoking…", () => api.deleteRule(env, r.id), `revoked ${r.host}`);
  }

  function ruleMenu(e: MouseEvent, r: CompiledRule) {
    openMenu(e, r.host, [
      {
        label: "Revoke",
        run: () => revoke(r),
        danger: true,
        disabled: r.origin !== "user",
        hint: r.origin !== "user" ? `from ${r.origin}` : undefined,
      },
      {
        label: "Show egress",
        run: () => (app.subject = { kind: "host", host: r.host }),
      },
    ]);
  }

  function expiry(r: CompiledRule): string {
    if (!r.expires) return "";
    const mins = Math.round((Date.parse(r.expires) - Date.now()) / 60_000);
    return mins > 90 ? `${Math.round(mins / 60)} h left` : `${Math.max(mins, 0)} min left`;
  }
</script>

{#if d}
  <div class="section">
    <p class="label">your rules</p>
    {#each userRules as r (r.id)}
      <div class="rule" oncontextmenu={(e) => ruleMenu(e, r)} role="listitem">
        <span class="host">{r.host}</span>
        <span class="muted small"
          >{accessText(r.access)}{r.mode === "tunnel" ? ", tunnel" : ""}{r.paths?.length
            ? `, ${r.paths.join(" ")}`
            : ""}</span
        >
        <span class="muted small">{expiry(r)}</span>
        <button class="icon" title="revoke" aria-label="revoke {r.host}" onclick={() => revoke(r)}
          ><X size={13} /></button
        >
      </div>
    {:else}
      <p class="muted small">none yet — allow hosts from the egress list</p>
    {/each}
  </div>

  <div class="section">
    <p class="label">from presets & profiles</p>
    {#each groups as [origin, rules] (origin)}
      <button
        class="group"
        aria-expanded={!!open[origin]}
        onclick={() => (open[origin] = !open[origin])}
      >
        <span>{origin}</span><span class="muted small">{rules.length}</span>
      </button>
      {#if open[origin]}
        {#each rules as r (r.id)}
          <p class="small sub">
            {r.host}
            <span class="muted"
              >{accessText(r.access)}{r.paths?.length ? ` ${r.paths.join(",")}` : ""}</span
            >
          </p>
        {/each}
      {/if}
    {/each}
    <p class="muted small cfg">config: <code>{d.path}</code></p>
  </div>
{/if}

<style>
  .rule {
    display: grid;
    grid-template-columns: 1fr auto 22px;
    gap: 2px 8px;
    align-items: center;
    padding: 4px 0;
  }

  .rule .host {
    grid-column: 1 / 2;
    font-size: 13px;
    word-break: break-all;
  }

  .rule .small:nth-of-type(2) {
    grid-column: 1 / 2;
  }

  .icon {
    grid-row: 1 / 3;
    grid-column: 3;
    padding: 2px;
    border: none;
    background: transparent;
    color: var(--halo-text-muted);
  }

  .icon:hover {
    color: var(--halo-error);
  }

  .group {
    display: flex;
    justify-content: space-between;
    width: 100%;
    padding: 4px 0;
    border: none;
    background: transparent;
    color: var(--halo-text-main);
    font-size: 13px;
  }

  .sub {
    padding-left: 10px;
  }

  .cfg {
    margin-top: 10px;
    word-break: break-all;
  }
</style>
