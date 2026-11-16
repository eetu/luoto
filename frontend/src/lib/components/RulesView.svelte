<script lang="ts">
  import Pencil from "@lucide/svelte/icons/pencil";
  import X from "@lucide/svelte/icons/x";

  import { api } from "$lib/api";
  import SurfaceTabs from "$lib/components/SurfaceTabs.svelte";
  import { openMenu } from "$lib/menu.svelte";
  import { act, app, leftText, ruleText } from "$lib/stores/app.svelte";
  import type { CompiledRule } from "$lib/types";

  // Every rule the env's gate applies: the user's, editable and revocable, then those of its
  // presets, agents and providers, which come from luoto's data and are listed as they are.
  // A row opens the rule in the subject panel.
  let filter = $state("");

  const groups = $derived.by(() => {
    const q = filter.trim().toLowerCase();
    const by: Record<string, CompiledRule[]> = { user: [] };
    for (const r of app.detail?.rules ?? []) {
      if (q && !r.host.toLowerCase().includes(q)) continue;
      (by[r.origin] ??= []).push(r);
    }
    return Object.entries(by).filter(([o, rs]) => o === "user" || rs.length > 0);
  });

  const selected = $derived(app.subject.kind === "rule" ? app.subject.id : null);
  const show = (r: CompiledRule) => (app.subject = { kind: "rule", id: r.id });

  function onKey(e: KeyboardEvent, r: CompiledRule) {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      show(r);
    }
  }

  function revoke(r: CompiledRule) {
    const env = app.env;
    if (!env) return;
    void act("revoking…", () => api.deleteRule(env, r.id), `revoked ${r.host}`);
  }

  function menu(e: MouseEvent, r: CompiledRule) {
    const mine = r.origin === "user";
    const hint = mine ? undefined : `from ${r.origin}`;
    openMenu(e, r.host, [
      { label: "Edit", run: () => show(r), disabled: !mine, hint },
      { label: "Revoke", run: () => revoke(r), danger: true, disabled: !mine, hint },
      { label: "Show egress", run: () => (app.subject = { kind: "host", host: r.host }) },
    ]);
  }
</script>

<section class="surface">
  <header class="bar">
    <SurfaceTabs />
    <div class="tools">
      <input type="text" placeholder="filter rules" bind:value={filter} aria-label="filter rules" />
      <button class="btn" onclick={() => (app.subject = { kind: "rule", id: null })}
        >Add rule</button
      >
    </div>
  </header>

  {#snippet card(origin: string, rules: CompiledRule[])}
    {@const mine = origin === "user"}
    <section class="card" class:mine aria-label={mine ? "your rules" : origin}>
      <header class="card-head">
        <span>{mine ? "your rules" : origin}</span>
        <span class="muted">{rules.length}</span>
      </header>
      <table class="list">
        <colgroup>
          <col class="c-host" />
          <col />
          <col class="c-for" />
          <col class="c-acts" />
        </colgroup>
        <tbody>
          {#each rules as r (r.id)}
            <tr
              class:selected={selected === r.id}
              tabindex="0"
              onclick={() => show(r)}
              onkeydown={(e) => onKey(e, r)}
              oncontextmenu={(e) => menu(e, r)}
            >
              <td class="host">{r.host}</td>
              <td class="muted">{ruleText(r)}</td>
              <td class="muted">{r.expires ? leftText(r.expires) : mine ? "until revoked" : ""}</td>
              <td class="acts">
                {#if mine}
                  <button
                    class="icon"
                    title="edit"
                    aria-label="edit {r.host}"
                    onclick={(e) => (e.stopPropagation(), show(r))}><Pencil size={13} /></button
                  ><button
                    class="icon revoke"
                    title="revoke"
                    aria-label="revoke {r.host}"
                    onclick={(e) => (e.stopPropagation(), revoke(r))}><X size={13} /></button
                  >
                {/if}
              </td>
            </tr>
          {:else}
            <tr>
              <td colspan="4" class="muted"
                >{filter ? "none match" : "none yet: add one, or allow a host from egress"}</td
              >
            </tr>
          {/each}
        </tbody>
      </table>
    </section>
  {/snippet}

  <div class="table-wrap cards">
    {#each groups.filter(([o]) => o === "user") as [origin, rules] (origin)}
      {@render card(origin, rules)}
    {/each}
    {#if app.detail}
      <p class="muted small cfg">yours are kept in <code>{app.detail.path}</code></p>
    {/if}
    {#if groups.length > 1}
      <p class="label others">from presets and profiles</p>
      {#each groups.filter(([o]) => o !== "user") as [origin, rules] (origin)}
        {@render card(origin, rules)}
      {/each}
    {/if}
  </div>
</section>

<style>
  .bar {
    justify-content: space-between;
  }

  .tools {
    display: flex;
    gap: 12px;
    align-items: center;
  }

  .c-host {
    width: 38%;
  }

  .c-for {
    width: 120px;
  }

  .c-acts {
    width: 64px;
  }

  .cards {
    padding-top: 4px;
  }

  /* A group: its heading over its rows, spaced from the next; no box, so no width lost. */
  .card {
    margin-bottom: 18px;
  }

  .card-head {
    display: flex;
    gap: 8px;
    align-items: baseline;
    padding: 6px 8px;
    border-bottom: 1px solid var(--halo-border);
    color: var(--halo-text-muted);
    font-family: var(--halo-font-heading);
    font-size: 11px;
    font-weight: 500;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }

  .card.mine .card-head {
    border-bottom-color: var(--halo-accent);
    color: var(--halo-text-main);
    font-size: 13px;
    letter-spacing: 0;
    text-transform: none;
  }

  .card table {
    table-layout: fixed;
  }

  .card tr:last-child td {
    border-bottom: none;
  }

  .others {
    margin: 32px 0 4px;
    padding: 0 8px;
  }

  .host {
    font-weight: 500;
    overflow-wrap: anywhere;
  }

  .acts {
    padding-top: 4px;
    padding-bottom: 4px;
    text-align: right;
    white-space: nowrap;
  }

  .icon {
    display: inline-flex;
    padding: 3px 5px;
    border: none;
    background: transparent;
    color: var(--halo-text-muted);
  }

  .icon:hover {
    color: var(--halo-text-main);
  }

  .icon.revoke:hover {
    color: var(--halo-error);
  }

  .cfg {
    margin: 12px 0;
    word-break: break-all;
  }
</style>
