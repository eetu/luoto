<script lang="ts">
  import ShieldQuestion from "@lucide/svelte/icons/shield-question";

  import { api } from "$lib/api";
  import { act, ago, app, installLabel, requestTarget, say, TTLS } from "$lib/stores/app.svelte";

  // Requests ticked for one decision; ids no longer pending drop out.
  let picked = $state<number[]>([]);
  let ttl = $state(60);
  const chosen = $derived(app.pending.filter((r) => picked.includes(r.id)));
  const accessChosen = $derived(chosen.some((r) => !r.install));

  function pick(id: number, on: boolean) {
    picked = on ? [...picked, id] : picked.filter((p) => p !== id);
  }

  /** Approve or reject every ticked request in turn. One whose rule has risks, or that fails,
   * stays ticked for review on its own: a batch never confirms risks. */
  async function decide(approve: boolean) {
    const env = app.env;
    if (!env || chosen.length === 0) return;
    const reqs = chosen;
    const verb = approve ? "approved" : "rejected";
    const outcome = await act(
      `${approve ? "approving" : "rejecting"} ${reqs.length}…`,
      async () => {
        const left: number[] = [];
        for (const r of reqs) {
          try {
            if (approve) await api.approve(env, r, r.install || !ttl ? undefined : `${ttl}m`);
            else await api.reject(env, r);
          } catch {
            left.push(r.id);
          }
        }
        return left;
      },
    );
    if (!outcome) return;
    picked = outcome;
    const done = reqs.length - outcome.length;
    say(
      outcome.length === 0
        ? `${verb} ${done}`
        : `${verb} ${done}; #${outcome.join(", #")} need review one by one`,
      outcome.length > 0,
    );
  }
</script>

{#if app.pending.length > 0}
  <div class="requests">
    {#if app.pending.length > 1}
      <div class="batch">
        <label class="all">
          <input
            type="checkbox"
            checked={chosen.length === app.pending.length}
            indeterminate={chosen.length > 0 && chosen.length < app.pending.length}
            onchange={(e) => (picked = e.currentTarget.checked ? app.pending.map((r) => r.id) : [])}
          />
          {chosen.length > 0 ? `${chosen.length} selected` : "select all"}
        </label>
        {#if chosen.length > 0}
          {#if accessChosen}
            <label class="field">
              <span>access for</span>
              <select bind:value={ttl}>
                {#each TTLS as t (t.minutes)}<option value={t.minutes}>{t.label}</option>{/each}
              </select>
            </label>
          {/if}
          <button class="btn primary" onclick={() => void decide(true)} disabled={!!app.busy}
            >approve {chosen.length}</button
          >
          <button class="btn" onclick={() => void decide(false)} disabled={!!app.busy}
            >reject {chosen.length}</button
          >
        {/if}
      </div>
    {/if}
    {#each app.pending as r (r.id)}
      <div
        class="request halo-card"
        class:selected={app.subject.kind === "request" && app.subject.id === r.id}
      >
        {#if app.pending.length > 1}
          <input
            type="checkbox"
            aria-label="select request #{r.id}"
            checked={picked.includes(r.id)}
            onchange={(e) => pick(r.id, e.currentTarget.checked)}
          />
        {/if}
        <button class="open" onclick={() => (app.subject = { kind: "request", id: r.id })}>
          <ShieldQuestion size={16} />
          {#if r.install}
            <span
              >{r.install.kind === "package" || r.install.kind === "tool" ? "install " : ""}<b
                >{installLabel(r.install)}</b
              > requested from inside the sandbox</span
            >
          {:else if r.port}
            <span
              >an uninspected tunnel to <b>{requestTarget(r)}</b> requested from inside the sandbox</span
            >
          {:else}
            <span
              ><b>{r.access}</b> access to <b>{r.host}</b> requested from inside the sandbox</span
            >
          {/if}
          <span class="muted">#{r.id}, {ago(r.created)}: review</span>
        </button>
      </div>
    {/each}
  </div>
{/if}

<style>
  .requests {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding: 0 18px 10px;
  }

  .batch {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    align-items: center;
    min-height: 30px;
    font-size: 13px;
  }

  .all {
    display: flex;
    gap: 8px;
    align-items: center;
    margin-right: auto;
    padding-left: 12px;
    color: var(--halo-text-muted);
  }

  input[type="checkbox"] {
    flex: none;
    margin: 0;
    accent-color: var(--halo-accent);
  }

  .request {
    display: flex;
    gap: 10px;
    align-items: center;
    padding: 0 0 0 12px;
    border: 1px solid transparent;
  }

  .open {
    display: flex;
    flex: 1;
    gap: 10px;
    align-items: center;
    min-width: 0;
    padding: 9px 12px 9px 0;
    border: 0;
    background: none;
    color: var(--halo-text-main);
    font: inherit;
    text-align: left;
    cursor: pointer;
  }

  .open :global(svg) {
    flex: none;
    color: var(--halo-accent);
  }

  .open span:nth-of-type(1) {
    flex: 1;
  }

  .request.selected {
    border-color: var(--halo-accent);
  }
</style>
