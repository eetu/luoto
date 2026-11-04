<script lang="ts">
  import { api } from "$lib/api";
  import { act, app, say } from "$lib/stores/app.svelte";
  import type { PullPlan } from "$lib/types";

  // The env's folder, and a reviewed pull of what changed in the env's copy.
  const d = $derived(app.detail);
  const row = $derived(app.overview?.envs.find((e) => e.name === app.env));
  const dir = $derived(row?.dir ?? null);

  let plan = $state<PullPlan | null>(null);
  let includeRisky = $state(false);

  $effect(() => {
    // A plan belongs to one env.
    void app.env;
    plan = null;
  });

  async function review() {
    const env = app.env;
    if (!env) return;
    app.busy = "reading the env's files…";
    try {
      plan = await api.pullPlan(env);
      includeRisky = false;
    } catch (e) {
      say(e instanceof Error ? e.message : String(e), true);
    } finally {
      app.busy = null;
    }
  }

  async function apply() {
    const env = app.env;
    if (!env || !plan) return;
    const digest = plan.digest;
    let result = { written: 0, skipped: 0 };
    const ok = await act("writing…", async () => {
      result = await api.pull(env, digest, includeRisky);
    });
    if (ok) {
      say(
        `wrote ${result.written} file(s)${result.skipped ? `, skipped ${result.skipped} risky` : ""}`,
      );
      plan = null;
    }
  }

  const risky = $derived(plan?.entries.filter((e) => e.risky) ?? []);
  const safe = $derived(plan?.entries.filter((e) => !e.risky) ?? []);
</script>

<div class="section">
  <p class="label">folder</p>
  <p class="small path">{dir ?? "none"}</p>
  <p class="small muted">copied in: the sandbox never writes here</p>

  {#if dir && d?.dev === "running"}
    {#if !plan}
      <button class="btn" onclick={review}>pull changes…</button>
    {:else}
      <div class="plan">
        <p class="small">
          {plan.entries.length} new or changed, {plan.unchanged} unchanged
        </p>
        {#each safe.slice(0, 20) as e, n (n)}
          <p class="small mono">{e.change} {e.path}</p>
        {/each}
        {#if safe.length > 20}<p class="small muted">… {safe.length - 20} more</p>{/if}
        {#if risky.length > 0}
          <p class="small warn">risky — host tools act on these:</p>
          {#each risky as e, n (n)}
            <p class="small mono">{e.change} {e.path} <span class="muted">— {e.risky}</span></p>
          {/each}
          <label class="small toggle">
            <input type="checkbox" bind:checked={includeRisky} /> also write risky files
          </label>
        {/if}
        {#each plan.refused as [p, why], n (n)}
          <p class="small muted">refused {p} — {why}</p>
        {/each}
        <div class="actions">
          <button
            class="btn primary"
            onclick={apply}
            disabled={safe.length === 0 && !(includeRisky && risky.length)}>write to folder</button
          >
          <button class="btn" onclick={() => (plan = null)}>cancel</button>
        </div>
      </div>
    {/if}
  {/if}
</div>

<style>
  .section {
    margin-top: 12px;
    padding-top: 10px;
    border-top: 1px solid var(--halo-border);
  }

  .small {
    margin: 2px 0;
    font-size: 12px;
  }

  .path {
    word-break: break-all;
  }

  .warn {
    margin: 4px 0;
    color: var(--halo-error);
    font-size: 12px;
  }

  .plan {
    margin-top: 8px;
  }

  .toggle {
    display: flex;
    gap: 6px;
    align-items: center;
  }

  .actions {
    display: flex;
    gap: 8px;
    margin-top: 8px;
  }
</style>
