<script lang="ts">
  import { api } from "$lib/api";
  import { app, busyWhile, say } from "$lib/stores/app.svelte";
  import type { SelftestReport } from "$lib/types";

  // The button sits in the env header's action row; the report wraps onto its own line.
  let report = $state<SelftestReport | null>(null);
  const stopped = $derived(app.detail?.dev !== "running");

  async function run() {
    const env = app.env;
    if (!env) return;
    const result = await busyWhile("self-test…", () => api.selftest(env));
    if (!result) return;
    report = result;
    say(result.ok ? "isolation self-test passed" : "isolation self-test FAILED", !result.ok);
  }
</script>

<button
  class="btn"
  onclick={run}
  disabled={stopped || !!app.busy}
  title={stopped ? "start the env first" : undefined}>Self-test</button
>
{#if report}
  <ul class="checks">
    {#each report.checks as c, n (n)}
      <li class:error={!c.ok}>
        <b>{c.ok ? "ok" : "FAIL"}</b>
        {c.name} <span class="muted">{c.detail}</span>
      </li>
    {/each}
  </ul>
{/if}

<style>
  .checks {
    flex: 0 0 100%;
    margin: 0;
    padding: 0;
    list-style: none;
    font-size: 12px;
  }
</style>
