<script lang="ts">
  import Copy from "@lucide/svelte/icons/copy";
  import RefreshCw from "@lucide/svelte/icons/refresh-cw";

  import { app, copyText, diskSize, refreshVmDisk } from "$lib/stores/app.svelte";

  // The disk every env lives on: a full one stops them all, so a low one is flagged here,
  // with the command that frees luoto's superseded images.
  const v = $derived(app.vmDisk);
  let busy = $state(false);

  async function refresh() {
    busy = true;
    await refreshVmDisk();
    busy = false;
  }
</script>

<div class="head">
  <p class="label">disk</p>
  <button
    class="refresh"
    aria-label="read disk space again"
    title="read again"
    disabled={busy}
    onclick={() => void refresh()}><RefreshCw size={12} /></button
  >
</div>
{#if v}
  <div class="disk" title={v.place}>
    {#if !v.space}
      <p class="small muted">{v.place}: not running, or its size is unknown</p>
    {:else}
      <p class="small" class:warn={v.low}>
        {diskSize(v.space.free)} free of {diskSize(v.space.size)}
      </p>
      {#if v.low}
        <p class="warn">{v.place} is nearly full, and a full disk stops every env</p>
      {/if}
    {/if}
    {#if v.prunable > 0}
      <p class="small muted">
        {v.prunable} superseded image(s), up to {diskSize(v.prunable_bytes)}:
      </p>
      <button class="cmd" title="copy" onclick={() => copyText("luoto prune")}
        ><code>luoto prune</code><Copy size={12} /></button
      >
    {/if}
  </div>
{/if}

<style>
  .head {
    display: flex;
    gap: 6px;
    align-items: baseline;
    margin-top: 22px;
  }

  .refresh {
    display: inline-flex;
    padding: 2px;
    border: none;
    border-radius: var(--halo-radius);
    background: none;
    color: var(--halo-text-muted);
  }

  .refresh:hover:not([disabled]) {
    color: var(--halo-accent);
  }

  .refresh[disabled] {
    opacity: 0.5;
    cursor: default;
  }

  .disk {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 0 8px;
  }
</style>
