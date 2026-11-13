<script lang="ts">
  import CopyCommand from "$lib/components/CopyCommand.svelte";
  import SectionHead from "$lib/components/SectionHead.svelte";
  import { app, diskSize, plural, refreshVmDisk } from "$lib/stores/app.svelte";

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

<div class="top">
  <SectionHead label="disk" what="read disk space again" {busy} onrefresh={() => void refresh()} />
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
        {plural(v.prunable, "superseded image")}, up to {diskSize(v.prunable_bytes)}:
      </p>
      <CopyCommand cmd="luoto prune" />
    {/if}
  </div>
{/if}

<style>
  .top {
    margin-top: 22px;
  }

  .disk {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 0 8px;
  }
</style>
