<script lang="ts">
  import SectionHead from "$lib/components/SectionHead.svelte";
  import { app, diskSize, loadEnvDisk } from "$lib/stores/app.svelte";

  // One read measures every env, so it happens when an env panel first shows and on refresh.
  const sizes = $derived(app.envDisk && app.env ? app.envDisk[app.env] : undefined);

  $effect(() => {
    if (!app.envDisk && !app.envDiskBusy && !app.envDiskError) void loadEnvDisk();
  });
</script>

<div class="section">
  <SectionHead
    label="disk"
    what="measure disk use again"
    busy={app.envDiskBusy}
    onrefresh={() => void loadEnvDisk()}
  />
  {#if app.envDiskBusy && !sizes}
    <p class="small muted">measuring…</p>
  {:else if app.envDiskError}
    <p class="small muted">{app.envDiskError}</p>
  {:else if sizes && sizes.parts.length > 0}
    <p class="small"><b>{diskSize(sizes.total)}</b></p>
    <dl class="parts">
      {#each sizes.parts as p (p.what)}
        <dt class="muted">{p.what}</dt>
        <dd>{diskSize(p.bytes)}</dd>
      {/each}
    </dl>
  {:else if sizes}
    <p class="small muted">nothing yet: its volumes come with its first start</p>
  {:else if app.envDisk}
    <p class="small muted">not measured yet</p>
  {/if}
</div>

<style>
  .parts {
    display: grid;
    grid-template-columns: max-content max-content;
    gap: 2px 14px;
    margin: 4px 0 0;
    font-size: 12px;
  }

  .parts dd {
    margin: 0;
    text-align: right;
  }
</style>
