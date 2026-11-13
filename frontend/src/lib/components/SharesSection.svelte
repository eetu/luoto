<script lang="ts">
  import { api } from "$lib/api";
  import CopyCommand from "$lib/components/CopyCommand.svelte";
  import SectionHead from "$lib/components/SectionHead.svelte";
  import { app, busyWhile, diskSize, errorText, say } from "$lib/stores/app.svelte";
  import type { SharesView } from "$lib/types";

  // Folders of this machine the env reads at /shares/<name>, read-only. The env can't change
  // them, so "changed" is always this machine's side: files changed, added or removed in the
  // folder since the env's clones were last synced. Reading it walks the folders, so it loads
  // when the panel shows, after a sync, when the env starts or stops, and on refresh.
  const d = $derived(app.detail);
  // Primitives, so the detail's polls don't reload it.
  const name = $derived(app.detail?.name);
  const dev = $derived(app.detail?.dev);
  let view = $state<SharesView | null>(null);
  let error = $state<string | null>(null);
  let loading = $state(false);

  const load = async (name: string) => {
    loading = true;
    try {
      view = await api.shares(name);
      error = null;
    } catch (e) {
      error = errorText(e);
    } finally {
      loading = false;
    }
  };

  $effect(() => {
    if (name && dev) void load(name);
  });

  const changed = $derived(view?.shares.reduce((n, s) => n + s.changed, 0) ?? 0);

  const sync = async (name: string) => {
    const done = await busyWhile("syncing shares…", () => api.syncShares(name));
    if (done) say(done.said.join("; "), done.failed);
    await load(name);
  };
</script>

{#if d}
  <div class="section">
    <SectionHead
      label="shares"
      what="check the shared folders again"
      busy={loading}
      onrefresh={() => void load(d.name)}
    />
    {#if error}
      <p class="small error">{error}</p>
    {:else if view && view.shares.length === 0}
      <p class="muted small">
        none; a folder of this machine the env reads at /shares/&lt;name&gt;:
      </p>
      {@const cmd = `luoto share add -e ${d.name} <folder>`}
      <CopyCommand {cmd} />
    {:else if view}
      <ul>
        {#each view.shares as s (s.name)}
          <li>
            <span class="mono">/shares/{s.name}</span>
            <span class="muted small folder" title={s.folder}>{s.folder}</span>
            {#if s.error}
              <span class="small error">{s.error}</span>
            {:else if s.changed > 0}
              <span class="small changed"
                >{s.changed} changed on this machine since the last sync</span
              >
            {:else}
              <span class="small muted"
                >{s.files} {s.files === 1 ? "file" : "files"}, {diskSize(s.bytes)}, up to date</span
              >
            {/if}
          </li>
        {/each}
      </ul>
      {#if view.fix}
        <p class="small changed">not in the env yet:</p>
        <CopyCommand cmd={view.fix} />
      {/if}
      <div class="actions">
        <button
          class="btn"
          class:primary={changed > 0}
          disabled={app.busy !== null}
          onclick={() => void sync(d.name)}>Sync</button
        >
      </div>
      <p class="muted small">Read-only in the env; a change here reaches it at sync or start.</p>
    {/if}
  </div>
{/if}

<style>
  ul {
    display: grid;
    gap: 8px;
    margin: 0 0 8px;
    padding: 0;
    list-style: none;
  }

  li {
    display: grid;
    gap: 1px;
    min-width: 0;
  }

  .folder {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .changed {
    color: var(--halo-accent);
  }
</style>
