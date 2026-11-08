<script lang="ts">
  import Copy from "@lucide/svelte/icons/copy";
  import ExternalLink from "@lucide/svelte/icons/external-link";

  import { app, copyText } from "$lib/stores/app.svelte";

  // Where the env's servers answer here: the ports the gate publishes and those luoto's
  // watcher forwards as the env starts listening on them.
  const d = $derived(app.detail);
  const open = $derived(
    d
      ? [
          ...d.ports.published,
          ...d.ports.forwarded.filter((p) => !d.ports.published.includes(p)),
        ].sort((a, b) => a - b)
      : [],
  );
</script>

{#if d && d.dev === "running"}
  <div class="section">
    <p class="label">ports</p>
    {#each open as port (port)}
      <a class="link" href="http://localhost:{port}" target="_blank" rel="noopener noreferrer"
        ><span class="mono">http://localhost:{port}</span><ExternalLink size={12} /></a
      >
    {:else}
      <p class="small muted">none forwarded</p>
    {/each}
    {#each d.ports.taken as port (port)}
      {@const cmd = `luoto forward -e ${d.name} <port>:${port}`}
      <p class="small muted taken">{port} is taken on this machine; forward it to another:</p>
      <button class="cmd" onclick={() => copyText(cmd)} title="copy"
        ><code>{cmd}</code><Copy size={12} /></button
      >
    {/each}
  </div>
{/if}

<style>
  .link {
    display: flex;
    gap: 6px;
    align-items: center;
    width: fit-content;
    margin-bottom: 4px;
    color: var(--halo-accent);
    text-decoration: none;
  }

  .link:hover {
    text-decoration: underline;
  }

  .taken {
    margin-top: 4px;
  }

  .cmd {
    display: flex;
    gap: 6px;
    align-items: center;
    width: 100%;
    margin: 4px 0;
    padding: 4px 6px;
    border: none;
    border-radius: var(--halo-radius);
    background: var(--halo-bg-light);
    color: var(--halo-text-main);
    text-align: left;
  }

  .cmd code {
    flex: 1;
  }
</style>
