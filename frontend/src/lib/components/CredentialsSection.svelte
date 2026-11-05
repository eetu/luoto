<script lang="ts">
  import { app } from "$lib/stores/app.svelte";

  const d = $derived(app.detail);
</script>

{#if d}
  <div class="section">
    <p class="label">credentials</p>
    {#if d.credentials.length === 0}
      <p class="muted small">none — the gate injects nothing. Add [credentials.*] to the config.</p>
    {:else}
      {#each d.injections as i, n (n)}
        <p class="small"><code>{i.binding}</code> → {i.host}</p>
      {/each}
      {#if d.missing_secrets.length}
        <p class="warn">vault is missing {d.missing_secrets.length} secret(s): unlock it</p>
      {/if}
    {/if}
    {#if d.sandbox_secrets.length}
      <p class="warn">exposed to code in the sandbox: {d.sandbox_secrets.join(", ")}</p>
    {/if}
  </div>
{/if}
