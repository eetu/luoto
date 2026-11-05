<script lang="ts">
  import ShieldQuestion from "@lucide/svelte/icons/shield-question";

  import { ago, app } from "$lib/stores/app.svelte";
</script>

{#if app.pending.length > 0}
  <div class="requests">
    {#each app.pending as r (r.id)}
      <button
        class="request halo-card"
        class:selected={app.subject.kind === "request" && app.subject.id === r.id}
        onclick={() => (app.subject = { kind: "request", id: r.id })}
      >
        <ShieldQuestion size={16} />
        <span><b>{r.access}</b> access to <b>{r.host}</b> requested from inside the sandbox</span>
        <span class="muted">#{r.id}, {ago(r.created)}: review</span>
      </button>
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

  .request {
    display: flex;
    gap: 10px;
    align-items: center;
    padding: 9px 12px;
    border: 1px solid transparent;
    color: var(--halo-text-main);
    text-align: left;
  }

  .request :global(svg) {
    flex: none;
    color: var(--halo-accent);
  }

  .request span:nth-child(2) {
    flex: 1;
  }

  .request.selected {
    border-color: var(--halo-accent);
  }
</style>
