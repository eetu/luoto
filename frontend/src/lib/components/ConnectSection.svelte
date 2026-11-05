<script lang="ts">
  import Copy from "@lucide/svelte/icons/copy";

  import { app, copyText } from "$lib/stores/app.svelte";

  const name = $derived(app.detail?.name ?? "");
</script>

<div class="section">
  <p class="label">connect</p>
  {#each [`luoto shell -e ${name}`, `luoto open -e ${name}`, `luoto open -e ${name} --with code`] as cmd (cmd)}
    <button class="cmd" onclick={() => copyText(cmd)} title="copy"
      ><code>{cmd}</code><Copy size={12} /></button
    >
  {/each}
</div>

<style>
  .cmd {
    display: flex;
    gap: 6px;
    align-items: center;
    width: 100%;
    margin-bottom: 4px;
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
