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
    width: 100%;
    margin-bottom: 4px;
  }
</style>
