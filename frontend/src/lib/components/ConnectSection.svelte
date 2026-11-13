<script lang="ts">
  import CopyCommand from "$lib/components/CopyCommand.svelte";
  import { app } from "$lib/stores/app.svelte";

  const name = $derived(app.detail?.name ?? "");
</script>

<div class="section">
  <p class="label">connect</p>
  {#each [`luoto shell -e ${name}`, `luoto open -e ${name}`, `luoto open -e ${name} --with code`] as cmd (cmd)}
    <CopyCommand {cmd} />
  {/each}
</div>
