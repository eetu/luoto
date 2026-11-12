<script lang="ts">
  import Copy from "@lucide/svelte/icons/copy";

  import { copyText } from "$lib/stores/app.svelte";

  // A command for a terminal, copied on click.
  let { cmd }: { cmd: string } = $props();
</script>

<button class="cmd" onclick={() => copyText(cmd)} title="copy"
  ><code>{cmd}</code><Copy size={12} /></button
>

<style>
  .cmd {
    width: 100%;
    margin-bottom: 4px;
  }
</style>
