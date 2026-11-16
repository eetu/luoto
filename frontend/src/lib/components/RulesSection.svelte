<script lang="ts">
  import { app } from "$lib/stores/app.svelte";

  // How many rules the env has; the rules view lists, edits and revokes them.
  const d = $derived(app.detail);
  const mine = $derived(d?.rules.filter((r) => r.origin === "user").length ?? 0);
  const others = $derived((d?.rules.length ?? 0) - mine);
</script>

{#if d}
  <div class="section">
    <p class="label">rules</p>
    <p class="small">
      {mine === 1 ? "1 of yours" : `${mine} of yours`}, {others} from presets and profiles
    </p>
    <button class="btn" onclick={() => (app.surface = "rules")}>Show rules</button>
  </div>
{/if}

<style>
  .btn {
    margin-top: 4px;
  }
</style>
