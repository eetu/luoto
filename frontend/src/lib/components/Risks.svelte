<script lang="ts">
  import { app } from "$lib/stores/app.svelte";

  // What the API asked the user to confirm before it accepts a risky rule; without `confirm`,
  // the caller's own button takes them.
  let {
    risks,
    heading = "confirm:",
    confirm,
    onconfirm,
  }: { risks: string[]; heading?: string; confirm?: string; onconfirm?: () => void } = $props();
</script>

<div class="risks">
  <p>{heading}</p>
  <ul>
    {#each risks as r (r)}<li>{r}</li>{/each}
  </ul>
  {#if confirm && onconfirm}
    <button type="button" class="btn danger" onclick={onconfirm} disabled={!!app.busy}
      >{confirm}</button
    >
  {/if}
</div>

<style>
  .risks {
    padding: 8px 10px;
    border-left: 2px solid var(--halo-error);
    background: color-mix(in srgb, var(--halo-error) 8%, transparent);
    font-size: 12px;
  }

  p {
    margin: 0;
  }

  ul {
    margin: 4px 0 8px;
    padding-left: 16px;
  }

  ul:last-child {
    margin-bottom: 0;
  }
</style>
