<script lang="ts">
  import RefreshCw from "@lucide/svelte/icons/refresh-cw";

  // A section label with the button that reads its contents again.
  let {
    label,
    what,
    busy,
    onrefresh,
  }: { label: string; what: string; busy: boolean; onrefresh: () => void } = $props();
</script>

<div class="head">
  <p class="label">{label}</p>
  <button class="refresh" aria-label={what} title={what} disabled={busy} onclick={onrefresh}
    ><RefreshCw size={12} /></button
  >
</div>

<style>
  .head {
    display: flex;
    gap: 6px;
    align-items: baseline;
  }

  .refresh {
    display: inline-flex;
    padding: 2px;
    border: none;
    border-radius: var(--halo-radius);
    background: none;
    color: var(--halo-text-muted);
  }

  .refresh:hover:not([disabled]) {
    color: var(--halo-accent);
  }

  .refresh[disabled] {
    opacity: 0.5;
    cursor: default;
  }
</style>
