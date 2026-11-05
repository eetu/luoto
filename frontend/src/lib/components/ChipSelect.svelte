<script lang="ts">
  let {
    options,
    selected,
    onchange,
  }: {
    options: { name: string; title?: string }[];
    selected: string[];
    onchange: (selected: string[]) => void;
  } = $props();

  const toggle = (name: string) =>
    onchange(selected.includes(name) ? selected.filter((x) => x !== name) : [...selected, name]);
</script>

<div class="chips">
  {#each options as o (o.name)}
    <button
      type="button"
      class="chip"
      class:on={selected.includes(o.name)}
      title={o.title}
      onclick={() => toggle(o.name)}>{o.name}</button
    >
  {/each}
</div>

<style>
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }

  .chip {
    padding: 3px 9px;
    border: 1px solid var(--halo-border);
    border-radius: var(--halo-radius-pill, 999px);
    background: var(--halo-bg-main);
    color: var(--halo-text-muted);
    font-size: 12px;
  }

  .chip.on {
    border-color: var(--halo-accent);
    background: var(--halo-accent-soft);
    color: var(--halo-accent);
  }
</style>
