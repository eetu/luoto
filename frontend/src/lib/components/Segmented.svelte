<script lang="ts" generics="T extends string | number">
  let {
    options,
    value,
    label,
    disabled = false,
    onchange,
  }: {
    options: readonly { value: T; label: string }[];
    value: T;
    label: string;
    disabled?: boolean;
    onchange: (value: T) => void;
  } = $props();
</script>

<div class="seg" role="group" aria-label={label}>
  {#each options as o (o.value)}
    <button
      type="button"
      class:active={value === o.value}
      {disabled}
      onclick={() => onchange(o.value)}>{o.label}</button
    >
  {/each}
</div>

<style>
  .seg {
    display: inline-flex;
    justify-self: start;
    overflow: hidden;
    border: 1px solid var(--halo-border);
    border-radius: var(--halo-radius);
  }

  button {
    padding: 4px 10px;
    border: none;
    background: var(--halo-bg-main);
    color: var(--halo-text-muted);
    font-size: 12px;
  }

  button.active {
    background: var(--halo-accent-soft);
    color: var(--halo-accent);
  }
</style>
