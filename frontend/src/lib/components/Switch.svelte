<script lang="ts">
  // An on/off switch: "is this thing on/present?" — distinct from a lit `active` button.
  let {
    checked,
    label,
    onchange,
  }: { checked: boolean; label: string; onchange: (next: boolean) => void } = $props();
</script>

<button
  type="button"
  class="sw"
  class:on={checked}
  role="switch"
  aria-checked={checked}
  aria-label={label}
  onclick={() => onchange(!checked)}
>
  <span class="knob"></span>
</button>

<style>
  .sw {
    position: relative;
    width: 26px;
    height: 15px;
    flex: none;
    padding: 0;
    border: 1px solid var(--halo-border);
    border-radius: 999px;
    background: var(--halo-bg-main);
    cursor: pointer;
    transition:
      background 120ms ease,
      border-color 120ms ease;
  }

  .sw.on {
    border-color: var(--halo-accent);
    background: var(--halo-accent);
  }

  .knob {
    position: absolute;
    top: 1px;
    left: 1px;
    width: 11px;
    height: 11px;
    border-radius: 50%;
    background: var(--halo-text-muted);
    transition:
      transform 120ms ease,
      background 120ms ease;
  }

  .sw.on .knob {
    background: var(--halo-bg-main);
    transform: translateX(11px);
  }

  @media (prefers-reduced-motion: reduce) {
    .sw,
    .knob {
      transition: none;
    }
  }
</style>
