<script lang="ts">
  import ChevronRight from "@lucide/svelte/icons/chevron-right";

  // The mark of a row that expands: points right, and down once open.
  let { open }: { open: boolean } = $props();
</script>

<span class="chevron" class:open aria-hidden="true"><ChevronRight size={12} /></span>

<style>
  .chevron {
    display: inline-flex;
    color: var(--halo-text-muted);
    transition: transform 120ms ease;
  }

  .open {
    transform: rotate(90deg);
  }

  @media (prefers-reduced-motion: reduce) {
    .chevron {
      transition: none;
    }
  }
</style>
