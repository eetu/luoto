<script lang="ts">
  let { lines }: { lines: [string, string][] } = $props();
</script>

{#each lines as [label, value], i (i)}
  <p class="line">
    <span class="muted">{label}</span><span class="value">{value}</span>
  </p>
{/each}

<style>
  .line {
    display: flex;
    gap: 6px;
    margin: 2px 0;
    font-size: 12px;
    word-break: break-word;
  }

  .value {
    min-width: 0;
    white-space: pre-line;
  }
</style>
