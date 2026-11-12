<script lang="ts">
  import Copy from "@lucide/svelte/icons/copy";

  import { app, copyText } from "$lib/stores/app.svelte";

  const d = $derived(app.detail);
</script>

{#if d}
  <div class="section">
    <p class="label">variables</p>
    {#if d.variables.length === 0}
      <p class="muted small">
        none of your own; a plain one, or a secret luoto asks where it is kept:
      </p>
      {#each [`luoto var set -e ${d.name} NAME=value`, `luoto var set -e ${d.name} NAME`] as cmd (cmd)}
        <button class="cmd" onclick={() => copyText(cmd)} title="copy"
          ><code>{cmd}</code><Copy size={12} /></button
        >
      {/each}
    {:else}
      <dl>
        {#each d.variables as v (v.name)}
          <dt><code>{v.name}</code></dt>
          {#if v.kind === "secret"}
            <dd><span class="muted">secret from</span> {v.kept}</dd>
          {:else if v.value === ""}
            <dd class="muted">(empty)</dd>
          {:else}
            <dd>{v.value}</dd>
          {/if}
        {/each}
      </dl>
      <p class="muted small">Any code in the env can read them.</p>
    {/if}
    {#if d.luoto_variables.length}
      <p class="muted small">set by luoto: {d.luoto_variables.join(", ")}</p>
    {/if}
  </div>
{/if}

<style>
  dl {
    display: grid;
    grid-template-columns: minmax(0, 40%) minmax(0, 1fr);
    gap: 4px 10px;
    margin: 0;
    font-size: 13px;
  }

  dt,
  dd {
    margin: 0;
    min-width: 0;
    overflow-wrap: anywhere;
  }

  .cmd {
    width: 100%;
    margin-bottom: 4px;
  }
</style>
