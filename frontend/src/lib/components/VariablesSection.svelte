<script lang="ts">
  import { app } from "$lib/stores/app.svelte";

  const d = $derived(app.detail);
  const secrets = $derived(d?.variables.filter((v) => v.kind === "secret").length ?? 0);
</script>

{#if d}
  <div class="section">
    <p class="label">variables</p>
    {#if d.variables.length === 0}
      <p class="muted small">
        none of your own: <code>luoto var set NAME=value</code>, or <code>luoto var set NAME</code>
        for a secret
      </p>
    {:else}
      <dl>
        {#each d.variables as v (v.name)}
          <dt><code>{v.name}</code></dt>
          {#if v.kind === "plain"}
            <dd>{v.value}</dd>
          {:else}
            <dd><span class="muted">secret from</span> {v.kept}</dd>
          {/if}
        {/each}
      </dl>
      {#if secrets > 0}
        <p class="warn">
          {secrets === 1 ? "The secret is" : "Secrets are"} readable by any code in the env.
        </p>
      {/if}
    {/if}
    {#if d.luoto_variables.length}
      <p class="muted small">set by luoto: {d.luoto_variables.join(", ")}</p>
    {/if}
  </div>
{/if}

<style>
  dl {
    display: grid;
    grid-template-columns: max-content 1fr;
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
</style>
