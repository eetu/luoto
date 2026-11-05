<script lang="ts">
  import { api } from "$lib/api";
  import { act, app } from "$lib/stores/app.svelte";

  const v = $derived(app.overview?.vault ?? null);
</script>

<div class="panel">
  <p class="label">vault</p>
  {#if !v}
    <p class="muted">
      The vault starts with the first env. It holds root secrets in memory only and hands each gate
      short-lived, scoped credentials.
    </p>
  {:else}
    <h2>{v.locked ? "locked" : "unlocked"}</h2>
    <p class="muted small">
      {v.loaded_refs.length} secret(s) in memory. Nothing is written to disk; one unlock per VM boot.
    </p>
    <div class="actions">
      <button
        class="btn primary"
        onclick={() =>
          void act(
            "unlocking… (your secret store may ask to authorize)",
            () => api.vault("unlock"),
            "vault unlocked",
          )}>unlock</button
      >
      <button
        class="btn"
        onclick={() =>
          void act(
            "locking…",
            () => api.vault("lock"),
            "vault locked; credentialed hosts now get 403",
          )}
        disabled={v.locked}>lock</button
      >
    </div>
    <div class="section">
      <p class="label">bindings per env</p>
      {#each v.envs as e (e.env)}
        <p class="small">
          <b>{e.env}</b>
          <span class="muted">{e.bindings.join(", ") || "none"}</span>
        </p>
        {#if e.missing.length}<p class="warn">
            missing: {e.missing.length} — unlock
          </p>{/if}
      {:else}
        <p class="muted small">no env has credentials yet</p>
      {/each}
    </div>
    <div class="section">
      <p class="label">loaded refs</p>
      {#each v.loaded_refs as r (r)}<p class="small mono">{r}</p>{/each}
    </div>
  {/if}
</div>

<style>
  h2 {
    margin: 0;
    font-size: 15px;
  }
</style>
