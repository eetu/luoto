<script lang="ts">
  import CopyCommand from "$lib/components/CopyCommand.svelte";
  import { authCommands, credentialMenu } from "$lib/credentials";
  import { app, openVault, vaultAction } from "$lib/stores/app.svelte";

  const d = $derived(app.detail);
  const row = $derived(app.overview?.envs.find((e) => e.name === d?.name));
  // The vault lacks some of them (locked, or not read yet): an unlock reads them.
  const waiting = $derived(
    d?.credentials.filter((c) => c.state === "missing" || c.state === "locked").length ?? 0,
  );
</script>

{#if d}
  <div class="section">
    <p class="label">credentials</p>
    {#if d.credentials.length === 0}
      <p class="muted small">none: the gate adds nothing. An agent's or a repo's:</p>
      {#each authCommands(d.name, row) as cmd (cmd)}<CopyCommand {cmd} />{/each}
    {:else}
      {#each d.credentials as c (c.binding)}
        <button
          class="cred"
          onclick={() => openVault({ env: c.env, binding: c.binding })}
          oncontextmenu={(e) => credentialMenu(e, c)}
          title="where it is kept, where it goes, how to change it"
        >
          <span class="small"><code>{c.binding}</code> → {c.hosts.join(", ") || "no host"}</span>
          <span class="muted small kept"
            >{c.kept}{c.state === "missing" || c.state === "locked"
              ? ", not in the vault"
              : ""}</span
          >
        </button>
        {#if c.change}<CopyCommand cmd={c.change} />{/if}
      {/each}
      {#if waiting > 0}
        <div class="unlock">
          <p class="warn">the vault lacks {waiting} of them</p>
          <button class="btn" onclick={() => void vaultAction("unlock")} disabled={!!app.busy}
            >Unlock</button
          >
        </div>
      {/if}
    {/if}
  </div>
{/if}

<style>
  .cred {
    display: flex;
    flex-direction: column;
    gap: 1px;
    width: 100%;
    padding: 4px 6px;
    border: 1px solid transparent;
    border-radius: var(--halo-radius);
    background: none;
    color: var(--halo-text-main);
    font: inherit;
    text-align: left;
    cursor: pointer;
  }

  .cred:hover {
    background: var(--halo-bg-light);
  }

  .kept {
    overflow-wrap: anywhere;
  }

  .unlock {
    display: flex;
    gap: 10px;
    align-items: center;
    justify-content: space-between;
    margin-top: 6px;
  }

  .unlock .warn {
    margin: 0;
  }
</style>
