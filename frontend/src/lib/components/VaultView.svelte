<script lang="ts">
  import CopyCommand from "$lib/components/CopyCommand.svelte";
  import { authCommands, credentialMenu } from "$lib/credentials";
  import { app, openVault, plural, vaultAction } from "$lib/stores/app.svelte";
  import type { Credential, CredState } from "$lib/types";

  const v = $derived(app.vault);
  const status = $derived(v?.status ?? null);
  const groups = $derived.by(() => {
    const by: [string, Credential[]][] = [];
    for (const c of v?.credentials ?? []) {
      const last = by.at(-1);
      if (last && last[0] === c.env) last[1].push(c);
      else by.push([c.env, [c]]);
    }
    return by;
  });
  // Credentials whose secret the unlocked vault lacks: an unlock reads them.
  const missing = $derived(v?.credentials.filter((c) => c.state === "missing").length ?? 0);
  const without = $derived(
    (app.overview?.envs ?? []).filter((e) => !groups.some(([g]) => g === e.name)),
  );

  const STATES: Record<CredState, { text: string; cls: string; hint: string }> = {
    loaded: { text: "loaded", cls: "plain", hint: "the vault holds it" },
    missing: { text: "missing", cls: "bad", hint: "not read yet: unlock reads it" },
    locked: { text: "locked", cls: "bad", hint: "the vault is locked: unlock" },
    not_up: { text: "env not up", cls: "muted", hint: "registered when the env next starts" },
  };

  function since(t: string): string {
    return new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  const open = (c: Credential) => openVault({ env: c.env, binding: c.binding });

  const onKey = (e: KeyboardEvent, c: Credential) => {
    if (e.key !== "Enter" && e.key !== " ") return;
    e.preventDefault();
    open(c);
  };

  const chosen = (c: Credential) =>
    app.subject.kind === "credential" &&
    app.subject.env === c.env &&
    app.subject.binding === c.binding;
</script>

<section class="surface">
  <header class="bar">
    <h1>vault</h1>
    <span class="muted state">
      {#if !v}
        reading…
      {:else if !status}
        not running: it starts with the first env's <code>luoto up</code>
      {:else if status.locked}
        locked: every env's credentials wait for an unlock
      {:else}
        unlocked since {since(status.started)}, {plural(status.loaded_refs.length, "secret")} in memory,
        shared by every env
      {/if}
    </span>
    <span class="spacer"></span>
    {#if status?.locked}
      <button class="btn primary" onclick={() => void vaultAction("unlock")} disabled={!!app.busy}
        >Unlock</button
      >
    {:else if status}
      {#if missing > 0}
        <button
          class="btn primary"
          title="read the secrets the vault lacks"
          onclick={() => void vaultAction("unlock")}
          disabled={!!app.busy}>Unlock</button
        >
      {/if}
      <button
        class="btn"
        title="after rotating a secret in your secret store"
        onclick={() => void vaultAction("reload")}
        disabled={!!app.busy}>Reload</button
      >
      <button class="btn" onclick={() => void vaultAction("lock")} disabled={!!app.busy}
        >Lock</button
      >
    {/if}
  </header>

  <div class="table-wrap">
    {#if v && groups.length === 0 && v.unused.length === 0}
      <p class="empty muted">No env has credentials. An agent's or a repo's are added with:</p>
      {#each without as e (e.name)}
        <div class="auth">
          {#each authCommands(e.name, e) as cmd (cmd)}<CopyCommand {cmd} />{/each}
        </div>
      {/each}
    {:else if v}
      <table class="list">
        <thead>
          <tr>
            <th>credential</th>
            <th>kept in</th>
            <th>goes to</th>
            <th>state</th>
          </tr>
        </thead>
        <tbody>
          {#each groups as [env, creds] (env)}
            <tr class="group"><td colspan="4">{env}</td></tr>
            {#each creds as c (c.binding)}
              {@const st = STATES[c.state]}
              <tr
                class:selected={chosen(c)}
                tabindex="0"
                onclick={() => open(c)}
                onkeydown={(e) => onKey(e, c)}
                oncontextmenu={(e) => credentialMenu(e, c)}
              >
                <td>
                  <code>{c.binding}</code>
                  <div class="why">{c.what}</div>
                </td>
                <td class="mono">{c.kept}</td>
                <td>{c.hosts.join(", ") || "—"}</td>
                <td><span class="chip {st.cls}" title={st.hint}>{st.text}</span></td>
              </tr>
            {/each}
          {/each}
          {#if v.unused.length}
            <tr class="group"><td colspan="4">in memory, no env uses it</td></tr>
            {#each v.unused as r (r)}
              <tr>
                <td class="muted">left from a credential since changed</td>
                <td class="mono">{r}</td>
                <td class="muted">nowhere</td>
                <td><span class="chip muted" title="lock and unlock to drop it">unused</span></td>
              </tr>
            {/each}
          {/if}
        </tbody>
      </table>
      {#each without as e (e.name)}
        <p class="muted small note">{e.name}: no credentials</p>
        <div class="auth">
          {#each authCommands(e.name, e) as cmd (cmd)}<CopyCommand {cmd} />{/each}
        </div>
      {/each}
      {#each v.errors as e, n (n)}<p class="warn note">{e}</p>{/each}
    {/if}
  </div>
</section>

<style>
  .state {
    font-size: 12px;
  }

  .spacer {
    flex: 1;
  }

  td {
    overflow-wrap: anywhere;
  }

  tr.group td {
    padding-top: 14px;
    color: var(--halo-text-muted);
    font-family: var(--halo-font-heading);
    font-size: 11px;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }

  .note {
    margin: 10px 8px 4px;
  }

  .auth {
    max-width: 480px;
    margin: 0 8px;
  }

  .empty ~ .auth {
    margin: 0 auto 8px;
  }
</style>
