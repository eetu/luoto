<script lang="ts">
  import { api } from "$lib/api";
  import { openMenu } from "$lib/menu.svelte";
  import {
    act,
    app,
    copyText,
    openVault,
    refreshVault,
    say,
    selectEnv,
  } from "$lib/stores/app.svelte";
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
    (app.overview?.envs ?? []).map((e) => e.name).filter((n) => !groups.some(([g]) => g === n)),
  );

  const STATES: Record<CredState, { text: string; cls: string; hint: string }> = {
    loaded: { text: "loaded", cls: "loaded", hint: "the vault holds it" },
    missing: { text: "missing", cls: "missing", hint: "not read yet: unlock reads it" },
    locked: { text: "locked", cls: "missing", hint: "the vault is locked: unlock" },
    not_up: { text: "env not up", cls: "idle", hint: "registered at the env's next `luoto up`" },
  };

  function since(t: string): string {
    return new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  async function unlock() {
    await act(
      "unlocking… (your secret store may ask to authorize)",
      () => api.vault("unlock"),
      "vault unlocked",
    );
    void refreshVault();
  }

  async function lock() {
    await act("locking…", () => api.vault("lock"), "vault locked; credentialed hosts now get 403");
    void refreshVault();
  }

  async function reload() {
    const r = await act("reading secrets again… (your secret store may ask)", api.reloadVault);
    if (!r) return;
    const failed = r.failed.length ? `; not read: ${r.failed.join("; ")}` : "";
    say(`read ${r.read}: ${r.changed} changed${failed}`, r.failed.length > 0);
    void refreshVault();
  }

  function menu(e: MouseEvent, c: Credential) {
    openMenu(e, `${c.env}: ${c.binding}`, [
      {
        label: "Copy change command",
        run: () => c.change && copyText(c.change),
        disabled: !c.change,
        hint: c.change ? undefined : "no command yet: the env's own file",
      },
      { label: "Copy where it is kept", run: () => copyText(c.kept) },
      { label: `Show ${c.env}'s egress`, run: () => void selectEnv(c.env) },
    ]);
  }

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
        unlocked since {since(status.started)}, {status.loaded_refs.length} secret(s) in memory, shared
        by every env
      {/if}
    </span>
    <span class="spacer"></span>
    {#if status?.locked}
      <button class="btn primary" onclick={() => void unlock()} disabled={!!app.busy}>unlock</button
      >
    {:else if status}
      {#if missing > 0}
        <button
          class="btn primary"
          title="read the secrets the vault lacks"
          onclick={() => void unlock()}
          disabled={!!app.busy}>unlock</button
        >
      {/if}
      <button
        class="btn"
        title="after rotating a secret in your secret store"
        onclick={() => void reload()}
        disabled={!!app.busy}>reload</button
      >
      <button class="btn" onclick={() => void lock()} disabled={!!app.busy}>lock</button>
    {/if}
  </header>

  <div class="table-wrap">
    {#if v && groups.length === 0 && v.unused.length === 0}
      <p class="empty muted">
        No env has credentials. An agent's or a repo's are added with
        <code>luoto agent auth</code> and <code>luoto repo auth</code>.
      </p>
    {:else if v}
      <table>
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
                onclick={() => openVault({ env: c.env, binding: c.binding })}
                oncontextmenu={(e) => menu(e, c)}
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
                <td><span class="chip idle" title="lock and unlock to drop it">unused</span></td>
              </tr>
            {/each}
          {/if}
        </tbody>
      </table>
      {#if without.length}
        <p class="muted small note">{without.join(", ")}: no credentials</p>
      {/if}
      {#each v.errors as e, n (n)}<p class="warn note">{e}</p>{/each}
    {/if}
  </div>
</section>

<style>
  .surface {
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
  }

  .bar {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    align-items: center;
    padding: 14px 18px 10px;
  }

  h1 {
    margin: 0;
    font-size: 16px;
    font-weight: 600;
  }

  .state {
    font-size: 12px;
  }

  .spacer {
    flex: 1;
  }

  .table-wrap {
    flex: 1;
    min-height: 0;
    padding: 0 18px 18px;
    overflow: auto;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }

  th {
    position: sticky;
    top: 0;
    padding: 6px 8px;
    border-bottom: 1px solid var(--halo-border);
    background: var(--halo-body);
    color: var(--halo-text-muted);
    font-family: var(--halo-font-heading);
    font-size: 11px;
    font-weight: 500;
    letter-spacing: 0.04em;
    text-align: left;
    text-transform: uppercase;
  }

  td {
    padding: 7px 8px;
    border-bottom: 1px solid var(--halo-border);
    vertical-align: top;
    overflow-wrap: anywhere;
  }

  tbody tr:not(.group):hover {
    background: var(--halo-bg-light);
  }

  tr.selected {
    background: var(--halo-accent-soft);
  }

  tr.group td {
    padding-top: 14px;
    color: var(--halo-text-muted);
    font-family: var(--halo-font-heading);
    font-size: 11px;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }

  .why {
    margin-top: 2px;
    color: var(--halo-text-muted);
    font-size: 12px;
  }

  .chip {
    display: inline-block;
    padding: 1px 7px;
    border-radius: var(--halo-radius-pill, 999px);
    font-size: 11px;
    white-space: nowrap;
  }

  .chip.loaded {
    background: var(--halo-bg-light);
    color: var(--halo-text-main);
  }

  .chip.missing {
    background: color-mix(in srgb, var(--halo-error) 15%, transparent);
    color: var(--halo-error);
  }

  .chip.idle {
    border: 1px dashed var(--halo-border);
    color: var(--halo-text-muted);
  }

  .empty {
    margin: 30px 0;
    text-align: center;
  }

  .note {
    margin: 10px 8px 0;
  }
</style>
