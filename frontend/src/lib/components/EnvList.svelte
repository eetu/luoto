<script lang="ts">
  import Lock from "@lucide/svelte/icons/lock";
  import LockOpen from "@lucide/svelte/icons/lock-open";
  import Plus from "@lucide/svelte/icons/plus";

  import { api } from "$lib/api";
  import VmDiskStatus from "$lib/components/VmDiskStatus.svelte";
  import { openMenu } from "$lib/menu.svelte";
  import {
    act,
    app,
    copyText,
    openLeft,
    openVault,
    plural,
    selectEnv,
    vaultAction,
  } from "$lib/stores/app.svelte";
  import type { EnvRow } from "$lib/types";

  let { onNew }: { onNew: () => void } = $props();

  const vault = $derived(app.overview?.vault ?? null);
  // Secrets the envs' credentials need and the vault lacks: an unlock reads them.
  const missing = $derived(vault?.envs.reduce((n, e) => n + e.missing.length, 0) ?? 0);

  // How many credentials the vault holds secrets for, across envs.
  const bindings = $derived(vault?.envs.reduce((n, e) => n + e.bindings.length, 0) ?? 0);

  function vaultMenu(e: MouseEvent) {
    const locked = vault?.locked ?? true;
    const off = !vault ? "not running" : undefined;
    openMenu(e, "vault", [
      {
        label: "Unlock",
        run: () => void vaultAction("unlock"),
        disabled: !vault || (!locked && missing === 0),
        hint: off ?? (!locked ? (missing ? `${missing} missing` : "unlocked") : undefined),
      },
      {
        label: "Read secrets again",
        run: () => void vaultAction("reload"),
        disabled: !vault || locked,
        hint: off ?? (locked ? "locked" : plural(vault?.loaded_refs.length ?? 0, "secret")),
      },
      {
        label: "Lock",
        run: () => void vaultAction("lock"),
        disabled: !vault || locked,
        hint: off ?? (locked ? "locked" : plural(bindings, "credential")),
      },
    ]);
  }

  function menu(e: MouseEvent, env: EnvRow) {
    const running = env.dev === "running";
    openMenu(e, env.name, [
      {
        label: "Start",
        run: () => void act("starting…", () => api.action(env.name, "up"), `${env.name} is up`),
        disabled: running,
        hint: running ? "running" : undefined,
      },
      {
        label: "Stop",
        run: () => void act("stopping…", () => api.action(env.name, "down"), `${env.name} stopped`),
        disabled: !running,
        hint: running ? undefined : "stopped",
      },
      {
        label: "Rebuild dev container",
        run: () =>
          void act("rebuilding…", () => api.action(env.name, "rebuild"), `${env.name} rebuilt`),
      },
      env.open
        ? {
            label: "Close egress",
            run: () =>
              void act("closing…", () => api.action(env.name, "close"), `${env.name}: rules only`),
            hint: openLeft(env.open) ? `${openLeft(env.open)} left` : "no end",
          }
        : {
            label: "Open egress for 1 h",
            run: () =>
              void act(
                "opening…",
                () => api.action(env.name, "open"),
                `${env.name} reaches any HTTP(S) host for 1 h`,
              ),
          },
      {
        label: "Copy shell command",
        run: () => copyText(`luoto shell -e ${env.name}`),
      },
      {
        label: "Copy VS Code command",
        run: () => copyText(`luoto open -e ${env.name} --with code`),
      },
    ]);
  }
</script>

<nav class="nav">
  <p class="label">envs</p>
  {#each app.overview?.envs ?? [] as env (env.name)}
    <button
      class="row"
      class:selected={app.view === "env" && app.env === env.name}
      onclick={() => void selectEnv(env.name)}
      oncontextmenu={(e) => menu(e, env)}
      title={env.error ?? `${env.name}: dev ${env.dev}, gate ${env.gate}`}
    >
      <span class="dot" class:on={env.dev === "running"} class:err={!!env.error}></span>
      <span class="name">{env.name}</span>
      {#if env.open}
        <span
          class="pill open"
          title="egress is open: any HTTP(S) host no rule allows, but those with your credentials and muted ones"
          >{["open", openLeft(env.open)].filter(Boolean).join(", ")}</span
        >
      {/if}
      {#if env.pending > 0}
        <span class="pill accent" title="access requests waiting for you">{env.pending}</span>
      {/if}
      {#if env.denied_recent > 0}
        <span class="pill" title="blocked attempts in the last 15 minutes">{env.denied_recent}</span
        >
      {/if}
    </button>
  {:else}
    <p class="muted empty">no envs yet</p>
  {/each}
  <button class="btn new" onclick={onNew}><Plus size={14} /> New env</button>

  <p class="label vault-label">vault</p>
  <button
    class="row"
    class:selected={app.view === "vault"}
    onclick={() => openVault()}
    oncontextmenu={vaultMenu}
  >
    {#if !vault}
      <Lock size={14} /><span class="name muted">not running</span>
    {:else if vault.locked && vault.envs.every((e) => e.bindings.length === 0)}
      <Lock size={14} /><span class="name muted">no secrets in use</span>
    {:else if vault.locked}
      <Lock size={14} /><span class="name">locked</span>
    {:else}
      <LockOpen size={14} class="accent-icon" /><span class="name">unlocked</span>
      {#if missing > 0}
        <span class="pill warn" title="secrets the envs need and the vault lacks: unlock reads them"
          >{missing}</span
        >
      {:else}
        <span class="pill" title="secrets in memory">{vault.loaded_refs.length}</span>
      {/if}
    {/if}
  </button>

  <VmDiskStatus />
</nav>

<style>
  .nav {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 14px 10px;
    overflow-y: auto;
  }

  .row {
    display: flex;
    gap: 8px;
    align-items: center;
    padding: 6px 8px;
    border: 1px solid transparent;
    border-radius: var(--halo-radius);
    background: transparent;
    color: var(--halo-text-main);
    text-align: left;
  }

  .row:hover {
    background: var(--halo-bg-light);
  }

  .row.selected {
    border-color: var(--halo-accent);
    background: var(--halo-accent-soft);
  }

  .name {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .dot {
    width: 8px;
    height: 8px;
    flex: none;
    border: 1.5px solid var(--halo-text-muted);
    border-radius: 50%;
  }

  .dot.on {
    border-color: var(--halo-accent);
    background: var(--halo-accent);
  }

  .dot.err {
    border-color: var(--halo-error);
  }

  .pill {
    min-width: 18px;
    padding: 0 6px;
    border-radius: var(--halo-radius-pill, 999px);
    background: var(--halo-bg-light);
    color: var(--halo-text-muted);
    font-size: 11px;
    line-height: 18px;
    text-align: center;
  }

  .pill.warn {
    background: color-mix(in srgb, var(--halo-error) 15%, transparent);
    color: var(--halo-error);
  }

  .pill.accent {
    background: var(--halo-accent);
    color: var(--halo-on-accent);
  }

  .pill.open {
    border: 1px solid var(--halo-accent);
    background: transparent;
    color: var(--halo-accent);
    white-space: nowrap;
  }

  .new {
    align-self: flex-start;
    margin-top: 8px;
  }

  .empty {
    margin: 4px 8px;
    font-size: 13px;
  }

  .vault-label {
    margin-top: 22px;
  }

  :global(.accent-icon) {
    color: var(--halo-accent);
  }
</style>
