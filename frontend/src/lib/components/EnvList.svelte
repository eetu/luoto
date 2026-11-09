<script lang="ts">
  import Lock from "@lucide/svelte/icons/lock";
  import LockOpen from "@lucide/svelte/icons/lock-open";
  import Plus from "@lucide/svelte/icons/plus";

  import { api } from "$lib/api";
  import VmDiskStatus from "$lib/components/VmDiskStatus.svelte";
  import { openMenu } from "$lib/menu.svelte";
  import { act, app, copyText, selectEnv } from "$lib/stores/app.svelte";
  import type { EnvRow } from "$lib/types";

  let { onNew }: { onNew: () => void } = $props();

  const vault = $derived(app.overview?.vault ?? null);

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
        hint: "volumes kept",
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
      class:selected={app.env === env.name && app.subject.kind !== "vault"}
      onclick={() => void selectEnv(env.name)}
      oncontextmenu={(e) => menu(e, env)}
      title={env.error ?? `${env.name}: dev ${env.dev}, gate ${env.gate}`}
    >
      <span class="dot" class:on={env.dev === "running"} class:err={!!env.error}></span>
      <span class="name">{env.name}</span>
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
  <button class="btn new" onclick={onNew}><Plus size={14} /> new env</button>

  <p class="label vault-label">vault</p>
  <button
    class="row"
    class:selected={app.subject.kind === "vault"}
    onclick={() => (app.subject = { kind: "vault" })}
  >
    {#if !vault}
      <Lock size={14} /><span class="name muted">not running</span>
    {:else if vault.locked && vault.envs.every((e) => e.bindings.length === 0)}
      <Lock size={14} /><span class="name muted">no secrets in use</span>
    {:else if vault.locked}
      <Lock size={14} /><span class="name">locked</span>
    {:else}
      <LockOpen size={14} class="accent-icon" /><span class="name">unlocked</span>
      <span class="pill">{vault.loaded_refs.length}</span>
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

  .pill.accent {
    background: var(--halo-accent);
    color: var(--halo-on-accent);
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
