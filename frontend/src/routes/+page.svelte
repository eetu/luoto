<script lang="ts">
  import Bell from "@lucide/svelte/icons/bell";
  import BellOff from "@lucide/svelte/icons/bell-off";
  import { onMount } from "svelte";

  import { bootToken } from "$lib/api";
  import EgressView from "$lib/components/EgressView.svelte";
  import EnvList from "$lib/components/EnvList.svelte";
  import EnvPanel from "$lib/components/EnvPanel.svelte";
  import HostPanel from "$lib/components/HostPanel.svelte";
  import NewEnvDialog from "$lib/components/NewEnvDialog.svelte";
  import RequestPanel from "$lib/components/RequestPanel.svelte";
  import SetupView from "$lib/components/SetupView.svelte";
  import VaultPanel from "$lib/components/VaultPanel.svelte";
  import VaultView from "$lib/components/VaultView.svelte";
  import Wordmark from "$lib/components/Wordmark.svelte";
  import { noticeRequests, notifications, toggleNotifications } from "$lib/notify.svelte";
  import { app, startSync } from "$lib/stores/app.svelte";

  let showNew = $state(false);
  const hasEnvs = $derived((app.overview?.envs.length ?? 0) > 0);

  $effect(() => {
    document.title = app.overview?.instance ?? "luoto";
  });

  $effect(() => {
    if (app.overview) {
      const { envs, instance, desktop_notifications } = app.overview;
      noticeRequests(envs, instance, desktop_notifications);
    }
  });

  onMount(() => {
    bootToken();
    return startSync();
  });

  // Escape ladder for the page: a credential falls back to the vault, a host or request to
  // the env.
  function onKeydown(e: KeyboardEvent) {
    if (e.key !== "Escape" || showNew) return;
    if (app.subject.kind === "credential") app.subject = { kind: "vault" };
    else if (app.subject.kind === "host" || app.subject.kind === "request") {
      app.subject = { kind: "env" };
    }
  }
</script>

<svelte:window onkeydown={onKeydown} />

{#if app.unauthorized}
  <main class="locked">
    <Wordmark />
    <p>
      Open the link printed by <code>luoto ui</code> — it carries this session's access token.
    </p>
  </main>
{:else}
  <header class="top">
    <Wordmark name={app.overview?.instance} />
    <span class="spacer"></span>
    {#if app.busy}<span class="busy">{app.busy}</span>{/if}
    {#if app.overview?.desktop_notifications}
      <button
        class="icon"
        aria-label="browser notifications"
        title="desktop notifications show access requests; notifications = false in config.toml hands them to this browser"
        disabled
      >
        <Bell size={16} />
      </button>
    {:else}
      <button
        class="icon"
        class:active={notifications.on}
        aria-label="browser notifications"
        aria-pressed={notifications.on}
        title={notifications.on
          ? "browser notifications for access requests: on"
          : "browser notifications for access requests: off"}
        onclick={() => void toggleNotifications()}
      >
        {#if notifications.on}<Bell size={16} />{:else}<BellOff size={16} />{/if}
      </button>
    {/if}
  </header>

  <div class="shell">
    <EnvList onNew={() => (showNew = true)} />
    {#if !app.overview}
      <main class="center"><p class="muted pad">connecting…</p></main>
    {:else if !hasEnvs}
      <main class="center"><SetupView onNew={() => (showNew = true)} /></main>
    {:else if app.view === "vault"}
      <main class="center"><VaultView /></main>
    {:else}
      <main class="center"><EgressView /></main>
    {/if}
    {#if hasEnvs || app.view === "vault"}
      <aside class="subject">
        {#if app.subject.kind === "host"}
          <HostPanel host={app.subject.host} />
        {:else if app.subject.kind === "request"}
          <RequestPanel id={app.subject.id} />
        {:else if app.subject.kind === "vault" || app.subject.kind === "credential"}
          <VaultPanel />
        {:else}
          <EnvPanel />
        {/if}
      </aside>
    {/if}
  </div>

  <footer class="status">
    <span class:error={app.status?.error} role="status">{app.status?.text ?? ""}</span>
    <span class="spacer"></span>
    <span class="muted">{app.overview?.runtime ?? ""}</span>
    <span class="live" class:on={app.live} title={app.live ? "live events" : "reconnecting"}></span>
  </footer>
{/if}

<NewEnvDialog open={showNew} onClose={() => (showNew = false)} />

<style>
  .top {
    display: flex;
    gap: 12px;
    align-items: center;
    padding: calc(10px + env(safe-area-inset-top)) 16px 10px;
    border-bottom: 1px solid var(--halo-border);
    background: var(--halo-bg-main);
  }

  .spacer {
    flex: 1;
  }

  .busy {
    color: var(--halo-accent);
    font-size: 12px;
  }

  .icon {
    display: inline-flex;
    padding: 4px;
    border: 1px solid transparent;
    border-radius: var(--halo-radius);
    background: none;
    color: var(--halo-text-muted);
  }

  .icon:hover {
    color: var(--halo-text-main);
  }

  .icon:disabled {
    opacity: 0.5;
    cursor: default;
  }

  .icon.active {
    background: var(--halo-accent-soft);
    color: var(--halo-accent);
  }

  .shell {
    display: grid;
    flex: 1;
    grid-template-columns: 220px minmax(0, 1fr) 340px;
    min-height: 0;
  }

  .center {
    display: flex;
    flex-direction: column;
    min-height: 0;
    overflow: hidden;
  }

  .pad {
    padding: 20px;
  }

  .subject {
    padding: 14px 16px;
    overflow-y: auto;
    border-left: 1px solid var(--halo-border);
    background: var(--halo-bg-main);
  }

  :global(.nav) {
    border-right: 1px solid var(--halo-border);
    background: var(--halo-bg-main);
  }

  .status {
    display: flex;
    gap: 10px;
    align-items: center;
    padding: 5px 14px calc(5px + env(safe-area-inset-bottom));
    border-top: 1px solid var(--halo-border);
    background: var(--halo-bg-main);
    font-size: 12px;
  }

  .live {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--halo-text-muted);
  }

  .live.on {
    background: var(--halo-accent);
  }

  .locked {
    display: grid;
    gap: 12px;
    place-content: center;
    height: 100%;
    text-align: center;
  }

  @media (max-width: 1000px) {
    .shell {
      grid-template-columns: 180px minmax(0, 1fr);
    }

    .subject {
      grid-column: 1 / -1;
      border-top: 1px solid var(--halo-border);
      border-left: none;
    }
  }
</style>
