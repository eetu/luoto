<script lang="ts">
  import { api } from "$lib/api";
  import { act, errorText, say } from "$lib/stores/app.svelte";
  import type { SetupInfo } from "$lib/types";

  // First run: what this machine has, what luoto recommends, and the one confirmed step to
  // get there. Shown until there is an env.
  let { onNew }: { onNew: () => void } = $props();

  let info = $state<SetupInfo | null>(null);
  let output = $state("");
  let confirming = $state(false);

  $effect(() => {
    void api.setup().then(
      (s) => (info = s),
      (e) => say(errorText(e), true),
    );
  });

  async function install() {
    confirming = false;
    await act(
      "installing…",
      async () => {
        const r = await api.setupInstall();
        output = r.output;
        info = await api.setup();
      },
      "installed — re-checking",
    );
  }

  const ready = $derived(
    !!info && info.detection.runtimes.some((r) => r.reachable && r.version_ok) && info.images_ok,
  );
</script>

<section class="setup">
  <h1>set up luoto</h1>
  {#if !info}
    <p class="muted">checking this machine…</p>
  {:else}
    <div class="halo-card card">
      <p class="label">this machine</p>
      <p>
        {info.detection.os}
        {info.detection.arch}{info.detection.distro ? `, ${info.detection.distro}` : ""}, {info
          .detection.cpus} CPUs
      </p>
      {#each info.detection.runtimes as r (r.name)}
        <p class:ok={r.reachable && r.version_ok}>
          <b>{r.name}</b>
          {r.version ? r.version.join(".") : "?"}
          <span class="muted">— {r.detail}</span>
        </p>
      {:else}
        <p class="muted">no container runtime found</p>
      {/each}
      <p class="muted small">
        images: {info.images_ok ? "present" : "missing — run `luoto setup`"}
      </p>
    </div>

    <div class="halo-card card">
      <p class="label">recommendation</p>
      <p><b>{info.recommendation.summary}</b></p>
      <ul>
        {#each info.recommendation.reasons as r (r)}<li>{r}</li>{/each}
      </ul>
      {#each info.recommendation.notes as n (n)}<p class="note">{n}</p>{/each}
      {#if info.recommendation.install}
        <p class="small">
          installs with: <code>{info.recommendation.install.join(" ")}</code>
        </p>
        {#if confirming}
          <p class="small">This runs on your machine (not sandboxed), from the package manager.</p>
          <div class="actions">
            <button class="btn primary" onclick={install}>run it</button>
            <button class="btn" onclick={() => (confirming = false)}>cancel</button>
          </div>
        {:else}
          <button class="btn primary" onclick={() => (confirming = true)}>install…</button>
        {/if}
      {/if}
      {#if output}<pre>{output}</pre>{/if}
    </div>

    {#if ready}
      <button class="btn primary" onclick={onNew}>create your first env</button>
    {/if}
  {/if}
</section>

<style>
  .setup {
    max-width: 640px;
    padding: 24px 28px;
    overflow-y: auto;
  }

  h1 {
    margin: 0 0 14px;
    font-size: 18px;
  }

  .card {
    margin-bottom: 14px;
  }

  .card p {
    margin: 4px 0;
  }

  .ok b {
    color: var(--halo-accent);
  }

  .small {
    font-size: 12px;
  }

  .note {
    color: var(--halo-text-muted);
    font-size: 12px;
  }

  .actions {
    display: flex;
    gap: 8px;
  }

  pre {
    max-height: 200px;
    overflow: auto;
    font-size: 11px;
  }
</style>
