<script lang="ts">
  import Copy from "@lucide/svelte/icons/copy";

  import { api } from "$lib/api";
  import { act, copyText, errorText, say } from "$lib/stores/app.svelte";
  import type { RuntimeChoice, SetupInfo } from "$lib/types";

  // First run: what this machine has, what luoto recommends, and the one confirmed step to
  // get there. Shown until there is an env. Where Apple's container runs, setup's choice of
  // runtime comes first, as `luoto setup` asks it.
  let { onNew }: { onNew: () => void } = $props();

  let info = $state<SetupInfo | null>(null);
  let output = $state("");
  let confirming = $state(false);
  let picked = $state<RuntimeChoice | null>(null);

  $effect(() => {
    void api.setup().then(
      (s) => (info = s),
      (e) => say(errorText(e), true),
    );
  });

  const offer = $derived(info?.runtimes ?? null);
  const choice = $derived(
    offer ? (picked ?? offer.options.find((o) => o.selected)?.runtime ?? null) : null,
  );
  const option = $derived(offer?.options.find((o) => o.runtime === choice));
  const apple = $derived(choice === "container" ? offer?.apple_need : undefined);
  const rec = $derived(choice === "podman" && offer ? offer.podman : info?.recommendation);
  const installs = $derived(apple === undefined ? rec?.install : apple?.install);
  const found = $derived(
    info ? [...info.detection.runtimes, ...(offer?.apple ? [offer.apple] : [])] : [],
  );
  const ready = $derived(!!info?.images_ok && found.some((r) => r.reachable && r.version_ok));

  function pick(runtime: RuntimeChoice) {
    picked = runtime;
    confirming = false;
    output = "";
  }

  async function install() {
    confirming = false;
    await act(
      "installing…",
      async () => {
        const r = await api.setupInstall(choice);
        output = r.output;
        info = await api.setup();
      },
      "installed — re-checking",
    );
  }
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
      {#each found as r (r.name)}
        <p class:ok={r.reachable && r.version_ok}>
          <b>{r.name}</b>
          {r.version ? r.version.join(".") : "?"}
          <span class="muted">— {r.detail}</span>
        </p>
      {:else}
        <p class="muted">no container runtime found</p>
      {/each}
      <p class="muted small">
        images: {info.images_ok ? "present" : offer ? "missing" : "missing — run `luoto setup`"}
      </p>
    </div>

    <div class="halo-card card">
      {#if offer}
        <fieldset class="choices">
          <legend class="label">run envs on</legend>
          {#each offer.options as o (o.runtime)}
            <label class="choice" class:on={choice === o.runtime}>
              <input
                type="radio"
                name="runtime"
                value={o.runtime}
                checked={choice === o.runtime}
                onchange={() => pick(o.runtime)}
              />
              <span>
                <b>{o.label}</b>
                {#if o.recommended}<span class="tag">recommended</span>{/if}
                {#if o.current}<span class="tag">current</span>{/if}
                <span class="muted small desc">{o.description}</span>
              </span>
            </label>
          {/each}
        </fieldset>
      {:else}
        <p class="label">recommendation</p>
      {/if}

      {#if apple !== undefined}
        {#if apple}
          <p><b>luoto needs Apple's container {apple.min} or later</b></p>
          {#if !apple.install}
            <p class="note">
              install it from <code>https://github.com/apple/container/releases</code>
            </p>
          {/if}
        {/if}
        <p class="note">
          setup starts its service (<code>container system start --enable-kernel-install</code>),
          whose first start downloads its kernel
        </p>
      {:else if rec}
        <p><b>{rec.summary}</b></p>
        <ul>
          {#each rec.reasons as r (r)}<li>{r}</li>{/each}
        </ul>
        {#each rec.notes as n (n)}<p class="note">{n}</p>{/each}
      {/if}

      {#if installs}
        <p class="small">
          installs with: <code>{installs.join(" ")}</code>
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

      {#if option && (!ready || !option.current)}
        <p class="small finish">then, in a terminal:</p>
        <button class="cmd" title="copy" onclick={() => copyText(option.setup)}
          ><code>{option.setup}</code><Copy size={12} /></button
        >
      {/if}
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

  .choices {
    display: flex;
    flex-direction: column;
    gap: 6px;
    margin: 0 0 10px;
    padding: 0;
    border: none;
  }

  .choice {
    display: flex;
    gap: 8px;
    align-items: baseline;
    padding: 6px 8px;
    border: 1px solid var(--halo-border);
    border-radius: var(--halo-radius);
    cursor: pointer;
  }

  .choice.on {
    border-color: var(--halo-accent);
    background: var(--halo-accent-soft);
  }

  .choice input {
    accent-color: var(--halo-accent);
  }

  .desc {
    display: block;
  }

  .tag {
    margin-left: 4px;
    padding: 1px 7px;
    border-radius: var(--halo-radius-pill, 999px);
    background: var(--halo-bg-light);
    color: var(--halo-text-muted);
    font-size: 11px;
  }

  .finish {
    margin-top: 10px;
  }

  pre {
    max-height: 200px;
    overflow: auto;
    font-size: 11px;
  }
</style>
