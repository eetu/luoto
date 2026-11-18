<script lang="ts">
  import { api } from "$lib/api";
  import CopyCommand from "$lib/components/CopyCommand.svelte";
  import { errorText, say } from "$lib/stores/app.svelte";
  import type { RuntimeChoice, SetupInfo } from "$lib/types";

  // First run: what this machine has and the command that sets luoto up on the runtime
  // picked, as `luoto setup` asks it. Shown until there is an env. Installing a runtime is
  // the user's: one that isn't ready says what it lacks and links to its own install page.
  let { onNew }: { onNew: () => void } = $props();

  let info = $state<SetupInfo | null>(null);
  let picked = $state<RuntimeChoice | null>(null);

  $effect(() => {
    void api.setup().then(
      (s) => (info = s),
      (e) => say(errorText(e), true),
    );
  });

  const options = $derived(info?.runtimes ?? []);
  const choice = $derived(picked ?? options.find((o) => o.selected)?.runtime ?? null);
  const option = $derived(options.find((o) => o.runtime === choice));
  const usable = $derived(options.some((o) => o.ready));
  const ready = $derived(!!info?.images_ok && usable);
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
      <p class="muted small">images: {info.images_ok ? "present" : "missing"}</p>
    </div>

    <div class="halo-card card">
      <fieldset class="choices">
        <legend class="label">run envs on</legend>
        {#each options as o (o.runtime)}
          <label class="choice" class:on={choice === o.runtime} class:off={!o.ready}>
            <input
              type="radio"
              name="runtime"
              value={o.runtime}
              checked={choice === o.runtime}
              disabled={!o.ready}
              onchange={() => (picked = o.runtime)}
            />
            <span>
              <b>{o.label}</b>
              {#if o.current}<span class="tag">current</span>{/if}
              <span class="muted small status">{o.status}</span>
              <span class="muted small desc">{o.description}</span>
              {#if !o.ready}
                <span class="small desc">
                  luoto runs on {o.min} or later:
                  <!-- eslint-disable-next-line svelte/no-navigation-without-resolve -- the runtime's own site -->
                  <a class="link" href={o.url} target="_blank" rel="noopener noreferrer">{o.url}</a>
                </span>
              {/if}
            </span>
          </label>
        {/each}
      </fieldset>

      {#if !usable}
        <p class="small finish">install one, then, in a terminal:</p>
        <CopyCommand cmd="luoto setup" />
      {:else if option && (!ready || !option.current)}
        {#if option.runtime === "container"}
          <p class="note">setup starts its service, whose first start downloads its kernel</p>
        {/if}
        <p class="small finish">in a terminal:</p>
        <CopyCommand cmd={option.setup} />
      {/if}
    </div>

    {#if ready}
      <button class="btn primary" onclick={onNew}>Create your first env</button>
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

  .choice.off {
    cursor: default;
  }

  .choice input {
    accent-color: var(--halo-accent);
  }

  .status {
    margin-left: 4px;
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
</style>
