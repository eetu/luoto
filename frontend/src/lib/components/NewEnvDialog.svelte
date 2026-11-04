<script lang="ts">
  import { api } from "$lib/api";
  import Modal from "$lib/components/Modal.svelte";
  import { act, app, selectEnv } from "$lib/stores/app.svelte";
  import type { Proposal } from "$lib/types";

  let { open, onClose }: { open: boolean; onClose: () => void } = $props();

  let dir = $state("");
  let name = $state("");
  let ports = $state("");
  let presets = $state<string[]>(["debian", "github", "toolchains"]);
  let presetsTouched = $state(false);
  let agents = $state<string[]>([]);
  let proposal = $state<Proposal | null>(null);
  /** The folder and name `proposal` answers. */
  let proposedFor = $state<string | null>(null);
  let detectError = $state<string | null>(null);

  const query = $derived({ dir: dir.trim() || undefined, name: name.trim() || undefined });
  const queryKey = $derived(JSON.stringify(query));
  // Creating accepts the folder's luoto.toml, so it waits until the one on screen is this
  // folder's (the API refuses any other by its sha).
  const ready = $derived(proposal !== null && proposedFor === queryKey);

  // What the folder says about itself: suggested presets (until the user picks their own),
  // the toolchains its version files pin and its luoto.toml.
  $effect(() => {
    const body = query;
    const key = queryKey;
    if (!body.dir) {
      proposal = null;
      proposedFor = null;
      detectError = null;
      return;
    }
    let stale = false;
    const timer = setTimeout(() => {
      api
        .detect(body)
        .then((p) => {
          if (stale) return;
          proposal = p;
          proposedFor = key;
          detectError = null;
          if (!presetsTouched) presets = p.presets.map((x) => x.name);
        })
        .catch((e: unknown) => {
          if (stale) return;
          proposal = null;
          proposedFor = null;
          detectError = e instanceof Error ? e.message : String(e);
        });
    }, 300);
    return () => {
      stale = true;
      clearTimeout(timer);
    };
  });

  function reason(preset: string): string | null {
    return proposal?.presets.find((p) => p.name === preset)?.reason ?? null;
  }

  const suggested = $derived(
    dir
      .trim()
      .replace(/[/\\]+$/, "")
      .split(/[/\\]/)
      .pop()
      ?.toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "") ?? "",
  );
  const finalName = $derived(name.trim() || suggested);
  const valid = $derived(
    /^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$/.test(finalName) && dir.trim() !== "" && ready,
  );

  function toggle(list: string[], v: string): string[] {
    return list.includes(v) ? list.filter((x) => x !== v) : [...list, v];
  }

  async function create() {
    if (!valid || !proposal) return;
    const body = {
      ...query,
      presets,
      agents,
      ports: ports
        .split(/[\s,]+/)
        .filter(Boolean)
        .map(Number)
        .filter((n) => n > 0 && n < 65536),
      project_sha: proposal.project_sha ?? undefined,
    };
    onClose();
    let created = finalName;
    const ok = await act(
      `creating ${finalName}…`,
      async () => {
        created = (await api.createEnv(body)).name;
      },
      `${finalName} is up`,
    );
    if (ok) await selectEnv(created);
  }
</script>

<Modal {open} title="new env" {onClose} onConfirm={create}>
  {#snippet body()}
    <div class="form">
      <div class="choice">
        <span>folder</span>
        <div>
          <input type="text" bind:value={dir} placeholder="~/dev/my-project" />
          <p class="hint">
            {#if proposal?.new_folder}
              New or empty: luoto creates it if needed, and the env starts empty. Pick its egress
              below.
            {:else}
              Copied in, git history included; the sandbox never writes to it. Push from the env, or
              bring files back with a reviewed pull.
            {/if}
          </p>
          {#if detectError}<p class="hint error">{detectError}</p>{/if}
        </div>
      </div>
      <label>
        <span>name</span>
        <input type="text" bind:value={name} placeholder={suggested || "my-project"} />
      </label>
      <label>
        <span>ports</span>
        <input type="text" bind:value={ports} placeholder="5173, 3000" />
      </label>
      <div class="choice">
        <span>egress</span>
        <div class="chips">
          {#each app.meta?.presets ?? [] as p (p.name)}
            <button
              type="button"
              class="chip"
              class:on={presets.includes(p.name)}
              title={reason(p.name)
                ? `${p.description} (suggested by ${reason(p.name)})`
                : p.description}
              onclick={() => {
                presetsTouched = true;
                presets = toggle(presets, p.name);
              }}>{p.name}</button
            >
          {/each}
        </div>
      </div>
      <div class="choice">
        <span>tools</span>
        <div>
          {#if proposal?.tools.length}
            <div class="chips">
              {#each proposal.tools as t, i (i)}
                <span class="pin" title="pinned by {t.source}">{t.tool} {t.version}</span>
              {/each}
            </div>
            <p class="hint">Installed by mise in the env; the project's files keep deciding.</p>
          {:else}
            <p class="hint first">
              None pinned. In the env, <code>mise use node@24</code> (or any tool) adds one to the project.
            </p>
          {/if}
        </div>
      </div>
      {#if proposal?.project}
        <div class="choice">
          <span>project</span>
          <div class="untrusted">
            <p class="hint first">
              luoto.toml, written in the repository: creating the env accepts these settings.
            </p>
            {#each proposal.project as [label, value], i (i)}
              <p class="line">
                <span class="label">{label}</span><span class="items">{value}</span>
              </p>
            {/each}
          </div>
        </div>
      {:else if proposal?.project_error}
        <div class="choice">
          <span>project</span>
          <p class="hint first">luoto.toml not used: {proposal.project_error}</p>
        </div>
      {/if}
      <div class="choice">
        <span>agents</span>
        <div class="chips">
          {#each app.meta?.agents ?? [] as a (a.name)}
            <button
              type="button"
              class="chip"
              class:on={agents.includes(a.name)}
              title={a.description}
              onclick={() => (agents = toggle(agents, a.name))}>{a.name}</button
            >
          {/each}
        </div>
      </div>
    </div>
  {/snippet}
  {#snippet footer()}
    <button class="btn" onclick={onClose}>cancel</button>
    <button class="btn primary" onclick={create} disabled={!valid}>create</button>
  {/snippet}
</Modal>

<style>
  .form {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  label,
  .choice {
    display: grid;
    grid-template-columns: 64px 1fr;
    gap: 10px;
    align-items: center;
    font-size: 13px;
  }

  .choice {
    align-items: start;
  }

  label span,
  .choice > span {
    color: var(--halo-text-muted);
  }

  input {
    width: 100%;
  }

  .hint {
    margin: 6px 0 0;
    color: var(--halo-text-muted);
    font-size: 12px;
  }

  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }

  .chip {
    padding: 3px 9px;
    border: 1px solid var(--halo-border);
    border-radius: var(--halo-radius-pill, 999px);
    background: var(--halo-bg-main);
    color: var(--halo-text-muted);
    font-size: 12px;
  }

  .pin {
    padding: 3px 9px;
    border-radius: var(--halo-radius-pill, 999px);
    background: var(--halo-bg-light);
    font-size: 12px;
    font-variant-numeric: tabular-nums;
  }

  .untrusted {
    padding: 6px 8px;
    border-left: 2px solid var(--halo-error);
    background: var(--halo-bg-light);
  }

  .line {
    margin: 2px 0;
    font-size: 12px;
    word-break: break-word;
  }

  .line {
    display: flex;
    gap: 6px;
  }

  .line .label {
    color: var(--halo-text-muted);
  }

  .line .items {
    min-width: 0;
    white-space: pre-line;
  }

  .hint.first {
    margin-top: 0;
  }

  .hint.error {
    color: var(--halo-error);
  }

  .chip.on {
    border-color: var(--halo-accent);
    background: var(--halo-accent-soft);
    color: var(--halo-accent);
  }
</style>
