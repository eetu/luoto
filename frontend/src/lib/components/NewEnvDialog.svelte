<script lang="ts">
  import { api } from "$lib/api";
  import ChipSelect from "$lib/components/ChipSelect.svelte";
  import LabelledLines from "$lib/components/LabelledLines.svelte";
  import Modal from "$lib/components/Modal.svelte";
  import { useDetect } from "$lib/detect.svelte";
  import { act, app, selectEnv } from "$lib/stores/app.svelte";

  let { open, onClose }: { open: boolean; onClose: () => void } = $props();

  let dir = $state("");
  let name = $state("");
  let ports = $state("");
  let presets = $state<string[]>(["debian", "github", "toolchains"]);
  let presetsTouched = $state(false);
  let agents = $state<string[]>([]);

  const query = $derived({ dir: dir.trim() || undefined, name: name.trim() || undefined });
  // The suggested presets stand until the user picks their own.
  const detection = useDetect(
    () => query,
    (p) => {
      if (!presetsTouched) presets = p.presets.map((x) => x.name);
    },
  );
  const proposal = $derived(detection.proposal);

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
  // A remote is cloned inside the env, and its first start asks about the clone's luoto.toml
  // and installs on a terminal: such an env is made with `luoto init`, not here.
  const remote = $derived(detection.ready ? (proposal?.remote ?? null) : null);
  const valid = $derived(
    /^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$/.test(finalName) &&
      dir.trim() !== "" &&
      detection.ready &&
      !remote,
  );

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
    const created = await act(
      `creating ${finalName}…`,
      () => api.createEnv(body),
      `${finalName} is up`,
    );
    if (created) await selectEnv(created.name);
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
            {#if remote}
              A remote, cloned inside the env with nothing on this machine. Its first start shows
              the clone's luoto.toml and what it installs, so create it in a terminal:
              <code>luoto init {remote}</code>
            {:else if proposal?.new_folder}
              New or empty: luoto creates it if needed, and the env starts empty. Pick its egress
              below.
            {:else}
              Copied in, git history included; the sandbox never writes to it. Push from the env, or
              bring files back with a reviewed pull.
            {/if}
          </p>
          {#if detection.error}<p class="hint error">{detection.error}</p>{/if}
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
        <ChipSelect
          options={(app.meta?.presets ?? []).map((p) => ({
            name: p.name,
            title: reason(p.name)
              ? `${p.description} (suggested by ${reason(p.name)})`
              : p.description,
          }))}
          selected={presets}
          onchange={(next) => {
            presetsTouched = true;
            presets = next;
          }}
        />
      </div>
      <div class="choice">
        <span>tools</span>
        <div>
          {#if proposal?.tools.length}
            <div class="pins">
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
            <LabelledLines lines={proposal.project} />
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
        <ChipSelect
          options={(app.meta?.agents ?? []).map((a) => ({ name: a.name, title: a.description }))}
          selected={agents}
          onchange={(next) => (agents = next)}
        />
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

  .pins {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }

  .pin {
    padding: 3px 9px;
    border-radius: var(--halo-radius-pill, 999px);
    background: var(--halo-bg-light);
    font-size: 12px;
    font-variant-numeric: tabular-nums;
  }

  .hint.first {
    margin-top: 0;
  }

  .hint.error {
    color: var(--halo-error);
  }
</style>
