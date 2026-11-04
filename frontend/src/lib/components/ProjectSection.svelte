<script lang="ts">
  import { api } from "$lib/api";
  import { act, app } from "$lib/stores/app.svelte";
  import type { ProjectStatus } from "$lib/types";

  // The project's luoto.toml: team settings written in the repository (so possibly by code in
  // the sandbox). They apply only once accepted here or with `luoto project`; a changed file
  // waits for review.
  let status = $state<ProjectStatus | null>(null);

  $effect(() => {
    const env = app.env;
    // Re-check whenever the env detail refreshes.
    void app.detail;
    if (!env) {
      status = null;
      return;
    }
    api
      .projectStatus(env)
      .then((s) => {
        if (app.env === env) status = s;
      })
      .catch(() => (status = null));
  });

  // Accepting names the sha of the text on screen, so a file swapped since is refused.
  async function run(action: "accept" | "forget") {
    const env = app.env;
    if (!env || !status) return;
    const sha = status.sha ?? undefined;
    await act(
      action === "accept" ? "applying luoto.toml…" : "ignoring luoto.toml…",
      async () => {
        status = await api.projectAction(env, action, sha);
      },
      action === "accept" ? "applied luoto.toml" : "luoto.toml is ignored",
    );
  }
</script>

{#if status && status.state !== "none"}
  <div class="section">
    <p class="label">luoto.toml</p>
    {#if status.state === "accepted"}
      <p class="small muted">the project's settings apply</p>
      <div class="lines">
        {#each status.current as [label, value], i (i)}
          <p class="small entry">
            <span class="muted">{label}</span><span class="items">{value}</span>
          </p>
        {/each}
      </div>
    {:else if status.state === "changed" || status.state === "new" || status.state === "declined"}
      <p class="small" class:warn={status.state !== "declined"}>
        {status.state === "changed"
          ? "changed since you accepted it"
          : status.state === "declined"
            ? "ignored for this env"
            : "the project's settings, not accepted"} — written in the repository, so review:
      </p>
      <div class="lines untrusted">
        {#if status.state === "changed"}
          {#each status.diff as line, i (i)}<p class="small mono">{line}</p>{/each}
        {:else}
          {#each status.current as [label, value], i (i)}
            <p class="small entry">
              <span class="muted">{label}</span><span class="items">{value}</span>
            </p>
          {/each}
        {/if}
      </div>
      <div class="actions">
        <button class="btn primary" onclick={() => run("accept")}>apply</button>
        {#if status.state !== "declined"}
          <button class="btn" onclick={() => run("forget")}>ignore</button>
        {/if}
      </div>
    {:else if status.state === "invalid"}
      <p class="small warn">not applied: {status.error}</p>
    {:else if status.state === "removed"}
      <p class="small muted">gone from the project; the accepted settings still apply</p>
      <button class="btn" onclick={() => run("forget")}>drop them</button>
    {/if}
    {#if status.needs.length > 0}
      <p class="small muted">credentials it needs (add them with <code>luoto edit</code>):</p>
      <pre class="needs">{status.needs.join("\n\n")}</pre>
    {/if}
  </div>
{/if}

<style>
  .section {
    margin-top: 12px;
    padding-top: 10px;
    border-top: 1px solid var(--halo-border);
  }

  .small {
    margin: 2px 0;
    font-size: 12px;
    word-break: break-word;
  }

  .warn {
    color: var(--halo-error);
  }

  .lines {
    margin-top: 6px;
  }

  .entry {
    display: flex;
    gap: 6px;
  }

  .items {
    min-width: 0;
    white-space: pre-line;
  }

  .untrusted {
    padding: 6px 8px;
    border-left: 2px solid var(--halo-error);
    background: var(--halo-bg-light);
  }

  .actions {
    display: flex;
    gap: 8px;
    margin-top: 8px;
  }

  .needs {
    overflow-x: auto;
    margin: 4px 0 0;
    padding: 6px 8px;
    background: var(--halo-bg-light);
    font-size: 11px;
  }
</style>
