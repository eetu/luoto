<script lang="ts">
  import { api } from "$lib/api";
  import { act, app, busyWhile, say } from "$lib/stores/app.svelte";
  import type { PullPlans } from "$lib/types";

  // The env's folder and its repos, and a reviewed pull of what changed in the env's copies:
  // the folder's, and each repo's copied in from a folder of its own. The plan belongs to one
  // env: the parent keys this section on it.
  const d = $derived(app.detail);
  const row = $derived(app.overview?.envs.find((e) => e.name === app.env));
  const dir = $derived(row?.dir ?? null);
  const repos = $derived(row?.repos ?? []);

  let pull = $state<PullPlans | null>(null);
  let includeRisky = $state(false);

  async function review() {
    const env = app.env;
    if (!env) return;
    const next = await busyWhile("reading the env's files…", () => api.pullPlan(env));
    if (!next) return;
    pull = next;
    includeRisky = false;
  }

  async function apply() {
    const env = app.env;
    if (!env || !pull) return;
    const digest = pull.digest;
    const result = await act("writing…", () => api.pull(env, digest, includeRisky));
    // Written or not, the reviewed plan is spent: a failure leaves a fresh review to do.
    pull = null;
    if (!result) return;
    say(
      `wrote ${result.written} file(s)${result.skipped ? `, skipped ${result.skipped} risky` : ""}`,
    );
  }

  const entries = $derived(pull?.plans.flatMap((p) => p.entries) ?? []);
  const anyRisky = $derived(entries.some((e) => e.risky));
  const anySafe = $derived(entries.some((e) => !e.risky));
</script>

<div class="section">
  <p class="label">folder</p>
  <p class="small path">{dir ?? "none"}</p>
  <p class="small muted">copied in: the sandbox never writes here</p>

  {#if repos.length > 0}
    <p class="label repos">repos</p>
    {#each repos as r (r.name)}
      <p class="small">
        <span class="mono">{r.name}</span>
        <span class="muted">{r.kind === "folder" ? "copied in from" : "cloned from"}</span>
        <span class="path">{r.source}</span>
        {#if r.branch}<span class="muted">({r.branch})</span>{/if}
        {#if r.origin === "project"}<span class="muted">— luoto.toml</span>{/if}
        {#if !r.present}<span class="muted">— on the next up</span>{/if}
      </p>
    {/each}
  {/if}

  {#if dir && d?.dev === "running"}
    {#if !pull}
      <button class="btn" onclick={review}>pull changes…</button>
    {:else}
      <div class="plan">
        {#if entries.length === 0}
          <p class="small muted">nothing to pull</p>
        {/if}
        {#each pull.plans.filter((p) => pull?.plans.length === 1 || p.entries.length || p.refused.length) as p (p.dir)}
          {@const safe = p.entries.filter((e) => !e.risky)}
          {@const risky = p.entries.filter((e) => e.risky)}
          <div class="target">
            {#if pull.plans.length > 1}
              <p class="small">
                {p.repo ? `repo ${p.repo}` : "folder"} → <span class="path">{p.dir}</span>
              </p>
            {/if}
            <p class="small">
              {p.entries.length} new or changed, {p.unchanged} unchanged
            </p>
            {#each safe.slice(0, 20) as e, n (n)}
              <p class="small mono">{e.change} {e.path}</p>
            {/each}
            {#if safe.length > 20}<p class="small muted">… {safe.length - 20} more</p>{/if}
            {#if risky.length > 0}
              <p class="warn">risky — host tools act on these:</p>
              {#each risky as e, n (n)}
                <p class="small mono">
                  {e.change}
                  {e.path} <span class="muted">— {e.risky}</span>
                </p>
              {/each}
            {/if}
            {#each p.refused as [path, why], n (n)}
              <p class="small muted">refused {path} — {why}</p>
            {/each}
          </div>
        {/each}
        {#if anyRisky}
          <label class="small toggle">
            <input type="checkbox" bind:checked={includeRisky} /> also write risky files
          </label>
        {/if}
        <div class="actions">
          <button
            class="btn primary"
            onclick={apply}
            disabled={!anySafe && !(includeRisky && anyRisky)}
            >write to {pull.plans.length > 1 ? "folders" : "folder"}</button
          >
          <button class="btn" onclick={() => (pull = null)}>cancel</button>
        </div>
      </div>
    {/if}
  {/if}
</div>

<style>
  .path {
    word-break: break-all;
  }

  .repos {
    margin-top: 8px;
  }

  .plan {
    margin-top: 8px;
  }

  .target + .target {
    margin-top: 8px;
  }

  .toggle {
    display: flex;
    gap: 6px;
    align-items: center;
  }
</style>
