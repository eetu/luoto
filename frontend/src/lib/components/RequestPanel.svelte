<script lang="ts">
  import { api, ApiError } from "$lib/api";
  import { act, ago, app, refreshEnv, refreshOverview, say } from "$lib/stores/app.svelte";

  let { id }: { id: number } = $props();

  const req = $derived(app.requests.find((r) => r.id === id) ?? null);
  let ttl = $state("1h");
  let risks = $state<string[]>([]);

  async function approve(force: boolean) {
    const env = app.env;
    if (!env || !req) return;
    const host = req.host;
    app.busy = "approving…";
    try {
      await api.approve(env, id, ttl || undefined, force);
      risks = [];
      say(`approved #${id}: ${host}`);
      app.subject = { kind: "host", host };
      await Promise.all([refreshEnv(), refreshOverview()]);
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        risks = (e.data.risks as string[]) ?? [];
      } else {
        say(e instanceof Error ? e.message : String(e), true);
      }
    } finally {
      app.busy = null;
    }
  }

  async function reject() {
    const env = app.env;
    if (!env || !req) return;
    const ok = await act("rejecting…", () => api.reject(env, id), `rejected #${id}`);
    if (ok) app.subject = { kind: "env" };
  }
</script>

<div class="panel">
  <p class="label">access request #{id}</p>
  {#if req}
    <h2>{req.host}</h2>
    <dl>
      <dt>access</dt>
      <dd>{req.access === "write" ? "write (any method)" : "read-only"}</dd>
      <dt>paths</dt>
      <dd>{req.paths?.length ? req.paths.join(", ") : "all"}</dd>
      <dt>filed</dt>
      <dd>{ago(req.created)}</dd>
      <dt>status</dt>
      <dd>{req.status}</dd>
    </dl>
    <div class="untrusted">
      <p class="label">reason — written by code in the sandbox, not by you</p>
      <p class="reason">{req.reason}</p>
    </div>
    {#if req.access === "write"}
      <p class="warn">
        Write access lets anything in the sandbox upload data to {req.host}.
      </p>
    {/if}
    {#if req.status === "pending"}
      <label class="field">
        <span>for</span>
        <select bind:value={ttl}>
          <option value="15m">15 min</option>
          <option value="1h">1 hour</option>
          <option value="1d">1 day</option>
          <option value="">until revoked</option>
        </select>
      </label>
      {#if risks.length > 0}
        <div class="risks">
          <p>confirm:</p>
          <ul>
            {#each risks as r (r)}<li>{r}</li>{/each}
          </ul>
        </div>
      {/if}
      <div class="actions">
        {#if risks.length > 0}
          <button class="btn danger" onclick={() => void approve(true)} disabled={!!app.busy}
            >approve anyway</button
          >
        {:else}
          <button class="btn primary" onclick={() => void approve(false)} disabled={!!app.busy}
            >approve</button
          >
        {/if}
        <button class="btn" onclick={reject} disabled={!!app.busy}>reject</button>
      </div>
    {/if}
  {:else}
    <p class="muted">this request is no longer listed</p>
  {/if}
</div>

<style>
  .panel {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  h2 {
    margin: 0;
    font-size: 15px;
    word-break: break-all;
  }

  dl {
    display: grid;
    grid-template-columns: 58px 1fr;
    gap: 4px 8px;
    margin: 0;
    font-size: 13px;
  }

  dt {
    color: var(--halo-text-muted);
  }

  dd {
    margin: 0;
  }

  .untrusted {
    padding: 8px 10px;
    border: 1px dashed var(--halo-border);
    border-radius: var(--halo-radius);
  }

  .reason {
    margin: 0;
    white-space: pre-wrap;
    word-break: break-word;
    font-family: ui-monospace, "SF Mono", Menlo, monospace;
    font-size: 12px;
  }

  .warn {
    margin: 0;
    color: var(--halo-error);
    font-size: 12px;
  }

  .field {
    display: grid;
    grid-template-columns: 58px 1fr;
    gap: 8px;
    align-items: center;
    font-size: 13px;
  }

  .field span {
    color: var(--halo-text-muted);
  }

  .actions {
    display: flex;
    gap: 8px;
  }

  .risks {
    padding: 8px 10px;
    border-left: 2px solid var(--halo-error);
    background: color-mix(in srgb, var(--halo-error) 8%, transparent);
    font-size: 12px;
  }

  .risks p {
    margin: 0;
  }

  .risks ul {
    margin: 4px 0 0;
    padding-left: 16px;
  }
</style>
