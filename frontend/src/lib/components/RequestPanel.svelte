<script lang="ts">
  import { api } from "$lib/api";
  import { act, ago, app } from "$lib/stores/app.svelte";

  let { id }: { id: number } = $props();

  const req = $derived(app.requests.find((r) => r.id === id) ?? null);
  let ttl = $state("1h");

  async function approve() {
    const env = app.env;
    if (!env || !req) return;
    const ok = await act(
      "approving…",
      () => api.approve(env, id, ttl || undefined),
      `approved #${id}: ${req.host}`,
    );
    if (ok) app.subject = { kind: "host", host: req.host };
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
      <div class="actions">
        <button class="btn primary" onclick={approve} disabled={!!app.busy}>approve</button>
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
</style>
