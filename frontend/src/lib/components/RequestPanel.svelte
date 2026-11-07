<script lang="ts">
  import { api } from "$lib/api";
  import Risks from "$lib/components/Risks.svelte";
  import { act, ago, app, installLabel, say, TTLS } from "$lib/stores/app.svelte";

  let { id }: { id: number } = $props();

  const req = $derived(app.requests.find((r) => r.id === id) ?? null);
  let ttl = $state(60);
  let risks = $state<string[]>([]);

  async function approve(force: boolean) {
    const env = app.env;
    if (!env || !req) return;
    if (req.install) {
      const done = await act("installing…", () => api.approve(env, id), `approved #${id}`);
      if (done && "installed" in done) say(done.installed);
      if (done) app.subject = { kind: "env" };
      return;
    }
    const host = req.host;
    const rule = await act(
      "approving…",
      () => api.approve(env, id, ttl ? `${ttl}m` : undefined, force),
      `approved #${id}: ${host}`,
      (found) => (risks = found),
    );
    if (rule) {
      risks = [];
      app.subject = { kind: "host", host };
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
  <p class="label">{req?.install ? "install request" : "access request"} #{id}</p>
  {#if req?.install}
    <h2>{installLabel(req.install)}</h2>
    <dl>
      <dt>kind</dt>
      <dd>
        {req.install.kind === "package"
          ? "system package (apt, apk or dnf)"
          : "toolchain installed by mise"}
      </dd>
      <dt>filed</dt>
      <dd>{ago(req.created)}</dd>
      <dt>status</dt>
      <dd>{req.status}{req.note ? `: ${req.note}` : ""}</dd>
    </dl>
    <div class="untrusted">
      <p class="label">reason — written by code in the sandbox, not by you</p>
      <p class="reason">{req.reason}</p>
    </div>
    <p class="muted">
      Approved, it is installed now and kept in the env's config, so a recreated container gets it
      too.
    </p>
    {#if req.status === "pending"}
      <div class="actions">
        <button class="btn primary" onclick={() => void approve(false)} disabled={!!app.busy}
          >approve and install</button
        >
        <button class="btn" onclick={reject} disabled={!!app.busy}>reject</button>
      </div>
    {/if}
  {:else if req}
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
          {#each TTLS as t (t.minutes)}<option value={t.minutes}>{t.label}</option>{/each}
        </select>
      </label>
      {#if risks.length > 0}
        <Risks {risks} confirm="approve anyway" onconfirm={() => void approve(true)} />
      {/if}
      <div class="actions">
        {#if risks.length === 0}
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

  .reason {
    margin: 0;
    white-space: pre-wrap;
    word-break: break-word;
    font-family: ui-monospace, "SF Mono", Menlo, monospace;
    font-size: 12px;
  }
</style>
