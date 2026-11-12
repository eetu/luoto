<script lang="ts">
  import Copy from "@lucide/svelte/icons/copy";
  import { untrack } from "svelte";

  import { api } from "$lib/api";
  import Risks from "$lib/components/Risks.svelte";
  import Segmented from "$lib/components/Segmented.svelte";
  import {
    act,
    ago,
    app,
    copyText,
    installLabel,
    requestTarget,
    say,
    TTLS,
  } from "$lib/stores/app.svelte";
  import type { Narrowing } from "$lib/types";

  let { id }: { id: number } = $props();

  const req = $derived(app.requests.find((r) => r.id === id) ?? null);
  let ttl = $state(60);
  let risks = $state<string[]>([]);
  // Less than asked: read for a write request, some of its paths. The backend refuses wider.
  let grant = $state<"asked" | "read">("asked");
  let paths = $state("");
  // A variable request's value: the one the sandbox suggests is filled in, to check.
  const variable = $derived(req?.install?.kind === "var" ? req.install : null);
  const suggestion = $derived(variable?.value ?? null);
  // What the env has under that name now, from its own file.
  const current = $derived(app.detail?.variables.find((v) => v.name === variable?.name) ?? null);
  let given = $state("");
  let givenField = $state<HTMLInputElement>();

  $effect(() => {
    void id;
    grant = "asked";
    paths = "";
    risks = [];
    // Polls refresh `req`: only another request starts the value over.
    given = untrack(() => suggestion) ?? "";
  });

  /** Show the next pending request, else the env. */
  function onward() {
    const next = app.pending.find((r) => r.id !== id);
    app.subject = next ? { kind: "request", id: next.id } : { kind: "env" };
  }

  async function approveVar() {
    const env = app.env;
    if (!env || !req) return;
    if (!given.trim()) {
      givenField?.focus();
      say("give the value first", true);
      return;
    }
    const shown = req;
    const done = await act("setting…", () => api.approveVar(env, shown, given));
    if (done && "installed" in done) say(`#${id} ${done.installed}`);
    if (done) onward();
  }

  function narrowing(): Narrowing | undefined {
    const globs = paths.split(/[\s,]+/).filter(Boolean);
    if (grant === "asked" && globs.length === 0) return undefined;
    return { read: grant === "read" || undefined, paths: globs.length ? globs : undefined };
  }

  async function approve(force: boolean) {
    const env = app.env;
    if (!env || !req) return;
    if (req.install) {
      const label = req.install.kind === "preset" ? "approving…" : "installing…";
      const shown = req;
      const done = await act(label, () => api.approve(env, shown));
      if (done && "installed" in done) say(`#${id} ${done.installed}`);
      if (done) onward();
      return;
    }
    const host = req.host;
    const shown = req;
    const narrow = narrowing();
    const rule = await act(
      "approving…",
      () => api.approve(env, shown, ttl ? `${ttl}m` : undefined, force, narrow),
      `approved #${id}: ${requestTarget(shown)}${narrow ? " (narrowed)" : ""}`,
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
    const shown = req;
    const ok = await act("rejecting…", () => api.reject(env, shown), `rejected #${id}`);
    if (ok) onward();
  }
</script>

<div class="panel">
  <p class="label">
    {variable ? "variable request" : req?.install ? "install request" : "access request"} #{id}
  </p>
  {#if req && variable}
    <h2>{installLabel(variable)}</h2>
    <dl>
      <dt>kind</dt>
      <dd>variable with a plain value</dd>
      <dt>now</dt>
      <dd>
        {#if !current}<span class="muted">not set</span>
        {:else if current.kind === "plain"}{current.value}
        {:else}<span class="muted">secret from</span> {current.kept}{/if}
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
    {#if suggestion !== null}
      <div class="untrusted">
        <p class="label">value it suggests — written by code in the sandbox</p>
        <p class="reason">{suggestion}</p>
      </div>
    {/if}
    {#if current?.kind === "secret"}
      <p class="warn">Approved, this plain value replaces the secret from {current.kept}.</p>
    {/if}
    {#if req.status === "pending"}
      <label class="field">
        <span>value</span>
        <input
          type="text"
          bind:value={given}
          bind:this={givenField}
          autocomplete="off"
          spellcheck="false"
          onkeydown={(e) => e.key === "Enter" && void approveVar()}
        />
      </label>
      <p class="muted">
        {suggestion !== null && given === suggestion
          ? "Filled in with the value it suggests. "
          : ""}Written into the env's file as it is, and any code in the env can read it. A secret
        you add yourself, on a terminal:
      </p>
      <button
        class="cmd"
        onclick={() => copyText(`luoto var set -e ${app.env} ${variable.name}`)}
        title="copy"
        ><code>luoto var set -e {app.env} {variable.name}</code><Copy size={12} /></button
      >
      <div class="actions">
        <button class="btn primary" onclick={() => void approveVar()} disabled={!!app.busy}
          >approve</button
        >
        <button class="btn" onclick={reject} disabled={!!app.busy}>reject</button>
      </div>
    {/if}
  {:else if req?.install}
    <h2>{installLabel(req.install)}</h2>
    <dl>
      <dt>kind</dt>
      <dd>
        {req.install.kind === "package"
          ? "system package (apt, apk or dnf)"
          : req.install.kind === "preset"
            ? "preset: a registry's or service's hosts"
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
      {req.install.kind === "preset"
        ? "Approved, its hosts open now and the env's config keeps the preset."
        : "Approved, it is installed now and kept in the env's config, so a recreated container gets it too."}
    </p>
    {#if req.status === "pending"}
      <div class="actions">
        <button class="btn primary" onclick={() => void approve(false)} disabled={!!app.busy}
          >{req.install.kind === "preset" ? "approve" : "approve and install"}</button
        >
        <button class="btn" onclick={reject} disabled={!!app.busy}>reject</button>
      </div>
    {/if}
  {:else if req}
    <h2>{requestTarget(req)}</h2>
    <dl>
      <dt>access</dt>
      <dd>
        {req.port
          ? "uninspected tunnel"
          : req.access === "write"
            ? "write (any method)"
            : "read-only"}
      </dd>
      {#if !req.port}
        <dt>paths</dt>
        <dd>{req.paths?.length ? req.paths.join(", ") : "all"}</dd>
      {/if}
      <dt>filed</dt>
      <dd>{ago(req.created)}</dd>
      <dt>status</dt>
      <dd>{req.status}</dd>
    </dl>
    <div class="untrusted">
      <p class="label">reason — written by code in the sandbox, not by you</p>
      <p class="reason">{req.reason}</p>
    </div>
    {#if req.port}
      <p class="warn">
        A tunnel is not inspected: anything in the sandbox gets full access to {requestTarget(req)},
        any protocol and any data.
      </p>
    {:else if req.access === "write" && grant === "asked"}
      <p class="warn">
        Write access lets anything in the sandbox upload data to {req.host}.
      </p>
    {/if}
    {#if req.status === "pending"}
      {#if !req.port}
        {#if req.access === "write"}
          <div class="field">
            <span>grant</span>
            <Segmented
              label="grant"
              options={[
                { value: "asked", label: "write" },
                { value: "read", label: "read-only" },
              ]}
              value={grant}
              onchange={(v) => ((grant = v), (risks = []))}
            />
          </div>
        {/if}
        <label class="field">
          <span>paths</span>
          <input
            type="text"
            bind:value={paths}
            oninput={() => (risks = [])}
            placeholder={req.paths?.length ? "as asked, or some of them" : "all, or e.g. /v1/**"}
          />
        </label>
      {/if}
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
