<script lang="ts">
  import { untrack } from "svelte";

  import { api, ApiError } from "$lib/api";
  import ChipSelect from "$lib/components/ChipSelect.svelte";
  import CopyCommand from "$lib/components/CopyCommand.svelte";
  import Risks from "$lib/components/Risks.svelte";
  import Segmented from "$lib/components/Segmented.svelte";
  import Switch from "$lib/components/Switch.svelte";
  import {
    act,
    ago,
    app,
    installLabel,
    isTunnel,
    requestTarget,
    say,
    TTLS,
  } from "$lib/stores/app.svelte";
  import type { Narrowing } from "$lib/types";

  let { id }: { id: number } = $props();

  const req = $derived(app.requests.find((r) => r.id === id) ?? null);
  let ttl = $state(60);
  // What approving as chosen asks to confirm, or why luoto refuses it: the check `luoto
  // approve` makes, run again as the choice changes; the last answer stays until the next.
  let risks = $state<string[]>([]);
  let refused = $state<string | null>(null);
  // The check itself failed (the backend unreachable): nothing approves until it is known.
  let unchecked = $state<string | null>(null);
  let checking = $state(false);
  let retry = $state(0);
  let checks = 0;
  let checkedText = "";
  // Less than asked: read for a write request, some of its paths. The backend refuses wider.
  let grant = $state<"asked" | "read">("asked");
  let paths = $state("");
  // One host of a wildcard or range asked for; a tunnel granted inspected.
  let onlyHost = $state("");
  let how = $state<"tunnel" | "inspect">("tunnel");
  // Why it is rejected, for the sandbox to read.
  let note = $state("");
  // On the user's network or VPN: as the request asked, which the user may turn off, or more
  // than asked when the user picks it. Never looked up first: the name is the sandbox's, and a
  // lookup from this machine would carry whatever it put in it.
  let allowPrivate = $state(false);
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
    onlyHost = "";
    how = "tunnel";
    note = "";
    allowPrivate = untrack(() => req?.private) ?? false;
    risks = [];
    refused = null;
    unchecked = null;
    checkedText = "";
    // Polls refresh `req`: only another request starts the value over.
    given = untrack(() => suggestion) ?? "";
  });

  $effect(() => {
    void id;
    void retry;
    const env = app.env;
    const shown = untrack(() => req);
    if (!env || !shown || shown.install || shown.status !== "pending") return;
    const narrow = narrowing();
    const priv = allowPrivate;
    const seq = ++checks;
    checking = true;
    // What is typed is checked once typing pauses, any other choice at once.
    const text = `${paths}\n${onlyHost}`;
    const typed = text !== checkedText;
    checkedText = text;
    const timer = setTimeout(
      () => {
        api.approvalRisks(env, shown, narrow, priv).then(
          (found) => {
            if (seq !== checks) return;
            [risks, refused, unchecked, checking] = [found, null, null, false];
          },
          (e: unknown) => {
            if (seq !== checks) return;
            const said = e instanceof Error ? e.message : String(e);
            risks = [];
            [refused, unchecked] = e instanceof ApiError ? [said, null] : [null, said];
            checking = false;
          },
        );
      },
      typed ? 300 : 0,
    );
    return () => clearTimeout(timer);
  });

  const asksTunnel = $derived(!!req && isTunnel(req));
  const tunnel = $derived(asksTunnel && how === "tunnel");
  /** A wildcard or an address range: one host of it may be granted instead. */
  const pattern = $derived(
    !!req && !req.install && (req.host.startsWith("*.") || req.host.includes("/")),
  );
  /** Hosts of the wildcard the env has tried, to grant one of with a click. */
  const tried = $derived.by(() => {
    const under = req?.host.startsWith("*.") ? req.host.slice(1) : null;
    if (!under) return [];
    return app.egress
      .map((h) => h.host)
      .filter((h) => /^[a-z0-9.-]+$/.test(h) && h.endsWith(under))
      .slice(0, 6)
      .map((name) => ({ name }));
  });

  /** `s` as one shell word. */
  const word = (s: string): string =>
    /^[\w@%+=:,./-]+$/.test(s) ? s : `'${s.replaceAll("'", "'\\''")}'`;
  const forArg = (m: number): string =>
    m % 1440 === 0 ? `${m / 1440}d` : m % 60 === 0 ? `${m / 60}h` : `${m}m`;
  /** The choice made here as `luoto approve` makes it, for a terminal or a script. */
  const command = $derived.by(() => {
    if (!req || !app.env) return "";
    const n = narrowing();
    const args = ["luoto approve -e", word(app.env), String(req.id)];
    if (n?.inspect) args.push("--inspect");
    if (n?.host) args.push("--host", word(n.host));
    if (n?.read) args.push("--read");
    for (const p of n?.paths ?? []) args.push("--path", word(p));
    if (allowPrivate) args.push("--private");
    if (ttl) args.push("--for", forArg(ttl));
    return args.join(" ");
  });

  /** What a preset opens, from luoto's own data: the request carries only its name. */
  function presetHosts(name: string): string[] {
    return app.meta?.presets.find((p) => p.name === name)?.hosts ?? [];
  }

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
    const globs = tunnel ? [] : paths.split(/[\s,]+/).filter(Boolean);
    const read = !tunnel && grant === "read";
    const host = (pattern && onlyHost.trim()) || undefined;
    const inspect = asksTunnel && how === "inspect";
    if (!read && globs.length === 0 && !host && !inspect) return undefined;
    return {
      read: read || undefined,
      paths: globs.length ? globs : undefined,
      host,
      inspect: inspect || undefined,
    };
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
      () => api.approve(env, shown, ttl ? `${ttl}m` : undefined, force, narrow, allowPrivate),
      `approved #${id}: ${requestTarget(shown)}${narrow ? " (narrowed)" : ""}`,
      (found) => (risks = found),
    );
    if (rule) {
      risks = [];
      app.subject = { kind: "host", host: "host" in rule ? rule.host : host };
    }
  }

  async function reject() {
    const env = app.env;
    if (!env || !req) return;
    const shown = req;
    const ok = await act("rejecting…", () => api.reject(env, shown, note), `rejected #${id}`);
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
      <CopyCommand cmd={`luoto var set -e ${app.env} ${variable.name}`} />
      {@render noteField()}
      <div class="actions">
        <button class="btn primary" onclick={() => void approveVar()} disabled={!!app.busy}
          >Approve</button
        >
        <button class="btn" onclick={reject} disabled={!!app.busy}>Reject</button>
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
      {#if req.install.kind === "preset"}
        <dt>opens</dt>
        <dd>
          {#each presetHosts(req.install.name) as h (h)}
            <span class="opens mono">{h}</span>
          {:else}
            nothing: luoto has no such preset
          {/each}
        </dd>
      {/if}
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
      {@render noteField()}
      <div class="actions">
        <button class="btn primary" onclick={() => void approve(false)} disabled={!!app.busy}
          >{req.install.kind === "preset" ? "Approve" : "Approve and install"}</button
        >
        <button class="btn" onclick={reject} disabled={!!app.busy}>Reject</button>
      </div>
    {/if}
  {:else if req}
    <h2>{requestTarget(req)}</h2>
    <dl>
      <dt>access</dt>
      <dd>
        {isTunnel(req)
          ? "uninspected tunnel"
          : req.access === "write"
            ? "write (any method)"
            : "read-only"}
      </dd>
      {#if !isTunnel(req)}
        <dt>paths</dt>
        <dd>{req.paths?.length ? req.paths.join(", ") : "all"}</dd>
      {/if}
      {#if req.ws}
        <dt>websockets</dt>
        <dd>allowed</dd>
      {/if}
      {#if req.private}
        <dt>where</dt>
        <dd>on your network or VPN: a private address, or one only a VPN reaches</dd>
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
    {#if req.status === "pending"}
      <div class="check" role="status" aria-live="polite" aria-busy={checking}>
        {#if refused}
          <p class="warn">{refused}</p>
        {:else if unchecked}
          <p class="warn">
            Couldn't check what approving it risks: {unchecked}
            <button type="button" class="btn" onclick={() => retry++}>Check again</button>
          </p>
        {:else if risks.length > 0}
          <Risks {risks} heading="approving this:" />
        {/if}
      </div>
      {#if pattern}
        <label class="field">
          <span>host</span>
          <input
            type="text"
            bind:value={onlyHost}
            autocomplete="off"
            spellcheck="false"
            placeholder="all it asks, or one host of it"
          />
        </label>
        {#if tried.length > 0}
          <div class="field">
            <span class="muted">tried</span>
            <ChipSelect
              options={tried}
              selected={onlyHost ? [onlyHost] : []}
              onchange={(picked) => (onlyHost = picked.find((h) => h !== onlyHost) ?? "")}
            />
          </div>
        {/if}
      {/if}
      {#if asksTunnel}
        <div class="field">
          <span>how</span>
          <Segmented
            label="how"
            options={[
              { value: "tunnel", label: "tunnel, as asked" },
              { value: "inspect", label: "inspected" },
            ]}
            value={how}
            onchange={(v) => (how = v)}
          />
        </div>
      {/if}
      {#if !tunnel}
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
              onchange={(v) => (grant = v)}
            />
          </div>
        {/if}
        <label class="field">
          <span>paths</span>
          <input
            type="text"
            bind:value={paths}
            placeholder={req.paths?.length ? "as asked, or some of them" : "all, or e.g. /v1/**"}
          />
        </label>
      {/if}
      <div class="field">
        <span>private</span>
        <Switch
          checked={allowPrivate}
          label="allow private address"
          onchange={(v) => (allowPrivate = v)}
        />
        <span class="muted small"
          >{req.private ? "as it asks" : "for a host on your network or VPN"}</span
        >
      </div>
      <label class="field">
        <span>for</span>
        <select bind:value={ttl}>
          {#each TTLS as t (t.minutes)}<option value={t.minutes}>{t.label}</option>{/each}
        </select>
      </label>
      {@render noteField()}
      <div class="actions">
        <!-- One button, relabelled in place, so focus stays on it as the risks change. -->
        <button
          class="btn {risks.length > 0 ? 'danger' : 'primary'}"
          onclick={() => void approve(risks.length > 0)}
          disabled={!!app.busy || checking || !!refused || !!unchecked}
          >{risks.length > 0 ? "Approve anyway" : "Approve"}</button
        >
        <button class="btn" onclick={reject} disabled={!!app.busy}>Reject</button>
      </div>
      <details class="as-command">
        <summary>as a command</summary>
        <div class="cmd"><CopyCommand cmd={command} /></div>
      </details>
    {/if}
  {:else}
    <p class="muted">this request is no longer listed</p>
  {/if}
</div>

{#snippet noteField()}
  <label class="field">
    <span>note</span>
    <input
      type="text"
      bind:value={note}
      maxlength="300"
      placeholder="with Reject: why, for the sandbox to read"
    />
  </label>
{/snippet}

<style>
  .as-command summary {
    padding-block: 5px;
    color: var(--halo-text-muted);
    font-size: 12px;
    cursor: pointer;
  }

  .as-command .cmd {
    margin-top: 6px;
  }

  .check[aria-busy="true"] {
    opacity: 0.6;
  }

  .check:empty {
    display: none;
  }

  .field:has(.small) {
    grid-template-columns: 58px auto 1fr;
  }

  .opens {
    display: block;
    font-size: 12px;
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

  .reason {
    margin: 0;
    white-space: pre-wrap;
    word-break: break-word;
    font-family: ui-monospace, "SF Mono", Menlo, monospace;
    font-size: 12px;
  }
</style>
