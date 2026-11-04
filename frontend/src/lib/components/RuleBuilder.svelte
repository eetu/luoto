<script lang="ts">
  import { api, ApiError } from "$lib/api";
  import Switch from "$lib/components/Switch.svelte";
  import { app, refreshEnv, refreshOverview, say } from "$lib/stores/app.svelte";
  import type { Rule } from "$lib/types";

  // A scoped "allow" built from what the sandbox actually tried. Defaults are the narrowest
  // thing that would have worked: the exact host, read unless a write was refused, an hour.
  let {
    host,
    wantsWrite = false,
    paths = [],
    privateHost = false,
    tlsRejected = false,
  }: {
    host: string;
    wantsWrite?: boolean;
    paths?: string[];
    privateHost?: boolean;
    tlsRejected?: boolean;
  } = $props();

  const TTLS = [
    { value: 15, label: "15 min" },
    { value: 60, label: "1 hour" },
    { value: 1440, label: "1 day" },
    { value: 0, label: "until revoked" },
  ];

  let target = $state("");
  let access = $state<"read" | "write">("read");
  let scope = $state("");
  let ttl = $state(60);
  let tunnel = $state(false);
  let allowPrivate = $state(false);
  let risks = $state<string[]>([]);

  // Reset to the narrowest defaults whenever the subject changes. Never a tunnel: code in the
  // sandbox can stage a TLS reject for any host.
  $effect(() => {
    target = host;
    access = wantsWrite ? "write" : "read";
    scope = "";
    ttl = 60;
    tunnel = false;
    allowPrivate = false;
    risks = [];
  });

  const prefixes = $derived(
    [
      ...new Set(paths.map((p) => p.split("/").slice(0, 2).join("/")).filter((p) => p.length > 1)),
    ].map((p) => `${p}/**`),
  );

  const notes = $derived(
    [
      access === "write" && "write lets code in the sandbox upload data to this host",
      target === "*" && "`*` covers every host: even reads can leak data in URLs",
      tunnel &&
        "a tunnel is not inspected: any method and path, no credential stripping or injection, no git or GraphQL guards",
      allowPrivate && "reaches services on your machine or network",
      ttl === 0 && "stays until you revoke it",
    ].filter(Boolean) as string[],
  );

  function rule(): Rule {
    return {
      host: target.trim(),
      access: tunnel ? "write" : access,
      paths: scope ? [scope] : undefined,
      expires: ttl ? new Date(Date.now() + ttl * 60_000).toISOString() : undefined,
      mode: tunnel ? "tunnel" : undefined,
      allow_private: allowPrivate || undefined,
      note: "added in luoto ui",
    };
  }

  async function attempt(force: boolean) {
    const env = app.env;
    if (!env) return;
    app.busy = "allowing…";
    try {
      const r = rule();
      await api.addRule(env, r, force);
      risks = [];
      const ttlLabel = TTLS.find((t) => t.value === ttl)?.label ?? "";
      say(`allowed ${r.host}${ttl ? ` for ${ttlLabel}` : ""}`);
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
</script>

<form class="builder" onsubmit={(e) => (e.preventDefault(), void attempt(false))}>
  <p class="label">allow</p>
  <label class="field">
    <span>host</span>
    <input type="text" bind:value={target} />
  </label>
  <div class="field">
    <span>access</span>
    <div class="seg" role="radiogroup" aria-label="access">
      <button
        type="button"
        class:active={access === "read"}
        onclick={() => (access = "read")}
        disabled={tunnel}>read</button
      >
      <button
        type="button"
        class:active={access === "write"}
        onclick={() => (access = "write")}
        disabled={tunnel}>write</button
      >
    </div>
  </div>
  <label class="field">
    <span>paths</span>
    <select bind:value={scope} disabled={tunnel}>
      <option value="">all paths</option>
      {#each prefixes as p (p)}<option value={p}>{p}</option>{/each}
    </select>
  </label>
  <label class="field">
    <span>for</span>
    <select bind:value={ttl}>
      {#each TTLS as t (t.value)}<option value={t.value}>{t.label}</option>{/each}
    </select>
  </label>
  <div class="field">
    <span>tunnel</span>
    <Switch checked={tunnel} label="opaque tunnel" onchange={(v) => (tunnel = v)} />
    <span class="muted small"
      >{tlsRejected
        ? "a client here rejected our certificate: if it pins certificates, it needs a tunnel"
        : "for certificate-pinning clients"}</span
    >
  </div>
  {#if privateHost}
    <div class="field">
      <span>private</span>
      <Switch
        checked={allowPrivate}
        label="allow private address"
        onchange={(v) => (allowPrivate = v)}
      />
    </div>
  {/if}

  {#if notes.length > 0}
    <ul class="notes">
      {#each notes as n (n)}<li>{n}</li>{/each}
    </ul>
  {/if}

  {#if risks.length > 0}
    <div class="risks">
      <p>confirm:</p>
      <ul>
        {#each risks as r (r)}<li>{r}</li>{/each}
      </ul>
      <button type="button" class="btn danger" onclick={() => void attempt(true)}
        >allow anyway</button
      >
    </div>
  {:else}
    <button type="submit" class="btn primary" disabled={!target.trim() || !!app.busy}>allow</button>
  {/if}
</form>

<style>
  .builder {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .field {
    display: grid;
    grid-template-columns: 58px 1fr;
    gap: 8px;
    align-items: center;
    font-size: 13px;
  }

  .field > span:first-child {
    color: var(--halo-text-muted);
  }

  .field:has(.small) {
    grid-template-columns: 58px auto 1fr;
  }

  .small {
    font-size: 12px;
  }

  .seg {
    display: inline-flex;
    justify-self: start;
    overflow: hidden;
    border: 1px solid var(--halo-border);
    border-radius: var(--halo-radius);
  }

  .seg button {
    padding: 4px 12px;
    border: none;
    background: var(--halo-bg-main);
    color: var(--halo-text-muted);
    font-size: 12px;
  }

  .seg button.active {
    background: var(--halo-accent-soft);
    color: var(--halo-accent);
  }

  .notes {
    margin: 4px 0;
    padding-left: 16px;
    color: var(--halo-text-muted);
    font-size: 12px;
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
    margin: 4px 0 8px;
    padding-left: 16px;
  }

  button[type="submit"] {
    align-self: flex-start;
    margin-top: 4px;
  }
</style>
