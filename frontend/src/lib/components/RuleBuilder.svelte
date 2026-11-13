<script lang="ts">
  import { api } from "$lib/api";
  import Risks from "$lib/components/Risks.svelte";
  import Segmented from "$lib/components/Segmented.svelte";
  import Switch from "$lib/components/Switch.svelte";
  import { act, app, expiresIn, TTLS } from "$lib/stores/app.svelte";
  import type { Rule } from "$lib/types";

  // A scoped "allow" built from what the sandbox actually tried. Defaults are the narrowest
  // thing that would have worked: the exact host, read unless a write was refused, an hour.
  // `keep`: a host reached through open egress, kept past its window (until revoked).
  let {
    host,
    keep = false,
    wantsWrite = false,
    paths = [],
    privateHost = false,
    tlsRejected = false,
  }: {
    host: string;
    keep?: boolean;
    wantsWrite?: boolean;
    paths?: string[];
    privateHost?: boolean;
    tlsRejected?: boolean;
  } = $props();

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
    ttl = keep ? 0 : 60;
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
      target === "*" && "a lone wildcard covers every host: even reads can leak data in URLs",
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
      expires: expiresIn(ttl),
      mode: tunnel ? "tunnel" : undefined,
      allow_private: allowPrivate || undefined,
      note: keep ? "kept from open egress" : "added in luoto ui",
    };
  }

  async function attempt(force: boolean) {
    const env = app.env;
    if (!env) return;
    const r = rule();
    const ttlLabel = TTLS.find((t) => t.minutes === ttl)?.label;
    const added = await act(
      keep ? "keeping…" : "allowing…",
      () => api.addRule(env, r, force),
      `${keep ? "kept" : "allowed"} ${r.host}${ttl ? ` for ${ttlLabel}` : ""}`,
      (found) => (risks = found),
    );
    if (added) risks = [];
  }
</script>

<form class="builder" onsubmit={(e) => (e.preventDefault(), void attempt(false))}>
  <p class="label">{keep ? "keep" : "allow"}</p>
  <label class="field">
    <span>host</span>
    <input type="text" bind:value={target} />
  </label>
  <div class="field">
    <span>access</span>
    <Segmented
      label="access"
      options={[
        { value: "read", label: "read" },
        { value: "write", label: "write" },
      ]}
      value={access}
      disabled={tunnel}
      onchange={(v) => (access = v)}
    />
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
      {#each TTLS as t (t.minutes)}<option value={t.minutes}>{t.label}</option>{/each}
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
    <Risks {risks} confirm="Allow anyway" onconfirm={() => void attempt(true)} />
  {:else}
    <button type="submit" class="btn primary" disabled={!target.trim() || !!app.busy}
      >{keep ? "Keep" : "Allow"}</button
    >
  {/if}
</form>

<style>
  .builder {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .field:has(.small) {
    grid-template-columns: 58px auto 1fr;
  }

  .notes {
    margin: 4px 0;
    padding-left: 16px;
    color: var(--halo-text-muted);
    font-size: 12px;
  }

  button[type="submit"] {
    align-self: flex-start;
    margin-top: 4px;
  }
</style>
