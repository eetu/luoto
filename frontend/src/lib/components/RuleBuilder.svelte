<script lang="ts">
  import type { Snippet } from "svelte";

  import { api } from "$lib/api";
  import Risks from "$lib/components/Risks.svelte";
  import Segmented from "$lib/components/Segmented.svelte";
  import Switch from "$lib/components/Switch.svelte";
  import { act, app, expiresIn, leftText, TTLS } from "$lib/stores/app.svelte";
  import type { CompiledRule, Resolved, Rule } from "$lib/types";

  // A scoped "allow" built from what the sandbox actually tried. Defaults are the narrowest
  // thing that would have worked: the exact host, read unless a write was refused, an hour.
  // `keep`: a host reached through open egress, kept past its window (until revoked).
  // `rule`: a rule of the user's to edit, saved in its place; what the form doesn't show is
  // kept. With no host (a rule added from scratch), the host is typed.
  let {
    host,
    keep = false,
    wantsWrite = false,
    paths = [],
    privateHost = false,
    resolvesPrivate = false,
    tlsRejected = false,
    rule = undefined,
    ondone = undefined,
    onsaving = undefined,
    pathHint = undefined,
    buttons = undefined,
  }: {
    host: string;
    keep?: boolean;
    wantsWrite?: boolean;
    paths?: string[];
    privateHost?: boolean;
    /** The gate found the name on a private address. */
    resolvesPrivate?: boolean;
    tlsRejected?: boolean;
    rule?: CompiledRule;
    ondone?: () => void;
    /** Called as a save starts (the saved rule replaces this one, under a new id). */
    onsaving?: () => void;
    /** A path picked from an attempt: the paths field takes it (a new object each pick). */
    pathHint?: { path: string };
    /** More buttons, beside the submit one (Revoke, Cancel). */
    buttons?: Snippet;
  } = $props();

  /** The duration option that keeps an edited rule's expiry. */
  const KEEP = -1;
  /** [`TTLS`] with labels short enough for one row of buttons. */
  const DURATIONS = TTLS.map((t) => ({
    value: t.minutes as number,
    label: ({ 15: "15m", 60: "1h", 1440: "1d", 0: "∞" } as Record<number, string>)[t.minutes],
  }));
  const listId = $props.id();

  let target = $state("");
  let access = $state<"read" | "write">("read");
  /** An edited rule's method list stays unless read or write is picked. */
  let accessPicked = $state(false);
  let scope = $state("");
  let ttl = $state(60);
  let tunnel = $state(false);
  let allowPrivate = $state(false);
  /** The user set the private switch: luoto no longer sets it from the host's addresses. */
  let privatePicked = $state(false);
  /** What the host resolves to on this machine, once asked. */
  let resolved = $state<Resolved | null>(null);
  /** The user typed the host: a name the sandbox chose is never looked up unasked. */
  let typed = $state(false);
  let risks = $state<string[]>([]);
  let hostField = $state<HTMLInputElement>();

  // Reset whenever the subject changes: to the rule being edited, or to the narrowest
  // defaults. Never a tunnel unless the rule is one: code in the sandbox can stage a TLS
  // reject for any host.
  $effect(() => {
    if (rule) {
      target = rule.host;
      access = rule.access === "write" ? "write" : "read";
      scope = (rule.paths ?? []).join(" ");
      ttl = KEEP;
      tunnel = rule.mode === "tunnel";
      allowPrivate = !!rule.allow_private;
    } else {
      target = host;
      access = wantsWrite ? "write" : "read";
      scope = "";
      ttl = keep ? 0 : 60;
      tunnel = false;
      allowPrivate = false;
    }
    accessPicked = false;
    privatePicked = false;
    typed = false;
    risks = [];
  });

  // Ask what a host the user typed resolves to here, a moment after it stops changing: a
  // lookup on this machine's resolver carries whatever is in the name, so a sandbox's is never
  // looked up unasked. A new rule for a name on a private address (the user's network, a VPN)
  // gets the private switch on, which saving then confirms; the gate vets every address again
  // when it dials.
  $effect(() => {
    const h = target.trim();
    resolved = null;
    risks = [];
    if (!typed || !h || h.includes("*")) return;
    const timer = setTimeout(() => {
      void api
        .resolve(h)
        .then((r) => {
          if (target.trim() !== h) return;
          resolved = r;
          if (!rule && !privatePicked && r.private.length > 0) allowPrivate = true;
        })
        .catch(() => {});
    }, 400);
    return () => clearTimeout(timer);
  });

  $effect(() => {
    if (!rule && !host) hostField?.focus();
  });

  $effect(() => {
    if (pathHint) scope = pathHint.path;
  });

  const methods = $derived(rule && Array.isArray(rule.access) ? rule.access : null);

  const prefixes = $derived(
    [
      ...new Set(paths.map((p) => p.split("/").slice(0, 2).join("/")).filter((p) => p.length > 1)),
    ].map((p) => `${p}/**`),
  );

  const keepLabel = $derived(rule?.expires ? leftText(rule.expires) : "until revoked");

  const notes = $derived(
    [
      access === "write" &&
        (accessPicked || !methods) &&
        "write lets code in the sandbox upload data to this host",
      target === "*" && "a lone wildcard covers every host: even reads can leak data in URLs",
      tunnel &&
        "a tunnel is not inspected: any method and path, no credential stripping or injection, no git or GraphQL guards",
      allowPrivate && "reaches services on your machine or network",
      (ttl === 0 || (ttl === KEEP && !rule?.expires)) && "stays until you revoke it",
    ].filter(Boolean) as string[],
  );

  function built(): Rule {
    const { id: _id, origin: _origin, ...kept } = rule ?? { id: "", origin: "" };
    const scoped = scope.split(/\s+/).filter(Boolean);
    return {
      ...kept,
      host: target.trim(),
      access: tunnel ? "write" : methods && !accessPicked ? methods : access,
      paths: scoped.length > 0 ? scoped : undefined,
      expires: ttl === KEEP ? rule?.expires : expiresIn(ttl),
      mode: tunnel ? "tunnel" : undefined,
      allow_private: allowPrivate || undefined,
      note: rule ? rule.note : keep ? "kept from open egress" : "added in luoto ui",
    };
  }

  /** A rule's fields in one order, without the empty ones: two that say the same compare equal. */
  const canonical = (r: Rule): string =>
    JSON.stringify(
      Object.entries(r)
        .filter(([k, v]) => k !== "id" && k !== "origin" && v !== undefined && v !== null)
        .sort(([a], [b]) => a.localeCompare(b)),
    );

  // An edited rule saves only once it differs from what is saved; a new one always.
  const dirty = $derived(!rule || canonical(built()) !== canonical(rule));

  const privateAt = $derived(resolved?.private.join(", ") ?? "");
  // The gate's check reports every rule that reaches private addresses as a risk: the private
  // question asks it, so the list beside it holds only the others.
  const otherRisks = $derived(risks.filter((r) => !r.includes("private/host addresses")));

  function withoutPrivate() {
    allowPrivate = false;
    privatePicked = true;
    risks = [];
    void attempt(false);
  }

  async function attempt(force: boolean) {
    onsaving?.();
    const env = app.env;
    if (!env) return;
    const r = built();
    const ttlLabel = TTLS.find((t) => t.minutes === ttl)?.label;
    const editing = rule;
    const done = await act(
      editing ? "saving…" : keep ? "keeping…" : "allowing…",
      () => (editing ? api.replaceRule(env, editing.id, r, force) : api.addRule(env, r, force)),
      editing
        ? `saved ${r.host}`
        : `${keep ? "kept" : "allowed"} ${r.host}${ttl ? ` for ${ttlLabel}` : ""}`,
      (found) => (risks = found),
    );
    if (done) {
      risks = [];
      ondone?.();
    }
  }
</script>

<form class="builder" onsubmit={(e) => (e.preventDefault(), void attempt(false))}>
  <p class="label">{rule ? "edit" : keep ? "keep" : "allow"}</p>
  <label class="field">
    <span>host</span>
    <input
      type="text"
      bind:value={target}
      bind:this={hostField}
      oninput={() => (typed = true)}
      placeholder="api.example.com"
    />
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
      onchange={(v) => ((access = v), (accessPicked = true))}
    />
    {#if methods && !accessPicked}
      <span class="muted small">{methods.join(", ")} only</span>
    {/if}
  </div>
  <label class="field">
    <span>paths</span>
    <input type="text" list={listId} bind:value={scope} disabled={tunnel} placeholder="all paths" />
  </label>
  <datalist id={listId}>
    {#each prefixes as p (p)}<option value={p}></option>{/each}
  </datalist>
  <div class="field">
    <span>for</span>
    <Segmented
      label="for"
      options={[...(rule ? [{ value: KEEP, label: "keep" }] : []), ...DURATIONS]}
      value={ttl}
      onchange={(v) => (ttl = v)}
    />
    {#if ttl === KEEP}<span class="muted small">{keepLabel}</span>{/if}
  </div>
  <div class="field">
    <span>tunnel</span>
    <Switch checked={tunnel} label="opaque tunnel" onchange={(v) => (tunnel = v)} />
    <span class="muted small"
      >{tlsRejected
        ? "a client here rejected our certificate: if it pins certificates, it needs a tunnel"
        : "for certificate-pinning clients"}</span
    >
  </div>
  <!-- Always offered: the gate never resolves a blocked name, so its address may be unknown
       until this machine's resolver answers. -->
  <div class="field">
    <span>private</span>
    <Switch
      checked={allowPrivate}
      label="allow private address"
      onchange={(v) => ((allowPrivate = v), (privatePicked = true))}
    />
    <span class="muted small" class:warn={resolved?.never}
      >{resolved?.never
        ? "resolves to this machine or cloud metadata, which no rule reaches"
        : privateAt
          ? `resolves to ${privateAt}, a private address`
          : resolvesPrivate
            ? "this name resolved to a private address: without this, the rule doesn't reach it"
            : privateHost
              ? "a private address"
              : "for a host on your network or VPN"}</span
    >
  </div>

  {#if notes.length > 0}
    <ul class="notes">
      {#each notes as n (n)}<li>{n}</li>{/each}
    </ul>
  {/if}

  {#if risks.length > 0 && allowPrivate}
    <!-- One question for a rule that reaches private addresses, its other risks beside it. -->
    <div class="confirm" role="alertdialog" aria-label="reach a private address">
      <p>
        {#if privateAt}
          Let <strong>{target.trim()}</strong> reach its private address {privateAt}? It is on your
          network or behind a VPN.
        {:else}
          Let <strong>{target.trim()}</strong> reach private addresses? Those are your network's, a VPN's
          and services on this machine.
        {/if}
      </p>
      {#if otherRisks.length > 0}
        <ul class="notes">
          {#each otherRisks as r (r)}<li>{r}</li>{/each}
        </ul>
      {/if}
      <div class="buttons">
        <button
          type="button"
          class="btn primary"
          onclick={() => void attempt(true)}
          disabled={!!app.busy}>{rule ? "Save" : "Allow"}</button
        >
        <button type="button" class="btn" onclick={withoutPrivate} disabled={!!app.busy}
          >{rule ? "Save" : "Allow"} without private</button
        >
        <button type="button" class="btn" onclick={() => (risks = [])}>Back</button>
      </div>
    </div>
  {:else if risks.length > 0}
    <Risks
      {risks}
      confirm={rule ? "Save anyway" : "Allow anyway"}
      onconfirm={() => void attempt(true)}
    />
    {#if buttons}<div class="buttons">{@render buttons()}</div>{/if}
  {:else}
    <div class="buttons">
      <button
        type="submit"
        class="btn primary"
        disabled={!target.trim() || !dirty || !!app.busy}
        title={dirty ? undefined : "nothing changed"}
        >{rule ? "Save" : keep ? "Keep" : "Allow"}</button
      >
      {@render buttons?.()}
    </div>
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

  .confirm {
    padding: 8px 10px;
    border-left: 2px solid var(--halo-accent);
    background: var(--halo-accent-soft);
    font-size: 13px;
  }

  .confirm p {
    margin: 0 0 4px;
  }

  .warn {
    color: var(--halo-error);
  }

  .buttons {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 4px;
  }
</style>
