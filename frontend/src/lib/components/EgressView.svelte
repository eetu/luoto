<script lang="ts">
  import ShieldQuestion from "@lucide/svelte/icons/shield-question";

  import { api } from "$lib/api";
  import Switch from "$lib/components/Switch.svelte";
  import { openMenu } from "$lib/menu.svelte";
  import { act, ago, app, refreshEnv, say, WINDOWS } from "$lib/stores/app.svelte";
  import type { HostSummary } from "$lib/types";

  function decision(h: HostSummary): { text: string; cls: string } {
    if (h.dns_only) return { text: "looked up", cls: "dns" };
    if (h.tls_rejected) return { text: "pinned?", cls: "mixed" };
    if (h.denied > 0 && h.allowed === 0) return { text: "blocked", cls: "blocked" };
    if (h.denied > 0) return { text: "partly", cls: "mixed" };
    return { text: "allowed", cls: "allowed" };
  }

  function quickAllow(h: HostSummary, write: boolean, minutes: number | null) {
    const expires = minutes ? new Date(Date.now() + minutes * 60_000).toISOString() : undefined;
    const label = `${h.host} ${write ? "write" : "read"}${minutes ? ` for ${minutes >= 60 ? `${minutes / 60} h` : `${minutes} min`}` : ""}`;
    void act(
      "allowing…",
      () =>
        api.addRule(
          app.env ?? "",
          { host: h.host, access: write ? "write" : "read", expires },
          false,
        ),
      `allowed ${label}`,
    );
  }

  function menu(e: MouseEvent, h: HostSummary) {
    openMenu(e, h.host, [
      { label: "Allow read for 1 h", run: () => quickAllow(h, false, 60) },
      {
        label: "Allow read",
        run: () => quickAllow(h, false, null),
        hint: "until revoked",
      },
      {
        label: "Allow…",
        run: () => (app.subject = { kind: "host", host: h.host }),
        hint: h.wants_write ? "write wanted" : undefined,
      },
      {
        label: "Copy host",
        run: () => void navigator.clipboard.writeText(h.host).then(() => say(`copied ${h.host}`)),
      },
    ]);
  }

  function setWindow(m: number) {
    app.minutes = m;
    void refreshEnv();
  }
</script>

<section class="surface">
  <header class="bar">
    <h1>{app.env ?? ""} <span class="muted">egress</span></h1>
    <div class="tools">
      <div class="seg" role="group" aria-label="time window">
        {#each WINDOWS as w (w.minutes)}
          <button class:active={app.minutes === w.minutes} onclick={() => setWindow(w.minutes)}
            >{w.label}</button
          >
        {/each}
      </div>
      <label class="toggle">
        <Switch
          checked={app.deniedOnly}
          label="blocked only"
          onchange={(v) => (app.deniedOnly = v)}
        />
        blocked only
      </label>
      <input
        type="text"
        placeholder="filter hosts"
        bind:value={app.search}
        aria-label="filter hosts"
      />
    </div>
  </header>

  {#if app.pending.length > 0}
    <div class="requests">
      {#each app.pending as r (r.id)}
        <button
          class="request halo-card"
          class:selected={app.subject.kind === "request" && app.subject.id === r.id}
          onclick={() => (app.subject = { kind: "request", id: r.id })}
        >
          <ShieldQuestion size={16} />
          <span><b>{r.access}</b> access to <b>{r.host}</b> requested from inside the sandbox</span>
          <span class="muted">#{r.id}, {ago(r.created)}: review</span>
        </button>
      {/each}
    </div>
  {/if}

  <div class="table-wrap">
    {#if app.visibleEgress.length === 0}
      <p class="empty muted">
        {#if app.egress.length === 0}
          no egress in this window. Everything the sandbox tries to reach shows up here.
        {:else}
          nothing matches the filter
        {/if}
      </p>
    {:else}
      <table>
        <thead>
          <tr>
            <th></th>
            <th>host</th>
            <th>methods</th>
            <th>via</th>
            <th class="num">allowed</th>
            <th class="num">blocked</th>
            <th>last</th>
          </tr>
        </thead>
        <tbody>
          {#each app.visibleEgress as h (h.host)}
            {@const d = decision(h)}
            <tr
              class:selected={app.subject.kind === "host" && app.subject.host === h.host}
              onclick={() => (app.subject = { kind: "host", host: h.host })}
              oncontextmenu={(e) => menu(e, h)}
            >
              <td><span class="chip {d.cls}">{d.text}</span></td>
              <td class="host">
                {h.host}
                {#if h.denied > 0 && h.last_message}<div class="why">
                    {h.last_message}
                  </div>{/if}
              </td>
              <td class="mono">{h.methods.join(" ")}</td>
              <td class="muted">{h.intakes.join(", ")}</td>
              <td class="num">{h.allowed || ""}</td>
              <td class="num" class:err={h.denied > 0}>{h.denied || ""}</td>
              <td class="muted">{ago(h.last_seen)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>
</section>

<style>
  .surface {
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
  }

  .bar {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    align-items: center;
    justify-content: space-between;
    padding: 14px 18px 10px;
  }

  h1 {
    margin: 0;
    font-size: 16px;
    font-weight: 600;
  }

  .tools {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    align-items: center;
  }

  .seg {
    display: inline-flex;
    overflow: hidden;
    border: 1px solid var(--halo-border);
    border-radius: var(--halo-radius);
  }

  .seg button {
    padding: 4px 9px;
    border: none;
    background: var(--halo-bg-main);
    color: var(--halo-text-muted);
    font-size: 12px;
  }

  .seg button.active {
    background: var(--halo-accent-soft);
    color: var(--halo-accent);
  }

  .toggle {
    display: inline-flex;
    gap: 6px;
    align-items: center;
    color: var(--halo-text-muted);
    font-size: 12px;
  }

  .requests {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding: 0 18px 10px;
  }

  .request {
    display: flex;
    gap: 10px;
    align-items: center;
    padding: 9px 12px;
    border: 1px solid transparent;
    color: var(--halo-text-main);
    text-align: left;
  }

  .request :global(svg) {
    flex: none;
    color: var(--halo-accent);
  }

  .request span:nth-child(2) {
    flex: 1;
  }

  .request.selected {
    border-color: var(--halo-accent);
  }

  .table-wrap {
    flex: 1;
    min-height: 0;
    padding: 0 18px 18px;
    overflow: auto;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }

  th {
    position: sticky;
    top: 0;
    padding: 6px 8px;
    border-bottom: 1px solid var(--halo-border);
    background: var(--halo-body);
    color: var(--halo-text-muted);
    font-family: var(--halo-font-heading);
    font-size: 11px;
    font-weight: 500;
    letter-spacing: 0.04em;
    text-align: left;
    text-transform: uppercase;
  }

  td {
    padding: 7px 8px;
    border-bottom: 1px solid var(--halo-border);
    vertical-align: top;
  }

  tr {
    cursor: default;
  }

  tbody tr:hover {
    background: var(--halo-bg-light);
  }

  tr.selected {
    background: var(--halo-accent-soft);
  }

  .host {
    font-weight: 500;
    word-break: break-all;
  }

  .why {
    margin-top: 2px;
    color: var(--halo-text-muted);
    font-size: 12px;
    font-weight: 400;
  }

  .num {
    text-align: right;
    font-variant-numeric: tabular-nums;
  }

  .err {
    color: var(--halo-error);
  }

  .chip {
    display: inline-block;
    padding: 1px 7px;
    border-radius: var(--halo-radius-pill, 999px);
    font-size: 11px;
    white-space: nowrap;
  }

  .chip.blocked {
    background: color-mix(in srgb, var(--halo-error) 15%, transparent);
    color: var(--halo-error);
  }

  .chip.mixed {
    background: var(--halo-accent-soft);
    color: var(--halo-accent);
  }

  .chip.allowed {
    background: var(--halo-bg-light);
    color: var(--halo-text-main);
  }

  .chip.dns {
    border: 1px dashed var(--halo-border);
    color: var(--halo-text-muted);
  }

  .empty {
    margin: 30px 0;
    text-align: center;
  }
</style>
