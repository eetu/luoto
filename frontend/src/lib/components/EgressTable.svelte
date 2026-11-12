<script lang="ts">
  import { api } from "$lib/api";
  import { openMenu } from "$lib/menu.svelte";
  import { act, ago, app, copyText, expiresIn, TTLS } from "$lib/stores/app.svelte";
  import type { HostSummary } from "$lib/types";

  function decision(h: HostSummary): { text: string; cls: string } {
    if (h.dns_only) return { text: "looked up", cls: "dns" };
    if (h.opened > 0) return { text: "open", cls: "open" };
    if (h.tls_rejected) return { text: "pinned?", cls: "mixed" };
    // What was blocked a rule allows now: the denials are history.
    if (h.allowed_now) return { text: "allowed", cls: "allowed" };
    if (h.denied > 0 && h.allowed === 0) return { text: "blocked", cls: "blocked" };
    if (h.denied > 0) return { text: "partly", cls: "mixed" };
    return { text: "allowed", cls: "allowed" };
  }

  function quickAllow(h: HostSummary, write: boolean, minutes: number) {
    const ttl = TTLS.find((t) => t.minutes === minutes)?.label;
    const label = `${h.host} ${write ? "write" : "read"}${minutes ? ` for ${ttl}` : ""}`;
    void act(
      "allowing…",
      () =>
        api.addRule(
          app.env ?? "",
          { host: h.host, access: write ? "write" : "read", expires: expiresIn(minutes) },
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
        run: () => quickAllow(h, false, 0),
        hint: "until revoked",
      },
      {
        label: h.opened > 0 ? "Keep…" : "Allow…",
        run: () => (app.subject = { kind: "host", host: h.host }),
        hint:
          h.opened > 0 ? "reached through open egress" : h.wants_write ? "write wanted" : undefined,
      },
      { label: "Copy host", run: () => copyText(h.host) },
    ]);
  }
</script>

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
              {#if h.allowed_now}<div class="why">
                  blocked before rule {h.allowed_now}
                </div>{:else if h.denied > 0 && h.last_message}<div class="why">
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

<style>
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

  .chip.open {
    border: 1px solid var(--halo-accent);
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
