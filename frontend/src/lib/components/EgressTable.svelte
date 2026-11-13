<script lang="ts">
  import { api } from "$lib/api";
  import { openMenu } from "$lib/menu.svelte";
  import { act, ago, app, copyText, expiresIn, TTLS } from "$lib/stores/app.svelte";
  import type { HostSummary } from "$lib/types";

  function decision(h: HostSummary): { text: string; cls: string } {
    if (h.dns_only) return { text: "looked up", cls: "muted" };
    if (h.opened > 0) return { text: "open", cls: "outline" };
    if (h.tls_rejected) return { text: "pinned?", cls: "accent" };
    // What was blocked a rule allows now: the denials are history.
    if (h.allowed_now) return { text: "allowed", cls: "plain" };
    if (h.denied > 0 && h.allowed === 0) return { text: "blocked", cls: "bad" };
    if (h.denied > 0) return { text: "partly", cls: "accent" };
    return { text: "allowed", cls: "plain" };
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

  const show = (h: HostSummary) => (app.subject = { kind: "host", host: h.host });

  const onKey = (e: KeyboardEvent, h: HostSummary) => {
    if (e.key !== "Enter" && e.key !== " ") return;
    e.preventDefault();
    show(h);
  };

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
        run: () => show(h),
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
    <table class="list">
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
            tabindex="0"
            onclick={() => show(h)}
            onkeydown={(e) => onKey(e, h)}
            oncontextmenu={(e) => menu(e, h)}
          >
            <td
              ><span
                class="chip {d.cls}"
                title={h.dns_only
                  ? "looked up, never connected: nothing left the sandbox"
                  : undefined}>{d.text}</span
              ></td
            >
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
            <td class="num" class:error={h.denied > 0}>{h.denied || ""}</td>
            <td class="muted">{ago(h.last_seen)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<style>
  .host {
    font-weight: 500;
    word-break: break-all;
  }

  .num {
    text-align: right;
    font-variant-numeric: tabular-nums;
  }
</style>
