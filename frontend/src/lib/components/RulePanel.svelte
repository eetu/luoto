<script lang="ts">
  import { api } from "$lib/api";
  import RuleBuilder from "$lib/components/RuleBuilder.svelte";
  import { accessText, act, app, leftText, say } from "$lib/stores/app.svelte";

  // One of the env's rules, or a new one (`id` null). The user's own is edited here and saved
  // in place; a preset's, agent's or provider's is shown as it is. Saving, revoking or Cancel
  // returns where it was opened from (a host, else the env); a rule that expires or is revoked
  // meanwhile does too.
  let { id, from }: { id: string | null; from?: { kind: "host"; host: string } } = $props();

  const rule = $derived(id ? (app.detail?.rules.find((r) => r.id === id) ?? null) : null);
  const mine = $derived(rule?.origin === "user");
  const back = () => (app.subject = from ?? { kind: "env" });
  /** This panel saved or revoked the rule, so its going is no news. */
  let changing = $state(false);

  $effect(() => {
    if (id && app.detail && !rule && !changing) {
      say("that rule is gone: it expired or was revoked");
      back();
    }
  });

  // What the rule says beyond its host and access, one fact a line.
  const facts = $derived.by(() => {
    if (!rule) return [];
    return [
      ["from", rule.origin === "user" ? "you" : rule.origin],
      ["allows", accessText(rule.access)],
      ["paths", rule.paths?.length ? rule.paths.join(" ") : "all"],
      ["port", rule.port ? String(rule.port) : null],
      ["lasts", rule.expires ? leftText(rule.expires) : mine ? "until revoked" : null],
      ["private", rule.allow_private ? "reaches a private address" : null],
      ["tunnel", rule.mode === "tunnel" ? "opaque, not inspected" : null],
      ["websocket", rule.ws ? "allowed" : null],
      ["idle", rule.idle ?? null],
      ["note", rule.note ?? null],
      ["id", rule.id],
    ].filter(([, v]) => v) as [string, string][];
  });

  function revoke() {
    const env = app.env;
    const r = rule;
    if (!env || !r) return;
    changing = true;
    void act("revoking…", () => api.deleteRule(env, r.id), `revoked ${r.host}`).then(
      (done) => done !== null && back(),
    );
  }
</script>

<div class="panel">
  <p class="label">rule</p>
  <h2>{rule ? rule.host : "new rule"}</h2>
  {#if rule}
    <dl class="facts">
      {#each facts as [k, v] (k)}
        <dt>{k}</dt>
        <dd class:mono={k === "paths" || k === "id"}>{v}</dd>
      {/each}
    </dl>
    <button
      class="link"
      onclick={() =>
        (app.subject = { kind: "host", host: rule.host, back: { kind: "rule", id: rule.id } })}
      >Show its egress</button
    >
  {/if}

  {#if !id || mine}
    <div class="section">
      <RuleBuilder
        host=""
        rule={rule ?? undefined}
        ondone={back}
        onsaving={() => (changing = true)}
      >
        {#snippet buttons()}
          <button type="button" class="btn" onclick={back}>Cancel</button>
          {#if mine}
            <button type="button" class="btn danger revoke" onclick={revoke}>Revoke</button>
          {/if}
        {/snippet}
      </RuleBuilder>
    </div>
  {:else if rule}
    <p class="muted small section">
      From {rule.origin}: luoto's own data, so it can't be edited or revoked on its own.
    </p>
  {/if}
</div>

<style>
  h2 {
    margin: 0;
    font-size: 15px;
    overflow-wrap: anywhere;
  }

  .facts {
    display: grid;
    grid-template-columns: 70px 1fr;
    gap: 3px 8px;
    margin: 10px 0 6px;
    font-size: 12px;
  }

  dt {
    color: var(--halo-text-muted);
  }

  dd {
    margin: 0;
    overflow-wrap: anywhere;
  }

  .link {
    align-self: flex-start;
    padding: 0;
    border: none;
    background: transparent;
    color: var(--halo-accent);
    font-size: 12px;
    cursor: pointer;
  }

  /* The destructive one apart from Save and Cancel. */
  .revoke {
    margin-left: auto;
  }
</style>
