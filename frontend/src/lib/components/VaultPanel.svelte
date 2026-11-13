<script lang="ts">
  import CopyCommand from "$lib/components/CopyCommand.svelte";
  import { app, openVault, plural, selectEnv } from "$lib/stores/app.svelte";

  const v = $derived(app.vault);
  const status = $derived(v?.status ?? null);
  const subject = $derived(app.subject.kind === "credential" ? app.subject : null);
  const cred = $derived(
    subject
      ? (v?.credentials.find((c) => c.env === subject.env && c.binding === subject.binding) ?? null)
      : null,
  );
  // Other credentials whose secret is kept in the same place: rotating it changes them too.
  const sharing = $derived(
    cred
      ? (v?.credentials.filter(
          (c) => c.kept === cred.kept && !(c.env === cred.env && c.binding === cred.binding),
        ) ?? [])
      : [],
  );
  const counts = $derived({
    envs: new Set(v?.credentials.map((c) => c.env)).size,
    credentials: v?.credentials.length ?? 0,
    missing: v?.credentials.filter((c) => c.state === "missing").length ?? 0,
  });
</script>

<div class="panel">
  {#if cred}
    <p class="label">credential</p>
    <h2>{cred.env}: <code>{cred.binding}</code></h2>
    <p class="muted small">{cred.what}</p>
    <div class="section">
      <p class="label">kept in</p>
      <p class="mono small">{cred.kept}</p>
      <p class="muted small">
        {cred.state === "loaded"
          ? "the vault holds it"
          : cred.state === "missing"
            ? "not read yet: unlock reads it"
            : cred.state === "locked"
              ? "the vault is locked: unlock"
              : "registered at the env's next luoto up"}{#if sharing.length}; also used by
          {sharing.map((c) => `${c.env} (${c.binding})`).join(", ")}: rotating it changes them too{/if}
      </p>
    </div>
    <div class="section">
      <p class="label">goes to</p>
      <p class="small">{cred.hosts.join(", ") || "no host"}</p>
      <p class="muted small">
        the gate adds it on these hosts; the env sees a placeholder, never the secret
      </p>
    </div>
    <div class="section">
      <p class="label">change it</p>
      {#if cred.change}
        <CopyCommand cmd={cred.change} />
      {:else}
        <p class="muted small">no command yet: it is in the env's own file, under [credentials]</p>
      {/if}
    </div>
    <div class="actions">
      <button class="btn" onclick={() => void selectEnv(cred.env)}>Show {cred.env}'s egress</button>
      <button class="btn" onclick={() => openVault()}>Back to the vault</button>
    </div>
  {:else if subject}
    <p class="muted">this credential is no longer listed</p>
  {:else}
    <p class="label">vault</p>
    <h2>{!status ? "not running" : status.locked ? "locked" : "unlocked"}</h2>
    <p class="muted small">
      One vault for every env on this machine. It holds secrets in memory only, never on disk, and
      hands each env's gate short-lived, scoped credentials; the envs see placeholders.
      {status?.locked ? "After a restart it is locked until you unlock it." : ""}
    </p>
    {#if v}
      <p class="small">
        {plural(counts.credentials, "credential")} in {plural(
          counts.envs,
          "env",
        )}{#if counts.missing}, <span class="error">{counts.missing} missing</span
          >{/if}{#if v.unused.length}, {plural(v.unused.length, "secret")} no env uses{/if}
      </p>
    {/if}
    <p class="muted small">
      Pick a credential for where it is kept, where it goes and how to change it.
    </p>
  {/if}
</div>

<style>
  h2 {
    margin: 0;
    font-size: 15px;
    word-break: break-all;
  }
</style>
