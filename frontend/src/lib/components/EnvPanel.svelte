<script lang="ts">
  import { api } from "$lib/api";
  import ConnectSection from "$lib/components/ConnectSection.svelte";
  import CredentialsSection from "$lib/components/CredentialsSection.svelte";
  import ProjectSection from "$lib/components/ProjectSection.svelte";
  import RulesSection from "$lib/components/RulesSection.svelte";
  import SelftestSection from "$lib/components/SelftestSection.svelte";
  import WorkspaceSection from "$lib/components/WorkspaceSection.svelte";
  import { act, app } from "$lib/stores/app.svelte";

  const d = $derived(app.detail);
</script>

{#if d}
  <!-- Sections hold per-env state (pull plan, self-test report): a new env starts them fresh. -->
  {#key app.env}
    <div class="panel">
      <p class="label">env</p>
      <h2>{d.name}</h2>
      <p class="muted small">
        dev {d.dev}, gate {d.gate}{d.gate_status ? `, ${d.gate_status.rules} rules` : ""}
      </p>
      <div class="actions">
        {#if d.dev === "running"}
          <button
            class="btn"
            onclick={() =>
              void act("stopping…", () => api.action(d.name, "down"), `${d.name} stopped`)}
            >stop</button
          >
        {:else}
          <button
            class="btn primary"
            onclick={() => void act("starting…", () => api.action(d.name, "up"), `${d.name} is up`)}
            >start</button
          >
        {/if}
        <SelftestSection />
      </div>

      {#each d.warnings as w, n (n)}<p class="warn">{w}</p>{/each}

      <WorkspaceSection />
      <ProjectSection />
      <ConnectSection />
      <CredentialsSection />
      <RulesSection />
    </div>
  {/key}
{:else}
  <p class="muted">select an env</p>
{/if}

<style>
  h2 {
    margin: 0;
    font-size: 15px;
  }
</style>
