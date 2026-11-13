<script lang="ts">
  import EgressTable from "$lib/components/EgressTable.svelte";
  import PendingRequests from "$lib/components/PendingRequests.svelte";
  import Segmented from "$lib/components/Segmented.svelte";
  import Switch from "$lib/components/Switch.svelte";
  import { app, refreshEnv, WINDOWS } from "$lib/stores/app.svelte";

  function setWindow(m: number) {
    app.minutes = m;
    void refreshEnv();
  }
</script>

<section class="surface">
  <header class="bar">
    <h1>{app.env ?? ""} <span class="muted">egress</span></h1>
    <div class="tools">
      <Segmented
        label="time window"
        options={WINDOWS.map((w) => ({ value: w.minutes, label: w.label }))}
        value={app.minutes}
        onchange={setWindow}
      />
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

  <PendingRequests />
  <EgressTable />
</section>

<style>
  .bar {
    justify-content: space-between;
  }

  .tools {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    align-items: center;
  }

  .toggle {
    display: inline-flex;
    gap: 6px;
    align-items: center;
    color: var(--halo-text-muted);
    font-size: 12px;
  }
</style>
