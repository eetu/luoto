<script lang="ts">
  import Segmented from "$lib/components/Segmented.svelte";
  import { app } from "$lib/stores/app.svelte";

  // The env's name, and which of its views the surface shows.
</script>

<div class="tabs">
  <h1>{app.env ?? ""}</h1>
  <Segmented
    label="env view"
    options={[
      { value: "egress", label: "egress" },
      { value: "rules", label: "rules" },
    ]}
    value={app.surface}
    onchange={(v) => (app.surface = v)}
  />
</div>

<style>
  .tabs {
    display: flex;
    gap: 12px;
    align-items: center;
  }
</style>
