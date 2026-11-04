<script lang="ts">
  import type { Snippet } from "svelte";

  import { closeMenu } from "$lib/menu.svelte";

  // The one dialog shell: veil, focus, Escape (bound at the window), Enter-with-button-guard,
  // and the halo-dialog geometry where only the body scrolls.
  let {
    open,
    title,
    onClose,
    onConfirm,
    body,
    footer,
  }: {
    open: boolean;
    title: string;
    onClose: () => void;
    onConfirm?: () => void;
    body: Snippet;
    footer?: Snippet;
  } = $props();

  function onKeydown(e: KeyboardEvent) {
    if (!open) return;
    if (e.key === "Escape") {
      e.stopPropagation();
      onClose();
      return;
    }
    if (e.key === "Enter" && onConfirm) {
      const el = document.activeElement;
      if (el instanceof HTMLButtonElement || el instanceof HTMLTextAreaElement) return;
      e.preventDefault();
      onConfirm();
    }
  }

  function focusFirst(node: HTMLElement) {
    (node.querySelector<HTMLElement>("input, select, textarea") ?? node).focus();
  }

  $effect(() => {
    if (open) closeMenu();
  });
</script>

<svelte:window onkeydown={onKeydown} />

{#if open}
  <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
  <div class="scrim" onclick={(e) => e.target === e.currentTarget && onClose()}>
    <div
      class="halo-dialog halo-card"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      tabindex="-1"
      use:focusFirst
    >
      <header>
        <h2>{title}</h2>
      </header>
      <div data-body>{@render body()}</div>
      {#if footer}
        <footer>{@render footer()}</footer>
      {/if}
    </div>
  </div>
{/if}

<style>
  .scrim {
    position: fixed;
    inset: 0;
    z-index: 50;
    display: grid;
    place-items: center;
    padding: 24px;
    background: rgb(0 0 0 / 0.35);
  }

  h2 {
    margin: 0;
    font-size: 15px;
    font-weight: 600;
  }
</style>
