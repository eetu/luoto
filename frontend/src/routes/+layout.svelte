<script lang="ts">
  import "$lib/styles/halo.css";

  import type { Snippet } from "svelte";

  import ContextMenu from "$lib/components/ContextMenu.svelte";

  let { children }: { children: Snippet } = $props();

  // One menu policy: the browser's own menu is suppressed everywhere except text fields.
  function onContextMenu(e: MouseEvent) {
    const t = e.target as HTMLElement | null;
    if (t?.closest("input, textarea, [contenteditable='true']")) return;
    e.preventDefault();
  }
</script>

<svelte:window oncontextmenu={onContextMenu} />

{@render children()}
<ContextMenu />

<style>
  :global(html),
  :global(body) {
    height: 100svh;
    height: 100dvh;
  }

  :global(body) {
    display: flex;
    flex-direction: column;
    margin: 0;
    overflow: hidden;
    background: var(--halo-body);
    color: var(--halo-text-main);
    font-family: var(--halo-font-body);
    font-size: 14px;
  }

  :global(button) {
    font: inherit;
    cursor: pointer;
  }

  :global(.btn) {
    display: inline-flex;
    gap: 6px;
    align-items: center;
    padding: 5px 10px;
    border: 1px solid var(--halo-border);
    border-radius: var(--halo-radius);
    background: var(--halo-bg-main);
    color: var(--halo-text-main);
    font-size: 13px;
    white-space: nowrap;
  }

  :global(.btn:hover:not([disabled])) {
    border-color: var(--halo-accent);
    color: var(--halo-accent);
  }

  :global(.btn.primary) {
    border-color: var(--halo-accent);
    background: var(--halo-accent);
    color: var(--halo-on-accent);
  }

  :global(.btn.primary:hover:not([disabled])) {
    color: var(--halo-on-accent);
    filter: brightness(1.05);
  }

  :global(.btn.danger) {
    color: var(--halo-error);
  }

  :global(.btn[disabled]) {
    opacity: 0.5;
    cursor: default;
  }

  :global(.panel) {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  :global(.section) {
    margin-top: 12px;
    padding-top: 10px;
    border-top: 1px solid var(--halo-border);
  }

  :global(.actions) {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 4px;
  }

  /* A command, copied on click. */
  :global(.cmd) {
    display: flex;
    gap: 6px;
    align-items: center;
    padding: 4px 6px;
    border: none;
    border-radius: var(--halo-radius);
    background: var(--halo-bg-light);
    color: var(--halo-text-main);
    text-align: left;
  }

  :global(.cmd code) {
    flex: 1;
  }

  :global(.small) {
    margin: 0;
    font-size: 12px;
    word-break: break-word;
  }

  :global(.warn) {
    margin: 0;
    color: var(--halo-error);
    font-size: 12px;
  }

  /* Text written by code in the sandbox. */
  :global(.untrusted) {
    padding: 6px 8px;
    border-left: 2px solid var(--halo-error);
    background: var(--halo-bg-light);
  }

  :global(.field) {
    display: grid;
    grid-template-columns: 58px 1fr;
    gap: 8px;
    align-items: center;
    font-size: 13px;
  }

  :global(.field > span:first-child) {
    color: var(--halo-text-muted);
  }

  :global(.label) {
    margin: 0 0 6px;
    color: var(--halo-text-muted);
    font-family: var(--halo-font-heading);
    font-size: 11px;
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }

  :global(.muted) {
    color: var(--halo-text-muted);
  }

  :global(code),
  :global(.mono) {
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    font-size: 12px;
  }

  :global(input[type="text"]),
  :global(input[type="number"]),
  :global(select) {
    box-sizing: border-box;
    padding: 5px 8px;
    border: 1px solid var(--halo-border);
    border-radius: var(--halo-radius);
    background: var(--halo-bg-main);
    color: var(--halo-text-main);
    font: inherit;
    font-size: 13px;
  }

  :global(input:focus-visible),
  :global(select:focus-visible),
  :global(button:focus-visible) {
    outline: 2px solid var(--halo-accent);
    outline-offset: 1px;
  }
</style>
