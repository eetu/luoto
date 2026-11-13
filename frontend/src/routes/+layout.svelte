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

  :global(.error) {
    color: var(--halo-error);
  }

  /* The surface: a header bar over a table that scrolls (an env's egress, the vault). */
  :global(.surface) {
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
  }

  :global(.surface > .bar) {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    align-items: center;
    padding: 14px 18px 10px;
  }

  :global(.surface h1) {
    margin: 0;
    font-size: 16px;
    font-weight: 600;
  }

  :global(.table-wrap) {
    flex: 1;
    min-height: 0;
    padding: 0 18px 18px;
    overflow: auto;
  }

  :global(.table-wrap > .empty) {
    margin: 30px 0;
    text-align: center;
  }

  :global(table.list) {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }

  :global(.list th) {
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

  :global(.list td) {
    padding: 7px 8px;
    border-bottom: 1px solid var(--halo-border);
    vertical-align: top;
  }

  /* A row that opens its subject: on click, or Enter/Space when focused. */
  :global(.list tr[tabindex]) {
    cursor: default;
  }

  :global(.list tr[tabindex]:hover) {
    background: var(--halo-bg-light);
  }

  :global(.list tr[tabindex]:focus-visible) {
    outline: 2px solid var(--halo-accent);
    outline-offset: -2px;
  }

  :global(.list tr.selected) {
    background: var(--halo-accent-soft);
  }

  /* A line under a row's main text. */
  :global(.list .why) {
    margin-top: 2px;
    color: var(--halo-text-muted);
    font-size: 12px;
    font-weight: 400;
  }

  /* A state, in a pill. Muted is an inactive state: dashed borders mean borrowed. */
  :global(.chip) {
    display: inline-block;
    padding: 1px 7px;
    border: 1px solid transparent;
    border-radius: var(--halo-radius-pill, 999px);
    font-size: 11px;
    white-space: nowrap;
  }

  :global(.chip.plain) {
    background: var(--halo-bg-light);
    color: var(--halo-text-main);
  }

  :global(.chip.bad) {
    background: color-mix(in srgb, var(--halo-error) 15%, transparent);
    color: var(--halo-error);
  }

  :global(.chip.accent) {
    background: var(--halo-accent-soft);
    color: var(--halo-accent);
  }

  :global(.chip.outline) {
    border-color: var(--halo-accent);
    color: var(--halo-accent);
  }

  :global(.chip.muted) {
    border-color: var(--halo-border);
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
