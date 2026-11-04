<script lang="ts">
  import { activeMenu, closeMenu } from "$lib/menu.svelte";

  // The app's only context menu, mounted once at the root so no panel can clip it.
  const menu = $derived(activeMenu());

  function place(node: HTMLElement) {
    const r = node.getBoundingClientRect();
    const pad = 8;
    const dx = Math.min(0, window.innerWidth - pad - r.right);
    const dy = Math.min(0, window.innerHeight - pad - r.bottom);
    if (dx || dy) node.style.transform = `translate(${dx}px, ${dy}px)`;
    node.querySelector<HTMLButtonElement>("button:not([disabled])")?.focus();
  }

  function onMenuKeydown(e: KeyboardEvent) {
    const list = [
      ...(e.currentTarget as HTMLElement).querySelectorAll<HTMLButtonElement>(
        "button:not([disabled])",
      ),
    ];
    const i = list.indexOf(document.activeElement as HTMLButtonElement);
    if (e.key === "ArrowDown") {
      list[(i + 1) % list.length]?.focus();
      e.preventDefault();
    } else if (e.key === "ArrowUp") {
      list[(i - 1 + list.length) % list.length]?.focus();
      e.preventDefault();
    }
  }

  $effect(() => {
    if (!menu) return;
    const outside = (e: Event) => {
      if (!(e.target as HTMLElement | null)?.closest("[role='menu']")) closeMenu();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      closeMenu();
      e.stopPropagation();
      e.preventDefault();
    };
    window.addEventListener("pointerdown", outside, true);
    window.addEventListener("keydown", onKey, true);
    window.addEventListener("blur", closeMenu);
    window.addEventListener("resize", closeMenu);
    return () => {
      window.removeEventListener("pointerdown", outside, true);
      window.removeEventListener("keydown", onKey, true);
      window.removeEventListener("blur", closeMenu);
      window.removeEventListener("resize", closeMenu);
    };
  });
</script>

{#if menu}
  <div
    class="ctx"
    style:left="{menu.x}px"
    style:top="{menu.y}px"
    role="menu"
    tabindex="-1"
    use:place
    onkeydown={onMenuKeydown}
  >
    <p class="ctx-title">{menu.title}</p>
    {#each menu.items as it (it.label)}
      <button
        role="menuitem"
        class:danger={it.danger}
        disabled={it.disabled}
        title={it.hint}
        onclick={() => {
          it.run();
          closeMenu();
        }}
      >
        <span>{it.label}</span>
        {#if it.hint}<span class="hint">{it.hint}</span>{/if}
      </button>
    {/each}
  </div>
{/if}

<style>
  .ctx {
    position: fixed;
    z-index: 61;
    min-width: 170px;
    padding: 4px;
    border: 1px solid var(--halo-border);
    border-radius: var(--halo-radius);
    background: var(--halo-bg-light);
    box-shadow: var(--halo-shadow, 0 8px 24px rgb(0 0 0 / 0.25));
  }

  .ctx-title {
    margin: 2px 10px 4px;
    overflow: hidden;
    max-width: 280px;
    color: var(--halo-text-muted);
    font-size: 11px;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .ctx button {
    display: flex;
    gap: 12px;
    align-items: baseline;
    justify-content: space-between;
    width: 100%;
    padding: 6px 10px;
    border: none;
    border-radius: var(--halo-radius);
    background: transparent;
    color: var(--halo-text-main);
    text-align: left;
    font-size: 13px;
  }

  .ctx button:hover:not([disabled]) {
    background: var(--halo-accent-soft);
    color: var(--halo-accent);
  }

  .ctx button[disabled] {
    color: var(--halo-text-muted);
    cursor: default;
  }

  .ctx button.danger:not([disabled]) {
    color: var(--halo-error);
  }

  .hint {
    color: var(--halo-text-muted);
    font-size: 11px;
  }
</style>
