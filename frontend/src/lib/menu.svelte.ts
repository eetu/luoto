// The app's one context menu, as state. `ContextMenu.svelte` renders it once at the root; every
// surface with verbs for a thing calls `openMenu` and never draws a menu of its own.

/** One line in a menu. A disabled item still renders — greyed, with `hint` saying why. */
export type MenuItem = {
  label: string;
  run: () => void;
  /** A fact: a count, a duration, or the reason this item is grey. */
  hint?: string;
  disabled?: boolean;
  danger?: boolean;
};

export type OpenMenu = {
  x: number;
  y: number;
  title: string;
  items: MenuItem[];
};

class MenuState {
  current = $state<OpenMenu | null>(null);
}

const state = new MenuState();

export function activeMenu(): OpenMenu | null {
  return state.current;
}

export function openMenu(event: MouseEvent, title: string, items: MenuItem[]): void {
  event.preventDefault();
  event.stopPropagation();
  state.current = { x: event.clientX, y: event.clientY, title, items };
}

export function closeMenu(): void {
  state.current = null;
}
