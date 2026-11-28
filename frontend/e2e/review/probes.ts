import AxeBuilder from "@axe-core/playwright";
import type { Page } from "@playwright/test";

/** One thing a probe found: on what, as `<region> <tag.classes>`, and what it measured. */
export type Found = { probe: string; target: string; detail: string };

/** Everything alike a view had, as one line. */
export type Violation = Found & { count: number };

type Ask = {
  /** Measure the page as it stands. */
  page?: { reducedMotion: boolean };
  /** Judge the element Tab just moved the focus to. */
  focus?: boolean;
  /** Name what these selectors match, as a `Found.target`. */
  name?: string[];
};

type Box = { left: number; top: number; right: number; bottom: number };

/** Runs in the page, so it holds everything it uses. */
const inPage = (ask: Ask): { found: Found[]; names: string[] } => {
  const found: Found[] = [];
  const vw = innerWidth;
  const vh = innerHeight;
  const px = (n: number) => `${Math.round(n)}px`;

  const REGIONS: [string, string][] = [
    ["[role=dialog]", "dialog"],
    ["[role=alertdialog]", "alertdialog"],
    ["[role=menu]", "menu"],
    ["nav.nav", "nav"],
    ["header.top", "top"],
    ["aside.subject", "subject"],
    ["main", "main"],
    ["footer.status", "status"],
  ];
  // Classes that say what state an element is in, not what it is.
  const STATE = ["selected", "active", "on", "off"];
  const own = (el: Element): string => {
    const classes = [...el.classList].filter(
      (c) => !c.startsWith("svelte-") && !c.startsWith("lucide") && !STATE.includes(c),
    );
    const role = el.getAttribute("role");
    return [el.tagName.toLowerCase(), ...classes].join(".") + (role ? `[role=${role}]` : "");
  };
  /** A bare tag says little: it is named with its parent. */
  const named = (el: Element): string =>
    own(el) === el.tagName.toLowerCase() && el.parentElement
      ? `${own(el.parentElement)} > ${own(el)}`
      : own(el);
  const describe = (el: Element): string => {
    for (const [selector, label] of REGIONS) {
      const region = el.closest(selector);
      if (region) return region === el ? label : `${label} ${named(el)}`;
    }
    return named(el);
  };

  const boxOf = (r: DOMRect): Box => ({
    left: r.left,
    top: r.top,
    right: r.right,
    bottom: r.bottom,
  });
  const width = (b: Box) => Math.max(0, b.right - b.left);
  const height = (b: Box) => Math.max(0, b.bottom - b.top);
  const meet = (a: Box, b: Box): Box => ({
    left: Math.max(a.left, b.left),
    top: Math.max(a.top, b.top),
    right: Math.min(a.right, b.right),
    bottom: Math.min(a.bottom, b.bottom),
  });
  const scrolls = (overflow: string) => overflow === "auto" || overflow === "scroll";

  /** What of `box` shows: cut by every ancestor that clips or scrolls, and by the window. */
  const shown = (el: Element, box: Box): Box => {
    const b = { ...box };
    let fixed = getComputedStyle(el).position === "fixed";
    for (let p = el.parentElement; p && !fixed; p = p.parentElement) {
      const cs = getComputedStyle(p);
      const r = p.getBoundingClientRect();
      if (cs.overflowX !== "visible") {
        b.left = Math.max(b.left, r.left);
        b.right = Math.min(b.right, r.right);
      }
      if (cs.overflowY !== "visible") {
        b.top = Math.max(b.top, r.top);
        b.bottom = Math.min(b.bottom, r.bottom);
      }
      fixed = cs.position === "fixed";
    }
    return meet(b, { left: 0, top: 0, right: vw, bottom: vh });
  };

  if (ask.name) {
    const names = ask.name.map((selector) => {
      const el = document.querySelector(selector);
      return el ? describe(el) : selector;
    });
    return { found, names };
  }

  if (ask.focus) {
    const el = document.activeElement;
    if (!(el instanceof HTMLElement) || el === document.body) return { found, names: [] };
    const target = describe(el);
    const modal = document.querySelector("[aria-modal=true]");
    if (modal && !modal.contains(el)) {
      found.push({
        probe: "focus-trap",
        target: describe(modal),
        detail: `Tab left the open dialog for ${target}`,
      });
    }
    const seen = shown(el, boxOf(el.getBoundingClientRect()));
    if (width(seen) === 0 || height(seen) === 0) {
      found.push({ probe: "focus-hidden", target, detail: "Tab focused what is out of view" });
      return { found, names: [] };
    }
    const cs = getComputedStyle(el);
    if (cs.outlineStyle !== "none" && parseFloat(cs.outlineWidth) > 0) return { found, names: [] };
    // No outline: focus has to change how the element looks some other way. A transition
    // would still show the focused look right after the blur.
    const still = document.createElement("style");
    still.textContent = "* { transition: none !important; }";
    document.head.append(still);
    const look = () => {
      const c = getComputedStyle(el);
      return [c.boxShadow, c.borderColor, c.backgroundColor, c.color, c.textDecorationLine].join();
    };
    const focused = look();
    el.blur();
    const blurred = look();
    el.focus();
    still.remove();
    if (focused === blurred) {
      found.push({ probe: "focus-ring", target, detail: "focused by Tab, it looks the same" });
    }
    return { found, names: [] };
  }

  const reducedMotion = ask.page?.reducedMotion ?? false;
  // Under a modal dialog the page is out of reach: only the dialog is judged.
  const modal = document.querySelector("[aria-modal=true]");
  const scope = modal ?? document.body;

  // The page, and what scrolls sideways in it.
  const root = document.scrollingElement ?? document.documentElement;
  if (root.scrollWidth > vw + 1) {
    found.push({
      probe: "overflow",
      target: "page",
      detail: `${px(root.scrollWidth)} of content in a ${px(vw)} window`,
    });
  }
  for (const el of scope.querySelectorAll("*")) {
    if (el.scrollWidth <= el.clientWidth + 1 || el.clientWidth === 0) continue;
    if (!scrolls(getComputedStyle(el).overflowX)) continue;
    found.push({
      probe: "hscroll",
      target: describe(el),
      detail: `scrolls sideways: ${px(el.scrollWidth)} in ${px(el.clientWidth)}`,
    });
  }

  // Text cut off by a box that doesn't scroll.
  const range = document.createRange();
  const walker = document.createTreeWalker(scope, NodeFilter.SHOW_TEXT);
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    const el = node.parentElement;
    const text = node.textContent?.trim();
    if (!el || !text || el.closest("script, style, title")) continue;
    if (getComputedStyle(el).visibility !== "visible") continue;
    range.selectNodeContents(node);
    const rects = [...range.getClientRects()].filter((r) => r.width > 0 && r.height > 0);
    if (rects.length === 0) continue;
    const box = rects.map(boxOf).reduce((a, b) => ({
      left: Math.min(a.left, b.left),
      top: Math.min(a.top, b.top),
      right: Math.max(a.right, b.right),
      bottom: Math.max(a.bottom, b.bottom),
    }));
    let cut = 0;
    let by: Element | null = null;
    let ellipsis = false;
    let x = true;
    let y = true;
    for (let p: Element | null = el; p && (x || y); p = p.parentElement) {
      const cs = getComputedStyle(p);
      const r = p.getBoundingClientRect();
      if (x && cs.overflowX !== "visible") {
        const over = Math.max(box.right - r.right, r.left - box.left);
        if (scrolls(cs.overflowX)) x = false;
        else if (over > 1 && over > cut) {
          cut = over;
          by = p;
          ellipsis = cs.textOverflow === "ellipsis";
        }
      }
      if (y && cs.overflowY !== "visible") {
        const over = Math.max(box.bottom - r.bottom, r.top - box.top);
        if (scrolls(cs.overflowY)) y = false;
        else if (over > 1 && over > cut) {
          cut = over;
          by = p;
          ellipsis = cs.webkitLineClamp !== "none" && cs.webkitLineClamp !== "";
        }
      }
      if (cs.position === "fixed") break;
    }
    if (!by || el.closest("[title]")?.getAttribute("title")) continue;
    found.push({
      probe: ellipsis ? "truncated" : "clipped",
      target: describe(el),
      detail: `"${text.slice(0, 40)}" loses ${px(cut)} to ${describe(by)}${ellipsis ? ", with an ellipsis and no title" : ""}`,
    });
  }

  // What can be clicked or focused, and shows. A checkbox or radio in a label is the label.
  const INTERACTIVE =
    "a[href], button, input:not([type=hidden]), select, textarea, summary, [role=button], " +
    "[role=switch], [role=menuitem], [role=tab], [role=checkbox], [role=radio], " +
    "[tabindex]:not([tabindex='-1'])";
  const menu = document.querySelector("[role=menu]")?.getBoundingClientRect();
  const targets = [...document.querySelectorAll<HTMLElement>(INTERACTIVE)]
    .filter((el) => !el.matches(":disabled, [aria-disabled=true]"))
    .filter((el) => !modal || modal.contains(el))
    .map((el) => {
      const hit =
        (el.matches("input[type=checkbox], input[type=radio]") && el.closest("label")) || el;
      const box = boxOf(hit.getBoundingClientRect());
      return { el, box, seen: shown(hit, box) };
    })
    .filter((t) => width(t.seen) > 0 && height(t.seen) > 0)
    // Under the open menu, nothing can be clicked.
    .filter((t) => {
      if (!menu || t.el.closest("[role=menu]")) return true;
      const under = meet(t.seen, boxOf(menu));
      return width(under) === 0 || height(under) === 0;
    });
  const apart = (a: HTMLElement, b: HTMLElement) => !a.contains(b) && !b.contains(a);

  // WCAG 2.5.8: a target under 24px passes while a 24px square on its centre meets no other.
  for (const t of targets) {
    const w = width(t.box);
    const h = height(t.box);
    if (w >= 24 && h >= 24) continue;
    if (t.el.matches("a") && getComputedStyle(t.el).display.startsWith("inline")) continue;
    const cx = (t.box.left + t.box.right) / 2;
    const cy = (t.box.top + t.box.bottom) / 2;
    const square = { left: cx - 12, top: cy - 12, right: cx + 12, bottom: cy + 12 };
    const near = targets.find((u) => {
      if (u === t || !apart(t.el, u.el)) return false;
      const shared = meet(square, u.seen);
      return width(shared) > 0 && height(shared) > 0;
    });
    if (near) {
      found.push({
        probe: "tap",
        target: describe(t.el),
        detail: `${px(w)}×${px(h)}, within 24px of ${describe(near.el)}`,
      });
    }
  }

  for (const [i, a] of targets.entries()) {
    for (const b of targets.slice(i + 1)) {
      if (!apart(a.el, b.el)) continue;
      const shared = meet(a.seen, b.seen);
      if (width(shared) <= 2 || height(shared) <= 2) continue;
      found.push({
        probe: "overlap",
        target: [describe(a.el), describe(b.el)].sort().join(" × "),
        detail: `${px(width(shared))}×${px(height(shared))} of each lies on the other`,
      });
    }
  }

  for (const el of document.querySelectorAll("[role=dialog], [role=menu]")) {
    const r = el.getBoundingClientRect();
    const out = Math.max(-r.left, -r.top, r.right - vw, r.bottom - vh);
    if (out > 1) {
      found.push({
        probe: "offscreen",
        target: describe(el),
        detail: `${px(out)} of it is outside the ${px(vw)}×${px(vh)} window`,
      });
    }
  }

  if (reducedMotion) {
    for (const animation of document.getAnimations()) {
      const effect = animation.effect;
      if (animation.playState !== "running" || !(effect instanceof KeyframeEffect)) continue;
      if (!effect.target || Number(effect.getComputedTiming().duration) === 0) continue;
      found.push({
        probe: "motion",
        target: describe(effect.target),
        detail: "animates though reduced motion is asked for",
      });
    }
  }

  // Sandbox text that became markup: the hostile scenario's strings set these.
  if ("__pwn" in window || document.querySelector("[data-pwn]")) {
    found.push({ probe: "markup", target: "page", detail: "sandbox text was rendered as HTML" });
  }

  return { found, names: [] };
};

const MODAL = "[aria-modal=true]";
const AXE_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

/** Layout, text and accessibility findings for the page as it stands. */
export async function inspect(
  page: Page,
  { reducedMotion, forcedColors }: { reducedMotion: boolean; forcedColors: boolean },
): Promise<Found[]> {
  const { found } = await page.evaluate(inPage, { page: { reducedMotion } });
  // `target-size` is the tap probe above, which names the neighbour. Under forced colors the
  // browser paints system colours over the authored ones, which are the ones axe reads.
  const axe = new AxeBuilder({ page })
    .withTags(AXE_TAGS)
    .disableRules(["target-size", ...(forcedColors ? ["color-contrast"] : [])]);
  if ((await page.locator(MODAL).count()) > 0) axe.include(MODAL);
  const nodes = (await axe.analyze()).violations.flatMap((v) =>
    v.nodes.map((n) => ({
      probe: `axe:${v.id}`,
      selector: String(n.target.at(-1)),
      detail: n.any[0]?.message ?? v.help,
      color: (n.any[0]?.data as { fgColor?: string } | undefined)?.fgColor,
    })),
  );
  const { names } = await page.evaluate(inPage, { name: nodes.map((n) => n.selector) });
  return [
    ...found,
    // Low contrast is a colour's, whatever carries it: one finding per text colour.
    ...nodes.map((n, i) =>
      n.color
        ? { probe: n.probe, target: `text ${n.color}`, detail: `${names[i]}: ${n.detail}` }
        : { probe: n.probe, target: names[i], detail: n.detail },
    ),
  ];
}

/**
 * Tab through what the view offers, then Escape out of a dialog or menu it left open. A modal
 * dialog gets enough presses to walk out of it, if it lets the focus out.
 */
export async function keyboard(page: Page): Promise<Found[]> {
  const found: Found[] = [];
  const tabs = (await page.locator(MODAL).count()) > 0 ? 60 : 12;
  for (let i = 0; i < tabs; i++) {
    await page.keyboard.press("Tab");
    found.push(...(await page.evaluate(inPage, { focus: true })).found);
  }
  const floating = page.locator("[role=dialog], [role=menu]");
  if ((await floating.count()) > 0) {
    const target = (await floating.first().getAttribute("role")) ?? "dialog";
    await page.keyboard.press("Escape");
    await floating
      .first()
      .waitFor({ state: "detached", timeout: 1000 })
      .catch(() => found.push({ probe: "esc", target, detail: "Escape left it open" }));
  }
  return found;
}

/** One line per probe and target, with how many there were. */
export function gather(found: Found[]): Violation[] {
  const by = new Map<string, Violation>();
  for (const f of found) {
    const key = `${f.probe}\n${f.target}`;
    const had = by.get(key);
    if (had) had.count += 1;
    else by.set(key, { ...f, count: 1 });
  }
  return [...by.values()];
}
