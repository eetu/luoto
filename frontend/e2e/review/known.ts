/**
 * A problem the probes find in the UI as it is: the review skips it, and fails on any other.
 * `target` is a finding's own (`<region> <tag.classes>`); `where` narrows it to the renders
 * whose `<scenario>/<view>/<setting>` it matches. Fixing one means deleting its line.
 */
export type Known = { probe: string; target: string | RegExp; where?: RegExp; reason: string };

const NARROW = /\/(400-(light|dark)|zoom200)$/;

export const KNOWN: Known[] = [
  // What can't be reached
  {
    probe: "unreachable",
    target: "host",
    where: /^crowded\//,
    reason:
      "request cards don't scroll: 50 fill the surface, and the egress table can't be reached",
  },
  {
    probe: "unreachable",
    target: "host",
    where: /^(hostile|states)\/host\/(400-|768-|zoom200)/,
    reason: "under 1000px the bar and the request cards fill the surface: no egress row shows",
  },
  {
    probe: "clipped",
    target: /^main (button\.open > span|span > b|span\.muted)$/,
    reason: "request cards past the surface's height are cut off, not scrolled",
  },
  {
    probe: "clipped",
    target:
      /^main (button\.btn|div\.seg\[role=group\] > button|div\.tabs > h1|label\.(all|toggle))$/,
    where: NARROW,
    reason:
      "at 400px and 200% zoom the surface's bar is cut off, and a focused card scrolls it away",
  },
  {
    probe: "clipped",
    target: "main div.seg[role=group] > button",
    where: /^hostile\//,
    reason: "a long env name squeezes the egress/rules switch until its labels are cut",
  },
  {
    probe: "hscroll",
    target: "subject",
    reason: "an unbroken sandbox string widens the subject panel: its controls scroll out sideways",
  },
  {
    probe: "hscroll",
    target: "dialog div.halo-dialog.halo-card[role=dialog] > div",
    reason: "an unbroken luoto.toml line makes the new-env dialog's body scroll sideways",
  },
  {
    probe: "hscroll",
    target: "main div.table-wrap.cards",
    reason: "a 253-character host widens the rule cards past the surface",
  },
  {
    probe: "hscroll",
    target: "main div.table-wrap",
    reason: "tables scroll sideways in their box: all under 1000px, the vault's on any long ref",
  },
  {
    probe: "hscroll",
    target: "subject pre.needs",
    reason: "a project's credential snippet scrolls sideways in its box",
  },

  // Keyboard and names
  {
    probe: "focus-trap",
    target: "dialog",
    reason: "the Modal doesn't keep Tab inside: focus walks into the page behind the veil",
  },
  {
    probe: "axe:scrollable-region-focusable",
    target: /^(main div\.table-wrap(\.cards)?|subject pre\.needs)$/,
    reason: "a scrolling box with nothing focusable in it can't be scrolled from the keyboard",
  },
  {
    probe: "axe:aria-required-parent",
    target: "main div.request.halo-card[role=listitem]",
    reason: "request cards are list items with no list around them",
  },

  // Contrast, under WCAG AA's 4.5:1
  {
    probe: "axe:color-contrast",
    target: "text #ff6347",
    reason: "light's error colour as text (warnings, the status bar, blocked): 2.2 to 2.9:1",
  },
  {
    probe: "axe:color-contrast",
    target: "text #f78f08",
    reason: "the accent as text in light (links, the active segment, chips): 1.9 to 2.4:1",
  },
  {
    probe: "axe:color-contrast",
    target: "text #767676",
    reason: "light's muted text on anything but white: 4.0 to 4.4:1",
  },
  {
    probe: "axe:color-contrast",
    target: "text #9c9c9c",
    reason: "dark's muted text on a selected row's accent fill: 3.9:1",
  },

  // Targets under 24px with a neighbour inside 24px
  {
    probe: "tap",
    target: /^main button\.icon(\.revoke)?$/,
    reason: "a rule's edit and revoke buttons are 23×19px, side by side",
  },
  {
    probe: "tap",
    target: /^subject (a\.link|summary\.small\.muted)$/,
    reason: "the ports' links and their disclosure are 14px lines, stacked",
  },
  {
    probe: "tap",
    target: "subject button.attempt",
    reason: "a host's attempts are 23px rows, stacked",
  },
  {
    probe: "tap",
    target: "dialog button.option",
    reason: "the new-env dialog's preset and agent chips are 23px tall, a row apart",
  },
  {
    probe: "tap",
    target: "subject div.seg[role=group] > button",
    reason:
      "segmented buttons are 23px tall: at 200% zoom the panel's meet the env list's last row",
  },
];

/** The known problem a finding is, if any. */
export const knownAs = (
  found: { probe: string; target: string },
  where: string,
): Known | undefined =>
  KNOWN.find(
    (k) =>
      k.probe === found.probe &&
      (typeof k.target === "string" ? k.target === found.target : k.target.test(found.target)) &&
      (!k.where || k.where.test(where)),
  );
