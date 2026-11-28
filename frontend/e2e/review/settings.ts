import type { PlaywrightTestOptions } from "@playwright/test";

export type Setting = {
  name: string;
  about: string;
  use: Pick<
    PlaywrightTestOptions,
    | "viewport"
    | "colorScheme"
    | "reducedMotion"
    | "forcedColors"
    | "deviceScaleFactor"
    | "locale"
    | "timezoneId"
  >;
};

const DESKTOP = { width: 1280, height: 800 };

// Every scenario renders under each of these: the widths in light, the narrowest and the
// desktop one in dark too, then one setting at a time on the desktop window.
export const SETTINGS: Setting[] = [
  {
    name: "400-light",
    about: "phone, light",
    use: { viewport: { width: 400, height: 800 }, colorScheme: "light" },
  },
  {
    name: "400-dark",
    about: "phone, dark",
    use: { viewport: { width: 400, height: 800 }, colorScheme: "dark" },
  },
  {
    name: "768-light",
    about: "tablet, light",
    use: { viewport: { width: 768, height: 1024 }, colorScheme: "light" },
  },
  { name: "1280-light", about: "desktop, light", use: { viewport: DESKTOP, colorScheme: "light" } },
  { name: "1280-dark", about: "desktop, dark", use: { viewport: DESKTOP, colorScheme: "dark" } },
  {
    name: "1920-dark",
    about: "wide, dark",
    use: { viewport: { width: 1920, height: 1080 }, colorScheme: "dark" },
  },
  {
    name: "motion",
    about: "reduced motion",
    use: { viewport: DESKTOP, colorScheme: "light", reducedMotion: "reduce" },
  },
  {
    name: "forced",
    about: "forced colors",
    use: { viewport: DESKTOP, colorScheme: "dark", forcedColors: "active" },
  },
  {
    // The desktop window at 200% browser zoom: half its CSS pixels, twice the density. The UI
    // sizes its text in px, which a larger default font size in the browser leaves as it is.
    name: "zoom200",
    about: "200% zoom",
    use: { viewport: { width: 640, height: 400 }, deviceScaleFactor: 2, colorScheme: "light" },
  },
  {
    name: "locale",
    about: "ar-EG, Auckland",
    use: {
      viewport: DESKTOP,
      colorScheme: "light",
      locale: "ar-EG",
      timezoneId: "Pacific/Auckland",
    },
  },
];
