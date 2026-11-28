import { rmSync } from "node:fs";

import { test as setup } from "@playwright/test";

import { OUT } from "./sheet.ts";

setup("clear the last review", () => {
  rmSync(OUT, { recursive: true, force: true });
});
