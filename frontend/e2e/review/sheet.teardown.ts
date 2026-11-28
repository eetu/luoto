import { test as teardown } from "@playwright/test";

import { writeSheet } from "./sheet.ts";

teardown("write the contact sheet", () => {
  const { path, renders, fresh } = writeSheet();
  console.log(`\ncontact sheet: ${path} (${renders} renders, ${fresh} new findings)`);
});
