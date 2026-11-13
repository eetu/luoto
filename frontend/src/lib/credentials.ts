// An env's credentials, wherever they are listed: the vault view and the env panel open one
// menu, and an env without any shows the commands that add them.

import { openMenu } from "$lib/menu.svelte";
import { app, copyText, selectEnv } from "$lib/stores/app.svelte";
import type { Credential, EnvRow } from "$lib/types";

export const credentialMenu = (e: MouseEvent, c: Credential): void => {
  const shown = app.view === "env" && app.env === c.env && app.subject.kind === "env";
  openMenu(e, `${c.env}: ${c.binding}`, [
    {
      label: "Copy change command",
      run: () => c.change && copyText(c.change),
      disabled: !c.change,
      hint: c.change ? undefined : "only in the env's own file",
    },
    { label: "Copy where it is kept", run: () => copyText(c.kept) },
    {
      label: `Show ${c.env}'s egress`,
      run: () => void selectEnv(c.env),
      disabled: shown,
      hint: shown ? "shown" : undefined,
    },
  ]);
};

/**
 * The commands that add an env's credentials: an agent's (named by the user), and a token for
 * each remote it clones, by the name `luoto repo auth` takes.
 */
export const authCommands = (env: string, row?: EnvRow): string[] => {
  const remotes = [
    ...(row?.remote ? [row.remote] : []),
    ...(row?.repos ?? []).filter((r) => r.kind === "clone").map((r) => r.source),
  ];
  return [
    `luoto agent auth -e ${env} <agent>`,
    ...(remotes.length
      ? remotes.map((r) => `luoto repo auth -e ${env} ${r}`)
      : [`luoto repo auth -e ${env} <owner/repo>`]),
  ];
};
