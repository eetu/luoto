// Browser notifications for access requests, so one doesn't wait unseen while this tab is in
// the background. The browser is asked for permission only from the user's click; turning
// them off here is remembered in this browser. Nothing the sandbox wrote goes into one.

import { say, selectEnv } from "$lib/stores/app.svelte";
import type { EnvRow } from "$lib/types";

const OFF_KEY = "luoto:notifications-off";

const supported = (): boolean => typeof Notification !== "undefined";

const readOff = (): boolean => {
  try {
    return localStorage.getItem(OFF_KEY) === "1";
  } catch {
    return false;
  }
};

const writeOff = (off: boolean): void => {
  try {
    if (off) localStorage.setItem(OFF_KEY, "1");
    else localStorage.removeItem(OFF_KEY);
  } catch {
    /* storage unavailable: the choice lasts until the page reloads */
  }
};

class NotifyState {
  permission = $state<NotificationPermission | "unsupported">(
    supported() ? Notification.permission : "unsupported",
  );
  off = $state(readOff());
  on = $derived(this.permission === "granted" && !this.off);
}

export const notifications = new NotifyState();

/** Turn browser notifications off, or on: from this click the browser may ask the user. */
export const toggleNotifications = async (): Promise<void> => {
  if (notifications.on) {
    notifications.off = true;
    writeOff(true);
    say("browser notifications off");
    return;
  }
  if (!supported()) {
    say("this browser has no notifications", true);
    return;
  }
  if (Notification.permission === "default") await Notification.requestPermission();
  notifications.permission = Notification.permission;
  if (notifications.permission !== "granted") {
    say("the browser blocks notifications for this page: allow them in its site settings", true);
    return;
  }
  notifications.off = false;
  writeOff(false);
  say("browser notifications on: a new access request shows one while this tab is out of sight");
};

// Requests pending per env at the last look; the first look only records them.
let lastPending: Record<string, number> | null = null;

/** Notify of each env with more requests pending than at the last look, unless the desktop
 * already does. */
export const noticeRequests = (envs: EnvRow[], instance: string, desktop: boolean): void => {
  const before = lastPending;
  lastPending = Object.fromEntries(envs.map((e) => [e.name, e.pending]));
  if (!before || !notifications.on || desktop) return;
  // In sight, the request shows on the page.
  if (document.visibilityState === "visible" && document.hasFocus()) return;
  for (const env of envs) {
    if (env.pending <= (before[env.name] ?? 0)) continue;
    const n = new Notification(`${instance}: ${env.name} asks for access`, {
      body:
        env.pending === 1
          ? "an access request waits for you"
          : `${env.pending} access requests wait for you`,
      tag: `requests-${env.name}`,
    });
    n.onclick = () => {
      window.focus();
      n.close();
      void selectEnv(env.name);
    };
  }
};
