import type { Overview } from "../../src/lib/types";

export default {
  "envs": [
    {
      "denied_recent": 1,
      "dev": "running",
      "dir": "/home/me/dev/web",
      "error": null,
      "gate": "running",
      "name": "web",
      "pending": 0,
      "repos": []
    }
  ],
  "desktop_notifications": false,
  "instance": "luoto",
  "runtime": "podman version 6.1.4",
  "vault": {
    "envs": [{ "bindings": [], "env": "web", "missing": [] }],
    "loaded_refs": [],
    "locked": true,
    "started": "2026-11-03T14:51:04.846862344Z",
    "version": "0.1.0"
  }
} satisfies Overview;
