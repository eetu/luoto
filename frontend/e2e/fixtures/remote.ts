import type { EnvRow } from "../../src/lib/types";

// An env whose workspace is cloned from a remote inside it (`luoto init acme/api`): no folder.
export default {
  "branch": "develop",
  "denied_recent": 0,
  "dev": "stopped",
  "dir": null,
  "error": null,
  "gate": "stopped",
  "name": "api",
  "pending": 0,
  "remote": "acme/api",
  "repos": [
    {
      "branch": null,
      "kind": "clone",
      "name": "lib",
      "origin": "project",
      "present": true,
      "source": "acme/lib"
    }
  ]
} satisfies EnvRow;
