import type { EnvDisk } from "../../src/lib/types";

export default {
  "web": {
    "parts": [
      { "what": "workspace", "bytes": 356200000 },
      { "what": "home", "bytes": 2104000000 },
      { "what": "tools", "bytes": 11600000 },
      { "what": "gate", "bytes": 1940000 },
      { "what": "containers", "bytes": 482712290 }
    ],
    "total": 2956452290
  }
} satisfies Record<string, EnvDisk>;
