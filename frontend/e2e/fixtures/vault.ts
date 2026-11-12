import type { VaultView } from "../../src/lib/types";

export default {
  "status": {
    "version": "0.4.4",
    "started": "2026-11-12T14:51:04.846862344Z",
    "locked": false,
    "loaded_refs": [
      "op://Dev/claude/token",
      "keyring:luoto/github-pat",
      "op://Old/retired/credential"
    ],
    "envs": [
      {
        "env": "web",
        "bindings": ["anthropic.oauth_token", "github", "custom.billing"],
        "missing": ["op://Dev/billing/key"]
      }
    ]
  },
  "credentials": [
    {
      "env": "web",
      "binding": "anthropic.oauth_token",
      "what": "anthropic oauth_token, for claude",
      "kept": "op://Dev/claude/token",
      "hosts": ["api.anthropic.com"],
      "state": "loaded",
      "change": "luoto agent auth -e web claude"
    },
    {
      "env": "web",
      "binding": "custom.billing",
      "what": "custom credential billing",
      "kept": "op://Dev/billing/key",
      "hosts": ["api.example.com"],
      "state": "missing",
      "change": null
    },
    {
      "env": "web",
      "binding": "github",
      "what": "GitHub token for acme/web",
      "kept": "keyring:luoto/github-pat",
      "hosts": ["api.github.com", "github.com"],
      "state": "loaded",
      "change": "luoto repo auth -e web acme/web"
    }
  ],
  "unused": ["op://Old/retired/credential"],
  "errors": []
} satisfies VaultView;
