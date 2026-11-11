import type { HostSummary } from "../../src/lib/types";

export default [
  {
    "host": "example.com",
    "allowed": 0,
    "opened": 0,
    "denied": 1,
    "muted": 0,
    "dns_only": false,
    "methods": ["GET"],
    "ports": [443],
    "intakes": ["proxy"],
    "top_paths": [["/", 1]],
    "last_reason": "no_rule",
    "last_message": "no rule allows example.com",
    "last_rule": null,
    "bytes_up": 0,
    "bytes_down": 0,
    "first_seen": "2026-11-03T20:22:03.402085484Z",
    "last_seen": "2026-11-03T20:22:03.402085484Z",
    "wants_write": false,
    "tls_rejected": false
  },
  {
    "host": "deb.debian.org",
    "allowed": 1,
    "opened": 0,
    "denied": 0,
    "muted": 0,
    "dns_only": false,
    "methods": ["GET"],
    "ports": [443],
    "intakes": ["proxy"],
    "top_paths": [["/debian/", 1]],
    "last_reason": null,
    "last_message": null,
    "last_rule": "debian-0",
    "bytes_up": 0,
    "bytes_down": 6153,
    "first_seen": "2026-11-03T20:22:03.710254588Z",
    "last_seen": "2026-11-03T20:22:03.710254588Z",
    "wants_write": false,
    "tls_rejected": false
  }
] satisfies HostSummary[];
