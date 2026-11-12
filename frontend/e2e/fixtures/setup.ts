import type { SetupInfo } from "../../src/lib/types";

// A first setup on macOS 26 on Apple silicon: podman installed, Apple's container not.
export default {
  "detection": {
    "os": "macos",
    "arch": "aarch64",
    "distro": null,
    "cpus": 12,
    "runtimes": [
      {
        "name": "podman",
        "version": [6, 1, 4],
        "version_ok": true,
        "reachable": true,
        "detail": "podman (luoto runs envs in its own VM)"
      }
    ],
    "package_manager": "brew",
    "wsl": null
  },
  "recommendation": {
    "summary": "use the installed podman (podman (luoto runs envs in its own VM))",
    "reasons": ["a supported runtime is already installed and running"],
    "install": null,
    "notes": []
  },
  "runtimes": {
    "options": [
      {
        "runtime": "container",
        "label": "Apple's container",
        "description": "every container is a VM of its own",
        "recommended": true,
        "current": false,
        "selected": true,
        "setup": "luoto setup --runtime container"
      },
      {
        "runtime": "podman",
        "label": "podman",
        "description": "every env in luoto's one VM, under gVisor",
        "recommended": false,
        "current": false,
        "selected": false,
        "setup": "luoto setup --runtime podman"
      }
    ],
    "apple": null,
    "apple_need": { "min": "1.7.1", "install": ["brew", "install", "container"] },
    "podman": {
      "summary": "use the installed podman (podman (luoto runs envs in its own VM))",
      "reasons": ["a supported runtime is already installed and running"],
      "install": null,
      "notes": []
    }
  },
  "images_ok": false
} satisfies SetupInfo;
