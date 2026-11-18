import type { SetupInfo } from "../../src/lib/types";

// A first setup on macOS 26 on Apple silicon: podman installed, Apple's container and Docker
// not.
export default {
  detection: {
    os: "macos",
    arch: "aarch64",
    distro: null,
    cpus: 12,
    runtimes: [
      {
        name: "podman",
        version: [6, 1, 4],
        version_ok: true,
        reachable: true,
        detail: "podman (luoto runs envs in its own VM)",
      },
    ],
    wsl: null,
  },
  runtimes: [
    {
      runtime: "container",
      label: "Apple's container",
      description: "every container is a VM of its own",
      min: "1.7.1",
      url: "https://github.com/apple/container/releases",
      status: "not installed",
      ready: false,
      current: false,
      selected: false,
      setup: "luoto setup --runtime container",
    },
    {
      runtime: "podman",
      label: "podman",
      description: "every env in luoto's one VM, under gVisor",
      min: "5.2.0",
      url: "https://podman.io/docs/installation",
      status: "6.1.4",
      ready: true,
      current: false,
      selected: true,
      setup: "luoto setup --runtime podman",
    },
    {
      runtime: "docker",
      label: "Docker",
      description: "containers in the Docker engine's VM; gVisor only where registered with it",
      min: "28.0.0",
      url: "https://docs.docker.com/engine/install/",
      status: "not installed",
      ready: false,
      current: false,
      selected: false,
      setup: "luoto setup --runtime docker",
    },
  ],
  images_ok: false,
} satisfies SetupInfo;
