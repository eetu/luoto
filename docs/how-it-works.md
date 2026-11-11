# How it works

The overview is the [README](../README.md); step by step, the [guides](guides/README.md).

```mermaid
%%{init: {"layout": "dagre", "theme": "base", "fontFamily": "Inter, system-ui, sans-serif", "flowchart": {"htmlLabels": false, "padding": 16, "wrappingWidth": 240}, "themeVariables": {"fontFamily": "Inter, system-ui, sans-serif", "fontSize": "14px", "background": "#f0f0f0", "mainBkg": "#ffffff", "primaryColor": "#ffffff", "primaryTextColor": "#525252", "primaryBorderColor": "#d3d3d3", "secondaryColor": "#fbfbfb", "secondaryTextColor": "#525252", "secondaryBorderColor": "#d3d3d3", "tertiaryColor": "#fbfbfb", "tertiaryTextColor": "#525252", "tertiaryBorderColor": "#d3d3d3", "textColor": "#525252", "titleColor": "#525252", "lineColor": "#767676", "nodeBorder": "#d3d3d3", "nodeTextColor": "#525252", "clusterBkg": "#fbfbfb", "clusterBorder": "#d3d3d3", "edgeLabelBackground": "#f0f0f0", "noteBkgColor": "#ffedcf", "noteTextColor": "#1a1a1a", "noteBorderColor": "#ffedcf"}}}%%
flowchart TB
  subgraph luoto[" "]
    direction TB
    subgraph host["your machine (trusted)"]
      editor("editor and browser")
      cli("luoto CLI and UI<br/>secrets: 1Password,<br/>keyring, OpenBao")
    end
    subgraph vm["luoto's VM (no host folders)"]
      subgraph env["one env per project"]
        dev("dev container<br/>gVisor, no route out<br/>tools, deps, agents")
        gate("gate<br/>policy, inspection<br/>adds credentials")
      end
      vault("vault<br/>secrets in<br/>memory only")
    end
    net("allowed hosts<br/>registries, APIs,<br/>your repo")
  end

  editor -- "SSH and ports<br/>over exec" --> dev
  cli -. "secrets<br/>via stdin" .-> vault
  cli -- "policy and events" --> gate
  dev -- "every request" --> gate
  vault -. "credentials" .-> gate
  gate -- "allowed only" --> net

  classDef halo-accent fill:#f78f08,stroke:#f78f08,color:#1a1a1a
  classDef canvas fill:#f0f0f0,stroke:#f0f0f0
  class gate halo-accent
  class luoto canvas
```

- **Default deny.** The sandbox has no route out. HTTP(S) leaves only through the env's gate,
  which applies per-host, per-method, per-path rules; read-only is enforced (a `PUT` to a
  registry you allowed for reads is refused). The other ways out pass through uninspected:
  tunnels you grant (`luoto allow --tunnel`) and git over SSH to the hosts an SSH credential
  names.
- **Every attempt is visible.** The UI and `luoto egress` show each host the sandbox tried to
  reach (allowed, blocked, or only looked up) with a one-click scoped allow.
- **Agents know where they are.** Claude Code, OpenCode, Codex, Copilot CLI and Antigravity
  CLI get a briefing and an MCP server: they can see the policy and ask you for access instead
  of guessing.

`SECURITY.md` has the threat model, including what luoto does not stop.

## Platforms

| host                                  | runtimes                                               | boundary                                                                                                                                                                                      |
| ------------------------------------- | ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| macOS                                 | podman (recommended), Docker Desktop, OrbStack, Colima | podman: luoto's own VM, with none of your folders mounted, and gVisor. Docker: its VM, which shares your folders, and plain containers                                                        |
| Windows (not yet verified end to end) | podman (Hyper-V or WSL2), Docker Desktop               | as on macOS; a WSL2 VM can still see `C:\` (`luoto doctor` reports it), so prefer Hyper-V                                                                                                     |
| Linux                                 | rootless podman (recommended), Docker                  | no VM. podman: gVisor when `runsc` is installed (`luoto setup` finds it). Docker: plain containers, or gVisor registered with Docker and `oci_runtime = "runsc"` under an env's `[resources]` |

With podman, dev containers run on [gVisor](https://gvisor.dev), a user-space kernel (on Linux
once `runsc` is installed). It costs time wherever a tool touches many files. A Rust + Vite
monorepo in luoto's VM (6 CPUs):

| step                                       | gVisor | container |
| ------------------------------------------ | ------ | --------- |
| `yarn install`                             | 4.6 s  | 3.1 s     |
| `vite build`                               | 2.9 s  | 2.0 s     |
| `cargo build` (debug, after `cargo clean`) | 36 s   | 21 s      |

gVisor is the default, and the right choice for anything that runs code you haven't read:
new dependencies, unfamiliar repos, agents in yolo mode. `isolation = "container"` in an env's
config (or `luoto init --isolation container`) suits an env whose day is spent in native
builds; it shares the VM's kernel, so an exploit from inside reaches the VM
([SECURITY.md](../SECURITY.md#residual-risks)).

Podman on macOS runs one VM at a time, so luoto's replaces your default podman machine while
you use luoto: `luoto up` asks before switching.
