# Guides

Step by step, for a task; the reference is [configuration](../configuration.md),
[projects and repositories](../projects.md) and [agents.md](../agents.md), and the
[README](../../README.md) has the overview.

- [Changing an env](changing-an-env.md): another repo, for you or the team, a token the
  remote refused, a host, a variable, a folder, the container, each a command.
- [A repository you don't trust](untrusted-repo.md): cloned inside the env with nothing on
  your machine, and what you are asked before anything of it runs.
- [Several repositories in one env](multi-repo.md): from the command line, a team's launchpad,
  or both, and the credentials they need.
- [Headless runs](headless.md): `luoto run` for scripts and schedules, from a report to a pull
  request, and letting GitHub merge it.
- [Azure](azure.md): `az`, terraform and the SDKs on your subscriptions as a managed identity,
  from your `az` login or a service principal, with the tokens outside the env.
- [Cloud APIs](cloud-apis.md): Hetzner, UpCloud, DigitalOcean and Cloudflare for their CLIs
  and terraform, read-only unless the env writes, with the tokens outside the env.
- [Private package feeds](package-feeds.md): `luoto feed add` for Azure DevOps, GitHub
  Packages and self-hosted Gitea, Forgejo and GitLab feeds, with your token outside the env.
- [Environment variables](env-vars.md): plain values, secrets the code reads and tokens it
  never sees, with `luoto var`.
- [Agent settings](agent-settings.md): model and effort, credentials without the prompt,
  commits without AI attribution.
- [Your settings in every env](your-settings.md): shell, prompt, git, terminal workspace
  themes, editors and agents' own settings from one folder, and the keys luoto writes itself.
- [Model servers](model-servers.md): Ollama, LM Studio, MTPLX or any OpenAI- or
  Anthropic-compatible server, on this machine, your network or the internet, beside the
  cloud.
- [Moving an env](moving-envs.md): to the release from a source build, or to another machine,
  with its workspace and home, and what stays behind.
