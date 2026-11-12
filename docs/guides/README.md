# Guides

Step by step, for a task; the reference is [configuration](../configuration.md),
[projects and repositories](../projects.md) and [agents.md](../agents.md), and the
[README](../../README.md) has the overview.

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
- [Environment variables](env-vars.md): plain values, secrets the code reads and tokens it
  never sees, with `luoto var`.
- [Agent settings](agent-settings.md): model and effort, credentials without the prompt, your
  own settings in every env, commits without AI attribution.
- [Model servers](model-servers.md): Ollama, LM Studio, MTPLX or any OpenAI- or
  Anthropic-compatible server, on this machine, your network or the internet, beside the
  cloud.
- [Moving an env](moving-envs.md): to the release from a source build, or to another machine,
  with its workspace and home, and what stays behind.
