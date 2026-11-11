# Model servers

An agent can use a model server of your own beside its cloud provider: one on this machine
(Ollama, LM Studio, MTPLX, llama.cpp, vLLM, LiteLLM), on your network, or a hosted one on the
internet. Anything that serves an OpenAI- or Anthropic-compatible API works; luoto doesn't need
to know which program it is.

## Setting one up

`luoto agent auth <agent>` (or the questions `up` asks for an agent without a credential)
offers "A model server" beside the cloud's ways in. It looks for servers answering on this
machine's usual ports (Ollama 11434, LM Studio 1234, MTPLX and vLLM 8000, llama.cpp 8080,
LiteLLM 4000) and lists them with what they serve; "Another address" takes any other, one not
running yet included. A server that answers lists its models to pick from; one that doesn't
gets the model typed. Your network is never scanned.

What it writes, in the env's own file:

```toml
[model_servers.mtplx]
url = "http://localhost:8000"   # as this machine reaches it; a trailing /v1 is fine
api = ["anthropic", "openai"]   # what it serves
# model = "qwen3-coder"         # the model agents use there unless their own `model` says
# token = "keyring:luoto/model_server.mtplx"   # any secret reference; none for a keyless one
# header = "x-api-key"          # where the token goes; default `authorization: Bearer`
# private = true                # its host name is on a private network

[agents.claude]
model_server = "mtplx"          # what it starts on; without it, its cloud provider
model = "qwen3-coder"
```

A team's `luoto.toml` can't hold either: which server an agent uses is each developer's own.

## Cloud and server side by side

The env can keep its cloud credential and have servers too. The first menu of `luoto agent
auth` says what the agent starts on; the rest stays. Where a session can switch depends on the
agent:

| agent | starts on | switching |
| --- | --- | --- |
| OpenCode | `model_server`, else its cloud default | in the session: `/models` lists the servers' models beside the cloud's |
| Codex | `model_server` (its default profile) | per start: `codex --profile <server>`, `codex --profile cloud` |
| Claude Code | `model_server`, else Anthropic | none: one endpoint a session; `luoto agent auth` changes it |

## What the gate allows

Only the server's exact host and port, and only the model endpoints of the APIs it serves:
`/v1/models`, Anthropic's `/v1/messages`, OpenAI's chat, completions, responses and
embeddings. A server's own API (Ollama's model pulls and deletes, LM Studio's downloads) stays
closed. The gate adds the token, and the sandbox holds a placeholder. A first token can take
minutes while a model loads, so the gate waits up to 30 minutes on the server.

- **This machine:** the sandbox reaches it as `host.docker.internal`. The token may go over
  plain HTTP, since the request never leaves the machine. On Linux the server must listen on
  this machine's address, not only on 127.0.0.1.
- **Your network:** a private address, or a host name with `private = true`. A token goes only
  over HTTPS.
- **The internet:** HTTPS with a token, as a cloud provider is.

`up`, `luoto edit` and `luoto agent auth` refuse a config that can't work: an agent naming a
server the env lacks, a server without the API the agent speaks, no model, a token over plain
HTTP off this machine, two servers on this machine with a token.

## What it costs

A server on this machine runs with your privileges, outside luoto's VM: code in the env can
reach its model API, and with it the server's request parsing. Sandboxing it and keeping it up
to date is yours. A server that forwards to a cloud service (Ollama's `:cloud` models) sends
the prompts there, which luoto can't tell from the request.
