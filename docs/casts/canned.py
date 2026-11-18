"""A stand-in model server for recording casts: Anthropic's Messages API with canned replies.

Agents in a cast's env reach it as a model server (`[model_servers.cast]`), so a recording
needs no account, costs nothing and plays the same every time. Standard library only.

    python3 canned.py [port]   # default 18000
"""

import json
import os
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MODEL = "claude-sonnet-4-5"


# The checkout whose change the hello cast makes: the agent writes these files as they are there.
SOURCE = Path(os.environ.get("LUOTO_CAST_SRC") or Path(__file__).resolve().parents[2])
SPLASH = "cli/src/splash.rs"
SETUP = "cli/src/setup.rs"


def read(path):
    return ("Read", {"file_path": f"/workspace/{path}"})


def write(path):
    """Write `path` as the checkout has it, read when the step is sent."""
    return (
        "Write",
        lambda: {"file_path": f"/workspace/{path}", "content": (SOURCE / path).read_text()},
    )


# A flow is a real change, made through the agent's own tools: each step is what the agent
# says and the tools it calls then, and answers the results of the step before it. A prompt
# gets the first flow whose words it has all of.
FLOWS = [
    # luoto in an env of its own clone, whose splash draws nothing (setup.sh): the splash of
    # `luoto setup`, then its tests.
    (
        ("splash", "luoto setup"),
        [
            (
                "I'll read where setup calls the splash, and what is there now.",
                [read(SETUP), read(SPLASH)],
            ),
            (
                "The island as pixels, two to a row of text: the palm grows, the sea spreads, "
                "the sun rises, and setup's lines come up under it.",
                [write(SPLASH)],
            ),
            (
                "Its tests.",
                [("Bash", {"command": "cargo test -p luoto splash", "description": "Run the tests"})],
            ),
            (
                "`luoto setup` now opens with the island, drawn once while it looks at the "
                "machine. Still under NO_COLOR, ASCII without UTF-8, nothing when piped. Its "
                "tests pass.",
                [],
            ),
        ],
    ),
    # A virtual workspace: a route for the api repo, beside the app.
    (
        ("health",),
        [
            ("I'll look at the API's routes.", [read("api/app.py")]),
            (
                "Adding a `/health` route.",
                [
                    (
                        "Edit",
                        {
                            "file_path": "/workspace/api/app.py",
                            "old_string": "def route(path):\n",
                            "new_string": (
                                "def route(path):\n"
                                '    if path == "/health":\n'
                                '        return 200, "ok\\n"\n'
                            ),
                        },
                    )
                ],
            ),
            (
                "Added a `/health` route to `api/app.py` that answers `ok`. The API reads its "
                "routes on every request, so it answers at once, no restart.",
                [],
            ),
        ],
    ),
]

# The reply to a prompt that mentions the key, else the default. Kept short: a cast shows
# the flow, not the model.
REPLIES = {
    "app": (
        "The app calls the API at `/workspace/api`. Both repos sit side by side in this "
        "workspace, so I can change them together and commit each from its own folder."
    ),
}
DEFAULT = "Done. Everything I ran stayed in the sandbox, behind luoto's gate."


def last_user(body):
    """The last user message's content blocks."""
    for m in reversed(body.get("messages", [])):
        if m.get("role") == "user":
            content = m.get("content")
            if isinstance(content, str):
                return [{"type": "text", "text": content}]
            return [c for c in content or [] if isinstance(c, dict)]
    return []


def prompt(body):
    """The text of the conversation's first user message: what the agent was asked."""
    for m in body.get("messages", []):
        if m.get("role") == "user":
            content = m.get("content")
            if isinstance(content, str):
                return content
            return " ".join(c.get("text", "") for c in content or [] if isinstance(c, dict))
    return ""


def reply_for(body):
    """(text, tool calls) for a Messages API request; a call is (id, name, input)."""
    tools = {t.get("name") for t in body.get("tools") or []}
    asked = prompt(body).lower()
    for words, steps in FLOWS:
        if all(w in asked for w in words) and {c[0] for _, calls in steps for c in calls} <= tools:
            answered = [
                c.get("tool_use_id", "") for c in last_user(body) if c.get("type") == "tool_result"
            ]
            step = next(
                (
                    i + 1
                    for i in range(len(steps))
                    if any(a.startswith(f"toolu_cast{i}_") for a in answered)
                ),
                0,
            )
            text, calls = steps[step]
            return text, [
                (f"toolu_cast{step}_{n}", name, args() if callable(args) else args)
                for n, (name, args) in enumerate(calls)
            ]
    lower = " ".join(c.get("text", "") for c in last_user(body)).lower()
    for key, reply in REPLIES.items():
        if key in lower:
            return reply, []
    return DEFAULT, []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # CANNED_LOG=1: each request on stderr, to see what an agent asks.
        if os.environ.get("CANNED_LOG"):
            sys.stderr.write(fmt % args + "\n")

    def body(self):
        n = int(self.headers.get("content-length") or 0)
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return {}

    def json(self, obj, status=200):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.split("?")[0].rstrip("/").endswith("/models"):
            self.json(
                {
                    "data": [{"id": MODEL, "type": "model", "display_name": "Cast"}],
                    "has_more": False,
                }
            )
        else:
            self.json({"error": {"type": "not_found"}}, 404)

    def do_POST(self):
        path = self.path.split("?")[0]
        body = self.body()
        if os.environ.get("CANNED_LOG"):
            sys.stderr.write(
                f"{path} model={body.get('model')} stream={body.get('stream')} "
                f"tools={len(body.get('tools') or [])} max_tokens={body.get('max_tokens')}\n"
            )
        if path.endswith("/count_tokens"):
            self.json({"input_tokens": 100})
        elif path.endswith("/messages"):
            text, calls = reply_for(body)
            if body.get("stream"):
                self.stream(text, calls)
            else:
                self.json(message(text, calls))
        else:
            self.json({"error": {"type": "not_found"}}, 404)

    def stream(self, text, calls):
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        self.end_headers()

        def event(kind, data):
            data["type"] = kind
            self.wfile.write(f"event: {kind}\ndata: {json.dumps(data)}\n\n".encode())
            self.wfile.flush()

        start = message("", [])
        start["content"] = []
        start["stop_reason"] = None
        event("message_start", {"message": start})
        block = {"type": "text", "text": ""}
        event("content_block_start", {"index": 0, "content_block": block})
        # Word by word, so the recording shows it arrive.
        words = text.split(" ")
        for i, w in enumerate(words):
            chunk = w if i == len(words) - 1 else w + " "
            delta = {"type": "text_delta", "text": chunk}
            event("content_block_delta", {"index": 0, "delta": delta})
            time.sleep(0.04)
        event("content_block_stop", {"index": 0})
        for index, (tid, name, args) in enumerate(calls, 1):
            block = {"type": "tool_use", "id": tid, "name": name, "input": {}}
            event("content_block_start", {"index": index, "content_block": block})
            delta = {"type": "input_json_delta", "partial_json": json.dumps(args)}
            event("content_block_delta", {"index": index, "delta": delta})
            event("content_block_stop", {"index": index})
        stop = {"stop_reason": "tool_use" if calls else "end_turn", "stop_sequence": None}
        event("message_delta", {"delta": stop, "usage": {"output_tokens": len(words)}})
        event("message_stop", {})


def message(text, calls):
    content = [{"type": "text", "text": text}]
    for tid, name, args in calls:
        content.append({"type": "tool_use", "id": tid, "name": name, "input": args})
    return {
        # Its own id: an agent joins the blocks of replies that share one.
        "id": f"msg_{uuid.uuid4().hex}",
        "type": "message",
        "role": "assistant",
        "model": MODEL,
        "content": content,
        "stop_reason": "tool_use" if calls else "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 100, "output_tokens": len(text.split())},
    }


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18000
    # Every interface: an env's gate reaches this machine at its VM network's gateway, not at
    # loopback. It serves canned text only.
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
