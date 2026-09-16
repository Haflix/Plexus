# Plexus

*Last updated for Plexus 0.81.0*

An async Python plugin framework with multi-node mTLS networking and pub/sub
event routing. PyPI package: [`plexus-core`](https://pypi.org/project/plexus-core/).

`Plexus` loads small, single-responsibility Python classes — *plugins* — from
disk, drives a deterministic `on_load` / `on_enable` / `on_disable` lifecycle,
and gives them three ways to talk to each other:

- direct method calls — `await self.execute("OtherPlugin", "method", args=...)`
- 1:N events — `await self.publish_event("event_id", payload=...)`
- 1:1 ask-by-topic — `result = await self.request_event("event_id", payload=...)`

The runtime can stretch across multiple nodes over an mTLS-pinned wire
protocol (`NetworkManager`), so the same `execute` / `publish_event` /
`request_event` calls transparently fan out to peer machines whose plugins
are flagged `remote: true`.

A typical deployment in conversational AI, data-pipeline, or event-driven
domains wires together base plugins (a Discord bot, a Postgres adapter, an
LLM adapter, a TTS pipeline) with orchestrator plugins that hold the
business logic — each one a class plus a YAML manifest.

---

## Highlights

- **One-class-per-plugin layout.** A `plugin.py` plus a declarative
  `plugin_config.yml` describing endpoints, events, and subscriptions.
- **Three call styles.** Direct endpoint calls (`execute`), 1:N
  fire-and-forget events (`publish_event`), and 1:1 topic-routed requests
  with optional streaming (`request_event`, `request_event_stream`).
- **Hot-swap reloading.** Any plugin can be disabled, re-instantiated from
  config, and re-enabled at runtime — its sockets, background tasks, and
  event subscriptions tear down and rebuild on a fresh class instance with
  no downtime for the rest of the cluster.
- **Three-tier discipline (project policy).** *Base* plugins wrap one
  protocol or service; *Extension* plugins glue bases together; *Orchestrator*
  plugins hold business logic.
- **Multi-node clustering.** Pinned-fingerprint mTLS between peers; remote
  endpoints and remote subscribers are reachable through the same Plugin
  base methods that drive local calls.
- **Sync and async surfaces.** Every cross-plugin call has both an `async`
  form and a sync form that bridges to the loop, so plugins written against
  blocking libraries do not have to twist themselves into coroutines.
- **Strict but small.** Around fifteen public methods on the Plugin base
  class; everything else is YAML.

---

## Install

Requires Python 3.11+.

From PyPI (recommended for using Plexus as a library):

```bash
pip install plexus-core
```

Optional: add `[fastloop]` for a faster event loop (uvloop on Linux/macOS,
winloop on Windows). Purely a performance opt-in; everything works without
it.

```bash
pip install plexus-core[fastloop]
```

From source (for developing on the framework itself):

```bash
git clone https://github.com/Haflix/Plexus.git
cd Plexus
python -m venv .venv
.venv/Scripts/activate          # Windows
# source .venv/bin/activate     # Linux / macOS
pip install -e .
cp config.example.yml config.yml
```

`config.yml` is gitignored. Edit it to enable the plugins you want.

---

## Quickstart

A plugin lives in its own folder containing exactly two files: `plugin.py`
(the class) and `plugin_config.yml` (declarative metadata).

Here is a minimal plugin showing the moving parts: lifecycle hooks, a regular
endpoint, a streaming endpoint, a cross-plugin call, and a topic-subscribed
endpoint. The shipped `copypasta/` folder has a fuller, **runnable** version of
these patterns (a two-plugin demo that also covers rate limiting and
capabilities); run it with `python copypasta/run_demo.py` and see
[`copypasta/README.md`](copypasta/README.md).

### A minimal `plugin.py`

```python
from plexus.utils import Plugin
from plexus.decorators import (
    log_errors, async_log_errors,
    async_handle_errors, async_gen_log_errors,
)
import asyncio


class AveragePlugin(Plugin):
    @log_errors
    def on_load(self, *args, **kwargs):
        self._logger.debug("AveragePlugin loaded")
        self.state = {}

    @async_log_errors
    async def on_enable(self):
        self._logger.debug("AveragePlugin enabled")

    @async_log_errors
    async def on_disable(self):
        self._logger.debug("AveragePlugin disabled")

    @async_log_errors
    async def example_method(self, value):
        return value * 2

    @async_handle_errors(default_return=None)
    async def call_other_plugin(self, plugin_name, method_name, args):
        return await self.execute(plugin_name, method_name, args, hosts="any")

    @async_log_errors
    async def handle_event(self, event):
        # event.topic, event.payload, event.author, event.author_host
        return {"received": event.payload, "handled_by": self.plugin_name}

    @async_gen_log_errors
    async def example_stream(self, count):
        for i in range(count):
            await asyncio.sleep(0.1)
            yield f"Item {i + 1} of {count}"
```

### The matching `plugin_config.yml`

```yaml
description: Example plugin demonstrating the Plexus plugin structure
version: 1.0.0
remote: True
arguments:

subscriptions:
  handle_event_sub:
    topic: "example/event"
    target_access_name: handle_event
    hosts: "local"

endpoints:
  example_method:
    internal_name: example_method
    remote: True
    accessible_by_other_plugins: True
    description: Doubles the input value.
    arguments:
      - name: value
        type: any
        description: Input value to process

  call_other_plugin:
    internal_name: call_other_plugin
    remote: True
    accessible_by_other_plugins: True
    description: Call another plugin's method by name and return its result.
    arguments:
      - name: plugin_name
        type: str
        description: Name of the plugin to call
      - name: method_name
        type: str
        description: Method to execute on the target plugin
      - name: args
        type: any
        description: Arguments to pass to the method

  example_stream:
    internal_name: example_stream
    remote: True
    accessible_by_other_plugins: True
    description: Streaming method that yields sequential results.
    arguments:
      - name: count
        type: int
        description: Number of items to yield

  handle_event:
    internal_name: handle_event
    remote: True
    accessible_by_other_plugins: True
    description: Endpoint subscribed to "example/event" via the subscriptions block.
    arguments:
      - name: event
        type: any
        description: Event object received from the topic
```

### Run it

The `copypasta/` folder ships a runnable version of these patterns. From the repo
root:

```bash
python copypasta/run_demo.py
```

It registers two plugins (`SensorPlugin` + `AveragePlugin`), wires them together,
and drives a scripted scenario: readings published as events flow into a running
average, an on-demand cross-plugin `execute()`, a capability assertion, and the
rate limiter rejecting once a bucket is dry.

To register a plugin in your own app, add it to `config.yml` and launch
`main_application.py`:

```yaml
plugins:
  - name: YourPlugin
    enabled: true
    path: ./path/to/YourPlugin
```

From any other plugin you can then call an endpoint, or fire an event the plugin
declares:

```python
result = await self.execute("YourPlugin", "some_method", args=...)

count = await self.publish_event("some_event", payload={"hello": "world"})
# count == number of subscribers the dispatch was scheduled for
```

That is the entire surface to write something useful. The rest is just more
endpoints, more events, more subscriptions.

---

## Documentation

| File | Audience | Focus |
|---|---|---|
| [docs/architecture.md](docs/architecture.md) | new readers | mental model, lifecycle, three-tier discipline, hot-swap, shutdown order |
| [docs/plugin_authoring.md](docs/plugin_authoring.md) | plugin authors | full `plugin_config.yml` schema and a tutorial-style walkthrough |
| [docs/api_reference.md](docs/api_reference.md) | reference users | every `Plugin`-base method (signature, args, raises) plus decorators |
| [docs/notifier.md](docs/notifier.md) | event-system users | publish vs request, topic templating, filter chain, runtime subs |
| [docs/networking.md](docs/networking.md) | multi-node operators | mTLS, peers, cert pinning, remote semantics, wire protocol |
| [docs/configuration.md](docs/configuration.md) | operators | full `config.yml` reference and per-plugin overrides |
| [docs/rate_limiting.md](docs/rate_limiting.md) | operators | the token-bucket rate limiter: dimensions, `rate_limits:` config, observability |
| [docs/capabilities.md](docs/capabilities.md) | operators | caller identity + the `capabilities:` impersonation / system-caller grant model |

---

## Status

Active development. Public API of the `Plugin` base class is stable;
internal `Plexus` helpers (`_*` prefix) are not. See the wire-protocol
table in [docs/networking.md](docs/networking.md) for cross-version
compatibility.

## Acknowledgements

The early networking and streaming work (0.6.0 through 0.6.5, mid-2025) was a
collaboration with [1ckyDev](https://github.com/1ckyDev), who wrote the first
structure of the networking layer. Development has been solo since.

## License

See [LICENSE](LICENSE).
