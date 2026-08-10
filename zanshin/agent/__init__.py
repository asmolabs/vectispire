"""The Zanshin scan agent: a worker that runs scans on another machine.

Started with `python -m zanshin.agent`, given the URL of a Zanshin instance and an
API key carrying the `agent` scope. It then loops: ask for work, run the scanners,
report back.

**The invariant this package exists to hold.** Nothing here imports
`zanshin.database`, `zanshin.models` or `zanshin.ui`. That is not a style
preference — it is the security property of décision 0003 expressed as an import
graph. An agent with a database connection would need the connection string *and*
`ENCRYPTION_KEY`, i.e. the ability to decrypt every deploy key Zanshin holds. With
only HTTP and a scoped key, a compromised agent is limited to the work it was
given. `tests/test_agent_worker.py` asserts the import graph, so the property
cannot quietly erode.

What it does import is the code that actually runs a scan — `ScanRunner` and the
`ScannerEngine` implementations — so the steps, the flags and the tool invocations
are the same ones the control plane would have used. Duplicating them here is how
the `scan-api/` sidecar drifted from `docker_engine.py`, and this package is meant
to replace that sidecar, not repeat its mistake.
"""

__all__ = ["main"]


def __getattr__(name):
    # Lazy so that `import zanshin.agent` stays cheap and dependency-free; the CLI
    # entry point pulls in httpx and the docker client only when actually run.
    if name == "main":
        from zanshin.agent.cli import main

        return main
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
