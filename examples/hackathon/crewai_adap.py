"""CrewAI: wrap a tool so ADAP runs before _run.

The console must be running. The original _run is called only when the
decision is ALLOW.
"""

from __future__ import annotations

from gate import ask


class ADAPToolDecorator:
    """Intercept a CrewAI tool or a plain function before it runs."""

    def __init__(self, name=None, decide=ask):
        self.name = name
        self.decide = decide

    def __call__(self, fn):
        tool_name = self.name or getattr(fn, "__name__", "tool")
        decide = self.decide

        def wrapped(*args, **kwargs):
            decision = decide(tool_name, _payload(args, kwargs))
            if decision.get("action") != "ALLOW":
                return {"executed": False, "decision": decision}
            return fn(*args, **kwargs)

        wrapped.__name__ = getattr(fn, "__name__", tool_name)
        wrapped.__doc__ = getattr(fn, "__doc__", None)
        return wrapped


def adap_tool(name=None, decide=ask):
    return ADAPToolDecorator(name, decide)


def wrap_crewai(tool, decide=ask):
    original = tool._run
    name = getattr(tool, "name", None) or tool.__class__.__name__

    def _run(*args, **kwargs):
        decision = decide(name, _payload(args, kwargs))
        if decision.get("action") != "ALLOW":
            return {"executed": False, "decision": decision}
        return original(*args, **kwargs)

    tool._run = _run
    return tool


def _payload(args, kwargs):
    if kwargs:
        return {key: value for key, value in kwargs.items() if _plain(value)}
    if len(args) == 1 and isinstance(args[0], dict):
        return args[0]
    if args:
        return {"input": args[0] if _plain(args[0]) else str(args[0])}
    return {}


def _plain(value):
    return value is None or isinstance(value, (str, int, float, bool))
