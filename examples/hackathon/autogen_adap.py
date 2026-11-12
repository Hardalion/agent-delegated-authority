"""Microsoft AutoGen: wrap a function before you register it as a tool.

The console must be running. The function runs only when ADAP returns ALLOW.
Pass the result of wrap_function to FunctionTool or the agent's tools list.
"""

from __future__ import annotations

from gate import ask


def safe_handoff(message, decide=None):
    """Refuse a cross-agent assignment when no delegation chain is present.

    AutoGen messages do not carry authority by themselves. Without a chain,
    Agent A does not get to assign work to Agent B.
    """

    sender = message.get("from") if isinstance(message, dict) else None
    receiver = message.get("to") if isinstance(message, dict) else None
    if not sender or not receiver or sender == receiver:
        return {"allowed": False, "reason": "delegation chain required"}
    chain = message.get("chain") if isinstance(message, dict) else None
    intent = message.get("intent") if isinstance(message, dict) else None
    if not chain or not intent:
        return {"allowed": False, "reason": "delegation chain required"}
    if decide is None:
        return {"allowed": False, "reason": "delegation chain must be checked by the ADAP runtime"}
    return decide(message)


def wrap_function(fn, name, decide=ask):
    def wrapped(*args, **kwargs):
        decision = decide(name, _payload(args, kwargs))
        if decision.get("action") != "ALLOW":
            return {"executed": False, "decision": decision}
        return fn(*args, **kwargs)

    wrapped.__name__ = getattr(fn, "__name__", name)
    wrapped.__doc__ = getattr(fn, "__doc__", None)
    return wrapped


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
