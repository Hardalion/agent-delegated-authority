"""AutoGen handoff. A message from one agent to another is not authority.

safe_handoff refuses the assignment when the delegation chain is missing.
"""

from autogen_adap import safe_handoff, wrap_function


def search_web(q: str) -> str:
    return f"results for {q}"


search = wrap_function(search_web, "search_web")


def on_message(message: dict):
    return safe_handoff(message)
