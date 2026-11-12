"""Plug ADAP in front of any Python tool. Stdlib only.

The console must already be running. Set:
  ADAP_URL=http://127.0.0.1:4317
  ADAP_TEAM_TOKEN=...
  ADAP_AGENT_ID=agt_hackathon_demo

CrewAI, Pydantic AI, Google ADK, AutoGen, and LlamaIndex all end at a
function call. Call guard() there. The tool runs only when the action is ALLOW.
"""

from __future__ import annotations

import json
import os
import urllib.request


def guard(tool_name: str, args: dict | None, execute):
    decision = ask(tool_name, args or {})
    if decision.get("action") != "ALLOW":
        return {"decision": decision, "executed": False, "output": None}
    return {"decision": decision, "executed": True, "output": execute(tool_name, args or {})}


def ask(tool_name: str, args: dict) -> dict:
    url = os.environ.get("ADAP_URL", "http://127.0.0.1:4317").rstrip("/") + "/api/gate"
    token = os.environ.get("ADAP_TEAM_TOKEN", "")
    agent = os.environ.get("ADAP_AGENT_ID", "agt_hackathon_demo")
    body = json.dumps(
        {"agentId": agent, "tool": tool_name, "args": args},
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "content-type": "application/json",
            "authorization": f"Bearer {token}",
            "x-adap-request": "1",
        },
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))
