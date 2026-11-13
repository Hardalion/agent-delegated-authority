#!/usr/bin/env python3
"""Framework-agnostic ADAP gate over HTTP. Stdlib only.

Local hackathon console:

  pnpm hackathon:start
  set ADAP_URL=http://127.0.0.1:4317
  set ADAP_TEAM_TOKEN=[REDACTED]
  python examples/hackathon/http_gate.py
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request


def gate(tool_name: str, args: dict | None = None, *, agent_id: str | None = None) -> dict:
    base = os.environ.get("ADAP_URL", "http://127.0.0.1:4317").rstrip("/")
    token = os.environ.get("ADAP_TEAM_TOKEN", "")
    if not token:
        raise SystemExit("Set ADAP_TEAM_TOKEN to the Team token printed by pnpm hackathon:start.")
    body = json.dumps(
        {
            "agentId": agent_id or os.environ.get("ADAP_AGENT_ID", "agt_hackathon_demo"),
            "tool": tool_name,
            "args": args or {},
        },
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{base}/api/gate",
        data=body,
        method="POST",
        headers={
            "content-type": "application/json",
            "authorization": f"Bearer {token}",
            "x-adap-request": "1",
        },
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


def guarded(tool_name: str, args: dict, execute):
    decision = gate(tool_name, args)
    if decision.get("action") != "ALLOW":
        return {"decision": decision, "executed": False, "output": None}
    return {"decision": decision, "executed": True, "output": execute()}


def main() -> int:
    demos = [
        ("search_web", {"q": "athens agents"}),
        ("send_email", {"to": "team@example.com"}),
        ("delete_record", {"id": "demo"}),
    ]
    for tool, args in demos:
        try:
            result = gate(tool, args)
        except urllib.error.HTTPError as error:
            print(tool, "HTTP", error.code, error.read().decode("utf-8", errors="replace"))
            return 1
        print(f"{tool:16} → {result.get('action')}  runTool={result.get('runTool')}  {result.get('ruleId')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
