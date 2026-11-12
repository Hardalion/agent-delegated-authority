"""Secure CrewAI tool. The decorator is the integration.

Three lines around the tool you already wrote.
The function runs only when ADAP returns ALLOW.
"""

from crewai_adap import adap_tool


@adap_tool("search_web")
def search_web(q: str) -> str:
    return f"results for {q}"


@adap_tool("send_email")
def send_email(to: str, body: str) -> str:
    return f"sent to {to}"
