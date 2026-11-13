# MCP binding

**Status:** Public Draft (v0.1). Normative for implementations that claim an ADAP-enforcing MCP gateway.

Model Context Protocol (MCP) is a transport and tool-call surface. ADAP is the authority semantics. This document maps MCP `tools/call` onto ADAP terms and separates two claim levels.

## Claim levels

| Claim | What it means | This repository |
| --- | --- | --- |
| **Policy-only MCP helper** | Evaluate tool name/args with `evaluateToolCall` / `McpToolGate` before dispatch. No signed intent, delegation, capability, or receipt. | `packages/policy-engine/src/integrations/mcp.ts`, `integrations/mcp.ts` |
| **Authority-enforcing MCP binding** | Every consequential `tools/call` is an ADAP intent under a presented delegation chain, with deterministic policy, optional human approval, single-use execution, and an Authorization Receipt. | Normative requirements below. Reference gateway shape: `packages/adap-gateway` |

`McpToolGate` MUST NOT be described as a full ADAP MCP binding. See [integrations/README.md](../integrations/README.md).

## Authority-enforcing binding (normative)

A conforming ADAP MCP gateway:

1. **Derives** `action` and `target` from server identity, tool name, and a pinned tool-definition hash (description + input schema). The agent MUST NOT freely label a call with an unrelated target while arguments point elsewhere.
2. **Requires** a signed ADAP intent whose `parameters` are the tool arguments (closed-world when the tool profile sets `closed: true`).
3. **Presents** a delegation chain whose terminal grant covers that action/target and every `max_<field>` ceiling.
4. **Evaluates** the governing policy from operator configuration or a pin carried on the root delegation — not from an unauthenticated client header alone when more than one policy is registered.
5. **Mints no side effect** on `BLOCK` or unresolved `REQUIRE_HUMAN`. Only `ALLOW` (including post-approval) may invoke the tool handler.
6. **Emits** an Authorization Receipt that binds intent hash, policy pin and content hash, decision, and reported execution. Demo placeholder signatures MUST NOT verify as valid evidence.
7. **Keeps** rail / tool credentials out of the model process. The gateway or vault broker holds them.

### Synthetic conformance scenarios (no side effects)

These scenarios MUST be testable without contacting a real MCP server:

| Id | Setup | Expected |
| --- | --- | --- |
| `mcp-pol-block` | Policy-only gate, tool `apply`, `amount: 800`, `basic-agent-authority` | `BLOCK`, executor not called |
| `mcp-pol-allow` | Policy-only gate, tool `read` | `ALLOW`, executor called once |
| `mcp-auth-over-delegation` | Child raises parent `max_amount` | `BLOCK`, no tool call, receipt `executed: false` |
| `mcp-auth-require-human` | Intent under grant, policy `REQUIRE_HUMAN`, no approval | Tool not called; pending bound to intent hash |
| `mcp-auth-tool-def-drift` | Tool schema hash differs from grant | `BLOCK` until a new grant names the new hash |

Language-independent vectors: [examples/conformance/mcp-vectors.json](../examples/conformance/mcp-vectors.json).

## Open questions (non-normative)

Retained from review (PR #9). Not required for v0.1 conformance:

- Whether receipts MUST bind a hash of the tool result (indirect prompt injection via results).
- Whether server-initiated MCP sampling/elicitation is an intent, and under whose delegation.
- Whether the gateway keeps session state (cumulative spend, data-flow labels). v0.1 decisions are **per call**. Cumulative multi-turn accounting is a **non-normative future**; see [amounts-and-targets.md](./amounts-and-targets.md) and issue #13.

## Reference

- Policy-only helper tests: `packages/policy-engine/src/integrations/mcp.test.ts`
- Authority path: `packages/aap`, `packages/adap-gateway`
- Threat model: [../THREAT_MODEL.md](../THREAT_MODEL.md)
