# ADAP MCP proxy — requirements, architecture, and design

**Status:** Draft for review (Milestone 1 deliverable for [issue #22](https://github.com/Hardalion/agent-delegated-authority/issues/22)).
**Target package:** `packages/adap-mcp-proxy` (not implemented yet).
**Protocol basis:** [`spec/mcp-binding.md`](../../spec/mcp-binding.md), [`spec/execution.md`](../../spec/execution.md), [`spec/human-approval.md`](../../spec/human-approval.md).

> This document is the "small design-first PR (a short doc under `docs/`)" requested on the issue.
> It contains no implementation code. It proposes the API surface and the failure semantics so the
> proxy can be reviewed before a package exists, rather than after a parallel authorization path has
> already been written.

---

## 1. What was agreed, in one paragraph

For a **full** integration the preferred shape is an **out-of-process MCP server proxy/gateway**. The
trusted host supplies the signed intent, the delegation chain, identity and key resolution out of
band. An explicit **server-side** mapping turns MCP tools into ADAP actions/targets/authorized
parameters. Model-supplied names and arguments must never define or widen that mapping. `ALLOW`
invokes the upstream tool **once**; `REQUIRE_HUMAN` preserves pending context and invokes nothing;
`BLOCK` and any verification, policy, timeout or approval error invoke nothing. The proxy builds on
**`executeAuthorized`**, not a parallel policy path. It lives in a **new package** and does not touch
core canonicalization or receipt code. It follows the outcome model `not_dispatched` / `returned` /
`unknown`, so an upstream timeout **after dispatch** is `unknown`, never `BLOCK` and never
`not_dispatched`.

Milestone 1 is **stdio only**: the host launches the proxy as a child process and speaks MCP over
stdio. No network listener, no new authentication surface.

---

## 2. Baseline

Verified against `main` at `0410cf4` before this design was written. This pull request adds
documentation only; it changes no existing behaviour.

| Check | Result |
| --- | --- |
| Runtime | Node 24.15.0 (repository requires >= 22) |
| Package manager | pnpm 12.23.0, `lockfileVersion: '9.0'` |
| Build (all packages) | `pnpm build` exit 0 — `adap-policy`, `adap-receipt`, `adap`, `adap-store-postgres`, `adap-gateway` |
| Tests | `pnpm test` exit 0 |
| MCP SDK | `@modelcontextprotocol/sdk` 1.32.2 |

The MCP tool-definition primitives this design builds on are already on `main`
(`hashMcpToolDefinition`, `adapBindingForMcpCall`, `authorityMcpCall`, `verifyReceiptMcpToolBinding`
in `packages/aap/src/mcp-tool.ts`, plus `closed: true` parameter enforcement and
`examples/conformance/mcp-vectors.json`).

---

## 3. Scope

### In scope (Milestone 1 / first PR with code)

1. One upstream MCP server connection per proxy process.
2. A **stdio** entry transport only: the host launches the proxy as a child process.
3. Tool discovery from the upstream, with every tool **pinned** by `hashMcpToolDefinition`.
4. `tools/call` interception and mapping to `server.tool` / `mcp/<server>/<tool>`.
5. Signed-intent + delegation handoff from the trusted host, verified — never derived from arguments.
6. Authorization through `executeAuthorized` from `adap-gateway`.
7. `ALLOW` / `REQUIRE_HUMAN` / `BLOCK` enforcement with hard "no upstream call" guarantees.
8. Receipt + correlation propagation back to the caller.
9. Post-dispatch timeout recorded as `unknown`.
10. Tests for the matrix in §11 and a runnable example.

### Explicitly out of scope (M1)

- A Streamable HTTP entry transport, or any listener the agent can reach over a network.
- Multi-server routing, load balancing, tool-name namespacing across servers.
- A UI for approvals; an approval service. Only the **contract** and a resume path.
- Policy authoring, identity provisioning, a secret manager.
- A Python package (that is a later, separately-scoped milestone).
- Streaming/progress passthrough beyond what MCP requires for a single tool result.
- Any claim that the proxy stops an agent that can reach the upstream server directly. That is a
  deployment property, exactly as [`docs/architecture/reference.md`](../architecture/reference.md)
  says.

---

## 4. Requirements

### 4.1 Functional

| ID | Requirement |
| --- | --- |
| FR-1 | The proxy exposes an MCP server surface (`initialize`, `tools/list`, `tools/call`) over stdio and proxies to exactly one configured upstream. |
| FR-2 | `tools/list` returns the upstream tool definitions **unmodified** (name, description, `inputSchema`, and optional `title`/`icons`/`outputSchema`/`annotations`). |
| FR-3 | Every advertised tool MUST resolve to an operator-configured mapping entry. A tool with no entry is advertised as **unavailable** and any call for it is refused before the authority path. |
| FR-4 | On `tools/call` the proxy re-derives `action`/`target` with `adapBindingForMcpCall(server_id, tool_name)` — never from the request. |
| FR-5 | The proxy verifies the presented signed intent and chain by calling `executeAuthorized` with a policy from the operator registry, a shared nonce ledger and a pending store. |
| FR-6 | Before authorization, the proxy MUST check that the signed intent's `parameters` are canonically equal to the model's `tools/call` `arguments`. A mismatch is refused. |
| FR-7 | On `ALLOW`, the upstream tool is invoked **exactly once**, with the authorized (frozen) parameters copied from the verified intent. |
| FR-8 | On `REQUIRE_HUMAN`, the upstream tool is not invoked; a structured pending result is returned with an approval reference bound to `(actor, nonce, intent_hash)`. |
| FR-9 | On `BLOCK`, the upstream tool is not invoked; a structured denial is returned with rule id, reason and receipt id. |
| FR-10 | Every authorization outcome that reached the authority path returns or emits its Authorization Receipt (id, hash, intent hash, policy hash, correlation id). |
| FR-11 | A post-dispatch upstream timeout / dropped connection / crash is recorded as `decision: ALLOW`, `failureMode: SYSTEM_ERROR`, `execution.outcome: unknown`, `executed: false` — never as `BLOCK`. |
| FR-12 | The mapping is loaded read-only at boot. An invalid, empty, duplicate or unregistered mapping prevents startup (fail closed, like `ADAP_POLICY_BINDINGS_PATH`). |
| FR-13 | Upstream tool definitions are re-hashed immediately before dispatch; drift from the granted `tool_definition_hash` is `BLOCK (tool_definition)`. |
| FR-14 | `REQUIRE_HUMAN` resumes only when the trusted host re-presents the same intent plus a signed `HumanApproval`; a model-initiated "retry" flag has no effect. |

### 4.2 Security invariants

| ID | Invariant |
| --- | --- |
| SI-1 | **The model cannot widen authority.** Tool names and arguments from the model never select a policy, a target, an upstream server, or a mapping entry. |
| SI-2 | **The model cannot mint context.** Signed intents, chains and approvals come only from `_meta` set by the trusted host, never from `arguments`. |
| SI-3 | **Credentials stay out of the model process.** The upstream stdio child's environment (and any upstream token) is constructed inside the proxy; nothing in a tool result can echo it. |
| SI-4 | **Fail closed.** Any error in parsing, mapping, intent/argument equality, signature, chain, audience, root authority, revocation, nonce, policy resolution, approval or receipt emission results in **no upstream call**. |
| SI-5 | **Single use.** One `(actor, nonce)` executes at most once, enforced by the same ledger the authority path uses. |
| SI-6 | **Determinism.** The same input state produces the same decision; the proxy adds no timestamps, randomness or retries to the decision path. |
| SI-7 | **No parallel authority path.** Policy evaluation, nonce handling, outcome classification and receipt sealing remain in `adap` / `adap-gateway`. The proxy owns routing and transport only. |

### 4.3 Non-functional

| ID | Requirement |
| --- | --- |
| NFR-1 | Node >= 22, ESM, TypeScript strict, no new runtime framework beyond the MCP SDK and `zod` (already used by the gateway). |
| NFR-2 | Decision overhead is local (signature verify + policy eval + ledger); the design must not add a network hop for M1. |
| NFR-3 | The mapping file and identity configuration are operator-owned, mounted read-only, and require a restart to change. |
| NFR-4 | Errors returned to the model are informative but must not leak credentials, key material, or unrelated tenants' data. |

---

## 5. Architecture

### 5.1 Trust boundaries and components

```
             TRUSTED HOST / OPERATOR DOMAIN  (holds keys, signs)
  ┌───────────────────────────────────────────────────────────────────┐
  │  Agent runtime (LLM loop)                                         │
  │    model emits { name, arguments }   ◄── UNTRUSTED text           │
  │           │                                                       │
  │           ▼                                                       │
  │  Host tool pipeline                                               │
  │    • binds model arguments to a signed ADAP intent (agent key)    │
  │    • attaches delegation chain, audience                          │
  └───────────┬───────────────────────────────────────────────────────┘
              │ MCP over stdio (child process)
              │   params.arguments            (model-controlled)
              │   params._meta["adap/intent"]      (HOST-set, signed)
              │   params._meta["adap/delegation"]  (HOST-set, signed)
              │   params._meta["adap/approval"]    (HOST-set, on resume)
  ┌───────────▼───────────────────────────────────────────────────────┐
  │  adap-mcp-proxy  — trusted enforcement process                    │
  │                                                                   │
  │   McpServer (stdio only in M1)                                    │
  │     │                                                             │
  │     ├─ MappingResolver      operator JSON, read-only, fail closed │
  │     ├─ ToolPin              hashMcpToolDefinition + drift check   │
  │     ├─ ContextGuard         intent.parameters == arguments        │
  │     │                                                             │
  │     ├─ executeAuthorized()  ── from adap-gateway ──┐              │
  │     │     runAuthorityPath:                        │              │
  │     │       sig → chain → audience → root →        │              │
  │     │       revocation → nonce → policy pin →      │              │
  │     │       decision → claim → execute → receipt   │              │
  │     │                                              │              │
  │     └─ McpUpstreamBroker implements CredentialBroker              │
  │           resolveHandle(action,target) → route                    │
  │           execute(handle, req) → upstream MCP client              │
  │           holds upstream transport + credentials                  │
  └───────────┬───────────────────────────────────────────────────────┘
              │ MCP client (credentials live here, never in a result)
  ┌───────────▼───────────┐   ┌─────────────────────┐   ┌────────────────────┐
  │ Upstream MCP server   │   │ Postgres (optional) │   │ Operator approval  │
  │ tools: pay, lookup…   │   │ nonces, pending,    │   │ plane (external to │
  │                       │   │ policies, exec log  │   │ this process)      │
  └───────────────────────┘   └─────────────────────┘   └────────────────────┘
```

Why `CredentialBroker` is the right seam: it already means *"the thing that holds the rail
credential and performs the downstream call after authorization, returning
`completed | accepted | failed | unknown`."* An MCP upstream is exactly a downstream system, and
`executeAuthorized` already gives canonical action/target checks, frozen parameters, correlation ids,
execution-state persistence and unknown-outcome semantics.

### 5.2 `tools/call` sequence (happy path)

```
Host            Proxy                    adap-gateway            Upstream MCP
 │  tools/call    │                          │                       │
 ├───────────────►│                          │                       │
 │                │ 1 mapping: server.tool   │                       │
 │                │   target mcp/srv/tool    │                       │
 │                │ 2 pin = hash(definition) │                       │
 │                │ 3 intent.parameters == arguments ?               │
 │                │        no → refuse (no path)                     │
 │                ├─ executeAuthorized ─────►│                       │
 │                │                          │ verify sig/chain/aud  │
 │                │                          │ pin vs grant          │
 │                │                          │ nonce assert          │
 │                │                          │ policy → ALLOW        │
 │                │                          │ claim nonce           │
 │                │                          ├─ broker.execute ─────►│ tools/call
 │                │                          │◄──── result ──────────┤
 │                │                          │ seal receipt          │
 │                │◄── result + receipt ─────┤                       │
 │◄── content ────┤  _meta.adap{decision,receiptId,intentHash,corr}  │
```

### 5.3 Decision and failure state machine

```
tools/call
   │
   ├─ unknown tool / no mapping / malformed target ──────────────► REFUSE  (no path, no receipt)
   ├─ intent.parameters ≠ arguments ────────────────────────────► REFUSE  (no path, no receipt)
   │
   ▼
executeAuthorized
   │
   ├─ signature / chain / audience / root / revocation fail ────► BLOCK   receipt, no dispatch
   ├─ tool-definition pin mismatch ─────────────────────────────► BLOCK   receipt, no dispatch
   ├─ policy BLOCK ─────────────────────────────────────────────► BLOCK   receipt, no dispatch
   │
   ├─ policy REQUIRE_HUMAN ─────────────────────────────────────► PENDING receipt, no dispatch
   │      │  host retries same intent + signed approval
   │      ├─ approval DENY ─────────────────────────────────────► BLOCK   receipt, no dispatch
   │      └─ approval APPROVE ──────────────────────────────────► dispatch once → ALLOW
   │
   └─ policy ALLOW ─────────────────────────────────────────────► dispatch once
          ├─ upstream returned (incl. tool-level isError) ──────► ALLOW   outcome returned
          └─ timeout / drop / crash after send ─────────────────► ALLOW   outcome unknown
```

**Two refusal classes are deliberate.** `REFUSE` happens *before* the authority path, so there is no
intent evaluation and therefore no receipt. The proxy must not emit an `ALLOW` receipt for an intent
it declined to run, nor a `BLOCK` receipt for an intent whose hash it never evaluated. These are
returned as an MCP tool error with `_meta.adap.refused = true` and a stable reason code, and recorded
in the proxy's security event log. `BLOCK` and `PENDING` always come *from* the path, so they always
carry a receipt.

### 5.4 Failure → receipt mapping (matches `spec/execution.md`)

| Situation | upstream called | decision | executed | outcome | failureMode |
| --- | --- | --- | --- | --- | --- |
| Mapping miss, args mismatch, malformed target | no | REFUSE | – | – | – |
| Bad signature / chain / audience / root / revoked | no | `BLOCK` | false | `not_dispatched` | `RULE_VIOLATION` |
| Tool-definition drift | no | `BLOCK` (`tool_definition`) | false | `not_dispatched` | `RULE_VIOLATION` |
| Policy `BLOCK` | no | `BLOCK` | false | `not_dispatched` | `RULE_VIOLATION` |
| Policy `REQUIRE_HUMAN`, no approval | no | `REQUIRE_HUMAN` | false | `not_dispatched` | `NONE` |
| Approval `DENY` | no | `BLOCK` | false | `not_dispatched` | `RULE_VIOLATION` |
| Approval `APPROVE` then success | **once** | `ALLOW` | true | `returned` | `NONE` |
| Upstream tool returned `isError: true` | **once** | `ALLOW` | true | `returned` | `NONE` |
| Upstream timeout / drop / crash after send | **once (unknown)** | `ALLOW` | false | **`unknown`** | `SYSTEM_ERROR` |
| Nonce replay | no | `BLOCK` (`replay`) | false | `not_dispatched` | `RULE_VIOLATION` |

The last-but-one row is the case the issue flagged: **dispatch happened, so it cannot be `BLOCK`**.
`unknown` is not proof of a commit and not proof of absence; reconciliation is a later read, never an
automatic retry. See [outcome unknown](../operations/outcome-unknown.md).

---

## 6. Signed context handoff contract

The host attaches context in MCP request `_meta`. In stdio, `_meta` travels inside the JSON-RPC
message; the model never writes it, because the host builds the request.

```jsonc
{
  "name": "pay",
  "arguments": { "amount": 40, "currency": "EUR" },
  "_meta": {
    "adap/intent":     { /* full SignedIntent, as produced by signIntent() */ },
    "adap/delegation": [ /* SignedDelegation[], root first */ ],
    "adap/approval":   { /* optional: HumanApproval on resume */ }
  }
}
```

Proxy checks, in this order, all **before** the authority path:

1. `intent.action === server_id.tool_name` and `intent.target === mcp/<server_id>/<tool_name>`.
2. `intent.actor === mapping.expected_actor` (pinned per route; prevents an intent from one agent
   being replayed through another route).
3. Canonical equality of `intent.parameters` and `arguments` (RFC 8785 encoding of both, compared as
   bytes). Extra or missing keys both fail; `1` vs `1.0` is decided by the encoder, not by the proxy.
4. `intent.delegation_chain.length === chain.length` (the authority path re-checks, but we reject
   early with a clear reason).

Rejections here are `REFUSE`. If all four hold, the proxy calls:

```ts
executeAuthorized({
  chain, intent, approval, directory, policy, policyUri, policyResolver,
  ledger, pendingStore, signer, audience, rootAuthority, revocationCheck,
  approvalPolicy, mcpToolDefinitionHash: hashMcpToolDefinition(liveDefinition),
  broker, events,
})
```

`action`/`target` used for routing are re-derived by the proxy. They are additionally re-derived
inside `runAuthorityPath` (`authorityMcpCall`), so a mismatch is `BLOCK (mcp_binding)` even if the
proxy is wrong. That is defense in depth, not duplicated policy logic.

---

## 7. Trusted mapping format

Operator-owned, read-only, validated with `zod.strict()` at boot. Path via `ADAP_MCP_MAPPING_PATH`
(mirrors `ADAP_POLICY_BINDINGS_PATH`).

```jsonc
{
  "version": 1,
  "audience": "https://mcp-gw.internal",
  "servers": [
    {
      "server_id": "treasury",                 // [A-Za-z0-9_-]+, no "." or "/"
      "expected_actor": "agt_treasury_agent",  // intent.actor must equal this
      "transport": {
        "kind": "stdio",
        "command": "node",
        "args": ["/srv/mcp/treasury.js"],
        "env_from": ["TREASURY_API_TOKEN"]     // names only; values come from proxy env
      },
      "tools": {
        "pay": {
          "policy_uri": "mcp-treasury@1.0.0",
          "closed": true,                      // grant is expected to set closed:true
          "notes": "high risk: transfers money"
        },
        "lookup": { "policy_uri": "mcp-treasury-read@1.0.0" }
      }
    }
  ]
}
```

Rules:

- **No wildcards.** Every tool is named. An unlisted tool is not callable, even if the upstream
  advertises it (FR-3).
- **Duplicates are fatal.** Duplicate `server_id`, duplicate tool within a server, or a policy URI
  missing from the registry prevents startup.
- **`server_id` is operator data, never model data.** It is what prevents `mcp/<server>/<tool>`
  namespace confusion.
- **`policy_uri` selection is operator data.** The model cannot select a policy; the proxy takes it
  from this mapping only. Contrast with the HTTP gateway, which reads an optional header that must
  *agree* with a fixed binding.
- **`closed: true` is enforced by the authority path, not the proxy.** `constraints.closed === true`
  makes `validate.ts` reject any parameter key not declared by the grant's constraints, so the proxy
  must not maintain a second parameter allowlist. The flag here is documentation plus a
  boot-time consistency check on the grant when one is presented.
- **Transport credentials:** `env_from` names are resolved from the proxy's own environment and
  injected into the upstream child. Neither the value nor the child's full URL is ever written to a
  receipt, result, event or log.

Optional boot validation: for each configured tool, connect, `tools/list`, and record the pin. If the
upstream is unreachable at boot, the proxy still starts but marks that tool unavailable (fail closed
per call). A proxy that refuses to boot on an upstream outage turns an upstream failure into a
denial of service on the agent.

---

## 8. Approval lifecycle (`REQUIRE_HUMAN`)

```
policy REQUIRE_HUMAN
   │  path: pendingStore.put(...) + nonce reserve, receipt emitted
   ▼
proxy returns pending result  ──► model sees "approval required", upstream untouched
   │   _meta.adap = { decision:"REQUIRE_HUMAN", pending:true,
   │                  approvalRef:"apr_…", intentHash, expiresAt, matchedRuleId }
   ▼
operator plane (NOT an MCP tool)
   │  authenticated person reviews the exact intent + context
   │  signs HumanApproval{intent_hash, approver_id, decision, policy_content_hash, …}
   ▼
host retries the SAME tools/call with the SAME _meta intent + "adap/approval"
   │  approval APPROVE → path: verify bindings → re-evaluate pinned policy still REQUIRE_HUMAN
   │                     with same rule → claim nonce → dispatch ONCE → receipt human.status=approved
   └─ approval DENY    → path marks declined, retires nonce, receipt BLOCK, no dispatch
```

Decisions:

- **`approvalRef` is derived, not stored:** `apr_` + base64url(sha256(`actor \0 nonce \0 intentHash`))
  truncated to 32 chars. No new table, and it cannot be forged into a different intent.
- **The model cannot resume.** Resume requires (a) the operator's signature over the intent hash and
  (b) the same reserved nonce. A "retry" or `"approved": true` argument does nothing.
- **Approval is never exposed as a tool.** In M1 the approval plane is external to the proxy. The
  proxy only consumes a signed approval that arrives in `_meta`; it never advertises an approval
  operation in `tools/list`, so the model cannot call one.
- **Expiry:** the pending record expires with the intent (`expires_at`); an expired pending record
  cannot be approved. This is existing path behaviour, not new proxy logic.
- **An approval on a first call:** an approval presented without a matching pending record is
  `BLOCK (approval)` by the path. Expected.

---

## 9. Outcome semantics for the MCP surface

| Decision | MCP result shape |
| --- | --- |
| `ALLOW` | normal result; upstream `content` passed through; `_meta.adap = { decision, ruleId, receiptId, receiptHash, intentHash, correlationId, outcome }` |
| `ALLOW` + unknown | `isError: true`; text "downstream outcome unknown, do not retry with the same intent"; `_meta.adap.outcome = "unknown"` |
| `REQUIRE_HUMAN` | `isError: true`; text "human approval required"; `_meta.adap.pending = true` + `approvalRef` |
| `BLOCK` | `isError: true`; text with rule id + reason; `_meta.adap = { decision:"BLOCK", …, receiptId }` |
| `REFUSE` | `isError: true`; text with reason code; `_meta.adap = { refused:true, reason }`; **no receipt** |

Receipt delivery: M1 returns the receipt **inline** in `_meta` (it is already signed and
self-contained) and appends it to an optional append-only JSONL sink using the existing
`sequence`/`prevReceiptHash` chaining fields. A separate receipt-transport design is not needed for
M1.

---

## 10. Data model (ERD) — existing Postgres store, no migration

The proxy adds **no tables**. It reuses `adap-store-postgres` for the nonce ledger, pending
approvals, policy registry, revocation and the execution log, so the cross-process single-use
guarantee is the one the protocol already defines.

```
┌──────────────────────────────────────┐
│ adap_schema_migrations               │
│ id TEXT PK, applied_at TIMESTAMPTZ   │
└──────────────────────────────────────┘

┌───────────────────────────────────────────────┐        ┌──────────────────────────────────┐
│ adap_policies                                 │        │ adap_revoked_grants              │
│ PK (tenant_id, content_hash)                  │        │ PK (tenant_id, delegation_id)    │
│ uri TEXT UNIQUE (tenant_id, uri)              │        │ revoked_at TIMESTAMPTZ           │
│ body JSONB, revoked BOOL                      │        └──────────────────────────────────┘
└───────────────▲───────────────────────────────┘                  ▲
                │ policy_content_hash (logical)                    │ revocationCheck(delegation_id)
                │                                                  │
┌───────────────┴───────────────────────────────┐                  │
│ adap_pending                                  │                  │
│ PK (tenant_id, actor_id, nonce)               │                  │
│ intent_hash, principal_id, agent_id           │                  │
│ delegation_chain_hash                         │                  │
│ policy_uri, policy_content_hash,              │                  │
│ policy_version, policy_name                   │                  │
│ matched_rule_id, original_decision,           │                  │
│ approval_state, expiry, approver_id           │                  │
└───────────────┬───────────────────────────────┘                  │
                │ 1:1 on (tenant, actor, nonce)                    │
┌───────────────▼───────────────────────────────┐                  │
│ adap_nonces                                   │                  │
│ PK (tenant_id, actor_id, nonce)               │                  │
│ version INT, status{pending,consumed,failed}  │                  │
│ intent_hash, in_flight BOOL, updated_at       │                  │
└───────────────┬───────────────────────────────┘                  │
                │ 1:1 on (tenant, intent_hash)  (one intent = one nonce)
┌───────────────▼───────────────────────────────┐                  │
│ adap_execution_log                            │                  │
│ PK (tenant_id, intent_hash)                   │                  │
│ nonce, correlation_id                         │                  │
│ state{started,accepted,completed,             │                  │
│       failed,unknown,reconciled}              │                  │
│ detail, updated_at                            │                  │
└───────────────────────────────────────────────┘                  │
                                                                   │
   Authorization receipts are NOT stored: they are signed artifacts ┘
   held by the caller/auditor and verified offline with adap-receipt.
```

Notes that matter for the design:

- **No foreign keys, deliberately.** The store is append-only and must survive rollback; joins are by
  `intent_hash` / `nonce`, and rows are never deleted while an intent could still be presented.
- **`adap_nonces` is the execution mutex**, keyed by the *verified* actor, not by anything the model
  sent. `in_flight` closes the concurrent double-dispatch window.
- **`adap_pending` is the approval state machine**; the proxy reads it only through
  `PostgresPendingStore`. The 1:1 relation to `adap_nonces` is what makes "a reserved pending nonce
  cannot turn into a fresh `ALLOW`" true.
- **`adap_execution_log` is where `unknown` becomes reconcilable**, keyed by intent hash, which is why
  the proxy must return `correlationId` + `intentHash` to the host even on failure.
- **Single process without Postgres is a development mode only.** `MemoryAtomicNonceBackend` does not
  coordinate across workers; the package README must say so, as
  [`docs/architecture/reference.md`](../architecture/reference.md) already does.

---

## 11. Test matrix (M1)

| # | Scenario | Expected |
| --- | --- | --- |
| T1 | `ALLOW`, well-formed call | upstream invoked **exactly once**; receipt binds `execution.toolDefinitionHash`; `intentHash` returned |
| T2 | Policy `BLOCK` | upstream never called; receipt `executed:false`, `outcome: not_dispatched` |
| T3 | Policy `REQUIRE_HUMAN`, no approval | upstream never called; pending record bound to `intent_hash`; `approvalRef` stable across retries |
| T4 | `REQUIRE_HUMAN` → signed `APPROVE` → resume | upstream invoked once; receipt `human.status = approved`; second resume is `BLOCK (replay)` |
| T5 | `REQUIRE_HUMAN` → signed `DENY` | upstream never called; nonce retired; receipt `BLOCK` with human `declined` |
| T6 | Tool-definition drift (schema changed after grant) | `BLOCK (tool_definition)`; upstream never called; receipt records the presented hash |
| T7 | `intent.parameters` ≠ `tools/call` arguments | `REFUSE`; no receipt; upstream never called |
| T8 | Unknown / unmapped tool | `REFUSE`; upstream never called |
| T9 | Intent for server A presented to route B | `REFUSE` (`expected_actor` / action-target mismatch) |
| T10 | Replayed nonce | `BLOCK (replay)`; upstream not called a second time |
| T11 | Upstream times out **after** dispatch | `ALLOW`, `executed:false`, `outcome: unknown`, nonce consumed; MCP result `isError` with `outcome:"unknown"` |
| T12 | Upstream returns `isError: true` (tool-level error) | `ALLOW`, `outcome: returned`; upstream called once; error surfaced as a tool error |
| T13 | Missing/invalid signature, expired intent, revoked delegation | `BLOCK`; upstream never called; fail-closed code |
| T14 | Mapping file invalid / duplicate / unregistered policy | process refuses to start |
| T15 | Conformance vectors | `mcp-receipt-tool-def-binding` pin and binding match `examples/conformance/mcp-vectors.json`; `mcp-auth-*` behaviours reproduced end to end |
| T16 | No credential leakage | serialized MCP result, `_meta`, events and receipts contain no upstream token/URL |

Fake upstream: a small stdio MCP fixture with call counters, so "invoked exactly once" and "never
invoked" are assertions rather than inferences.

---

## 12. Frameworks and toolchain

| Concern | Choice | Why |
| --- | --- | --- |
| Language | TypeScript 6, ESM, `strict` | matches every existing package |
| Runtime | Node >= 22 | `engines` in every `package.json` |
| MCP | `@modelcontextprotocol/sdk` 1.32.x — `McpServer`, `StdioServerTransport` (entry), `Client` + `StdioClientTransport` (upstream) | official SDK; stdio is the only transport M1 needs |
| Schemas | `zod` v4 | already a dependency of `adap-gateway`; used for the mapping file |
| Tests | `vitest` 4 | repo standard, per-package `vitest.config.ts` |
| Monorepo | pnpm workspace + `workspace:*` | existing convention |
| Authority | `adap` (`runAuthorityPath`) + `adap-gateway` (`executeAuthorized`) | the issue's stated stable boundary |
| Store | `adap-store-postgres` (optional at dev, required for multi-process) | existing single-use guarantee |
| HTTP | none in M1 | stdio-only decision |

Planned package wiring: `packages/adap-mcp-proxy/package.json` with
`dependencies: { adap, adap-gateway, adap-policy, adap-receipt, @modelcontextprotocol/sdk, zod }`,
and `packages/adap-mcp-proxy` added to the root `build` / `test` / `typecheck` filters.

### Module layout

```
packages/adap-mcp-proxy/
  src/
    index.ts            public surface: config types, createProxy()
    config.ts           ADAP_MCP_MAPPING_PATH + zod strict schema, fail-closed boot
    mapping.ts          MappingResolver: tool → { action, target, policyUri, expectedActor }
    pin.ts              tool discovery snapshot + hashMcpToolDefinition + drift check
    context.ts          _meta parsing, ContextGuard (args == intent params, actor, action/target)
    broker.ts           McpUpstreamBroker implements CredentialBroker
    result.ts           decision → MCP result / _meta.adap mapping
    approvals.ts        approvalRef derivation + resume wiring
    server.ts           McpServer wiring over stdio
  test/
    proxy.test.ts       T1–T16 against a fake upstream
  README.md
```

---

## 13. Open questions

1. **`_meta` key namespace.** I propose `adap/intent`, `adap/delegation`, `adap/approval`. If you
   prefer a single base64url `adap/context` blob (less parsing surface, larger string), say so before
   implementation — it changes the public contract.
2. **Where the intent is signed.** This design assumes the host signs *after* the model proposes
   arguments, so the host is in the loop for every consequential call. If you expect the proxy to
   request a signature from a signing service instead, that is a different (and larger) contract.
3. **Tool-definition pinning across `tools/list_changed`.** M1 re-hashes before dispatch and refuses
   a tool that disappeared from the pinned snapshot. Should a changed definition instead invalidate
   the route until an operator re-issues grants, or is per-call `BLOCK (tool_definition)` enough?
4. **`REFUSE` without a receipt.** I deliberately do not emit a receipt for calls that never reached
   the authority path. Is a local, unsigned denial record enough for your evidence model, or do you
   want a signed "refused before evaluation" object?
5. **Upstream result binding** (still an open question in `spec/mcp-binding.md`): I am not hashing
   tool results in M1. If you want `execution.resultHash` as an extension, it is a small addition,
   but it makes receipts depend on upstream payload size.
6. **Approval plane.** M1 consumes a signed approval supplied by the host and ships no approval UI or
   listener. Confirm that is acceptable for a first PR, or say whether the proxy should own a
   separate authenticated resume endpoint.

**Resolved for M1:** the entry transport is **stdio only**. The host launches the proxy as a child
process, so there is no new network authentication surface. A loopback Streamable HTTP listener is a
later milestone for hosts that cannot launch a child process.

---

## 14. Milestones

| Milestone | Content | Output |
| --- | --- | --- |
| **M1 — this document** | Requirements, mapping format, handoff contract, failure semantics, test matrix | `docs/integrations/mcp-proxy.md` (design-first PR, no code) |
| **M2 — skeleton + core path** | `packages/adap-mcp-proxy`: config, mapping, pin, context guard, broker, stdio server; T1, T2, T6–T8, T13, T14 | PR with tests, `pnpm test` green |
| **M3 — approval lifecycle** | pending result, `approvalRef`, resume with signed approval; T3–T5 | PR |
| **M4 — outcomes + evidence** | timeout → `unknown`, receipt/`_meta` propagation, T9, T11, T12, T15, T16 | PR |
| **M5 — adoption** | runnable end-to-end example + README + mapping reference | docs PR |

### What this PR is

This branch lands the design only: this document and one index entry in
[`docs/README.md`](../README.md). The `packages/adap-mcp-proxy` skeleton follows in a separate pull
request after the design is accepted, which is the sequencing the issue asked for and keeps
"coordinate on the API before implementing a parallel authorization path" true.

### What would help most in review

- Confirm the `_meta` contract in §6, since it is the only new public interface.
- Confirm that refusing before the authority path (§5.3) is acceptable for the evidence model.
- Confirm the mapping format in §7 is the shape you want operators to maintain.
