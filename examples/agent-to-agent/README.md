# Agent to agent (reference walkthrough)

Reference implementation. Not normative.

Synthetic identifiers: `prn_example`, `agt_a`, `agt_b`, `resource/example`.

```
Principal → Agent A → Agent B → authorized action → receipt
```

Agent B may read. Apply stays with Agent A and waits for the principal. The child grant is narrower than the parent grant.

```bash
pnpm demo
```

The example policy is [../policies/basic-agent-authority.yaml](../policies/basic-agent-authority.yaml). Unsigned bodies: [../delegation.json](../delegation.json), [../intent.json](../intent.json), [../receipt.json](../receipt.json).
