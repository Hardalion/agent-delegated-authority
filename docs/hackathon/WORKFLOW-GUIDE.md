# Workflow guide

Amounts are integer euro cents. €120 is `12000`. €750 is `75000`. €6,000 is `600000`. The sandbox currency is EUR. No workflow moves real money.

| Workflow | Policy | Downstream |
|---|---|---|
| Read `pay_seed_1001` | ALLOW | One GET, resource id returned |
| Pay €120 | ALLOW | One persisted payment |
| Pay €750 | REQUIRE_HUMAN | No POST until approval, then exactly one |
| Reject €750 | REQUIRE_HUMAN then rejected | No payment row |
| Pay €6,000 | BLOCK | Zero payment POSTs |
| Vendor account change | REQUIRE_HUMAN | Record unchanged until approval, then one change |
| Office purchase €100 | ALLOW | One purchase row |
| Office purchase €800 | REQUIRE_HUMAN | No purchase until approval |
| Restricted purchase | BLOCK | No purchase row |
| Same nonce again | BLOCK replay | No second side effect |
| Timeout before commit | UNKNOWN | Sandbox has no new row. The POST is not retried |
| Timeout after commit | UNKNOWN until reconcile | One row. Reconcile reads it and does not POST again |
| Unknown or malformed agent | Denied | No sandbox write |

The signed receipt can still say `execution.executed: true` when the downstream result is unknown. That is a kernel limitation on this branch. The console label stays OUTCOME UNKNOWN, and `executed` on the case is false until a completed downstream result or a reconcile read confirms the row. See `docs/hackathon/KNOWN-LIMITATIONS.md`.

Starter examples:

```bash
pnpm --filter adap-policy build
node hackathon-starter.mjs
node --experimental-strip-types hackathon-starter.ts
```

Both pass `agentRole` explicitly. A missing, malformed, or unknown agent is BLOCK.
