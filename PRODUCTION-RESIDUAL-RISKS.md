# PRODUCTION-RESIDUAL-RISKS

| Risk | Severity | Why remaining | Owner |
| --- | --- | --- | --- |
| Agent holds rail credentials or can reach the write URL | Critical | Staging blocked an agent that was only on the edge network. An agent given the rail token or the trust network is outside that proof | Platform |
| Split-brain Postgres (two writable primaries) | Critical | Would break nonce exclusion | SRE |
| External security retest not done | High | Staging gate 10 is open. Package is `EXTERNAL-RETEST-PACKAGE.md` | Security |
| Gateway with a live pool connection still authorizes when new Postgres clients are refused | Medium | Observed: `executed: true` and `sorry, too many clients already` in the same staging check | SRE |
| `docker pause` of Postgres lets an in-flight statement commit on resume | Medium | Caller timed out; nonce ended `consumed`; retry was `BLOCK`. One commit, not two | SRE |
| Vault dev mode | High | In-memory, root token in the Vault container environment, no HA | Platform |
| Identity directory is operator-managed, not an IdP | Medium | Forged keys possible if directory is wrong | Identity ops |
| Clock manipulation on gateway host | Medium | Zero skew; host NTP assumed | SRE |
| Downstream `outcome_unknown` | Medium | Honest semantics; needs reconciliation runbooks | App + SRE |
| Multi-tenancy is store namespacing only | Medium | Not a full SaaS isolation product | Product |

## Claim ceiling

Do not say “production ready.”
Staging gates 1–9 passed on this host. External retest has not been done. Vault is dev mode. One Postgres primary.
