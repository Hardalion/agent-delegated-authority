# Known limitations

1. One console process handles one team and serializes decisions on an in-process lock. With durable SQLite state enabled (default for `pnpm hackathon:start` / hosted compose), identities, nonces, pending approvals, cases, and receipt chain metadata survive restart. In-memory sessions still do not; participants must sign in again after a restart. Without a durable store (unit-test mode), pending approvals are lost on restart.

1b. Human approval identity is a shared-secret operator gate, not an independently authenticated person. The approve route requires a team session (or team bearer) plus the approver passphrase. After those checks pass, the console signs `HumanApproval` with `approver_id = prn_treasury` using the process-held principal key. ADAP requires `approver_id` to equal the delegating principal. There is no separate human login, OIDC subject, or personal approver key. Wrong passphrase is rejected without execution. See `apps/hackathon-console/src/approval-identity.test.ts`.

2. The hosted compose stack was built and started once on this machine, checked, and stopped. It is not left running and it was not published beyond `127.0.0.1`. GitHub Actions runs when this branch is pushed. The result for a commit is that commit's Actions run, not a claim made in advance.

3. The load sample is 20 concurrent status reads on one team, four waves. p50 109.4 ms and p95 285.1 ms include queue wait. A larger event profile was not invented and was not run.

4. The sandbox uses `node:sqlite`, which prints an experimental warning on Node.js 22.19.0. Fault injection exists only when `SANDBOX_FAULTS=1`. The participant start script sets it to 0.

5. The in-memory rail is still present when `ADAP_SANDBOX_URL` is unset. The page says "Process memory" in that mode. `pnpm hackathon:start` sets the sandbox URL.

6. Vendor changes and purchases are sandbox workflows. The original memory scenario `beneficiary` is still BLOCK and still has no broker route. That is the previous demo behavior, kept for the memory rail.

7. The hackathon path does not use `ADAP_PG_URL`. The Postgres store suite runs in CI and is not part of the participant sandbox.
