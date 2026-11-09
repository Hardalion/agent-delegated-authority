# Known limitations

1. The signed receipt can say `execution.executed: true` when the downstream call times out. The console label is OUTCOME UNKNOWN and the case `executed` flag is false until a completed result or a reconcile read. Changing the receipt requires a kernel decision. `security/execution-semantics` was not merged into this branch.

2. One console process handles one team and serializes decisions on an in-process lock. Pending approvals and the nonce ledger are lost if the process restarts. A restarted process will not execute an approval that only the old process knew about. That behavior is tested.

3. Hosted mode is specified and covered by config tests. Docker Desktop's daemon was not running, so the image was not built or started here. GitHub Actions was not run for this commit because the branch was not pushed.

4. The load sample is 20 concurrent status reads on one team, four waves. p50 109.4 ms and p95 285.1 ms include queue wait. A larger event profile was not invented and was not run.

5. The sandbox uses `node:sqlite`, which prints an experimental warning on Node.js 22.19.0. Fault injection exists only when `SANDBOX_FAULTS=1`. The participant start script sets it to 0.

6. The in-memory rail is still present when `ADAP_SANDBOX_URL` is unset. The page says "Process memory" in that mode. `pnpm hackathon:start` sets the sandbox URL.

7. Vendor changes and purchases are sandbox workflows. The original memory scenario `beneficiary` is still BLOCK and still has no broker route. That is the previous demo behavior, kept for the memory rail.

8. Postgres integration tests were not run. The hackathon path does not use `ADAP_PG_URL`.
