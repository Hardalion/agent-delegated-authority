# Known limitations

1. One console process handles one team and serializes decisions on an in-process lock. Pending approvals and the nonce ledger are lost if the process restarts. A restarted process will not execute an approval that only the old process knew about. That behavior is tested.

2. The hosted compose stack was built and started once on this machine, checked, and stopped. It is not left running and it was not published beyond `127.0.0.1`. GitHub Actions runs when this branch is pushed. The result for a commit is that commit's Actions run, not a claim made in advance.

3. The load sample is 20 concurrent status reads on one team, four waves. p50 109.4 ms and p95 285.1 ms include queue wait. A larger event profile was not invented and was not run.

4. The sandbox uses `node:sqlite`, which prints an experimental warning on Node.js 22.19.0. Fault injection exists only when `SANDBOX_FAULTS=1`. The participant start script sets it to 0.

5. The in-memory rail is still present when `ADAP_SANDBOX_URL` is unset. The page says "Process memory" in that mode. `pnpm hackathon:start` sets the sandbox URL.

6. Vendor changes and purchases are sandbox workflows. The original memory scenario `beneficiary` is still BLOCK and still has no broker route. That is the previous demo behavior, kept for the memory rail.

7. Postgres integration tests were not run. The hackathon path does not use `ADAP_PG_URL`.
