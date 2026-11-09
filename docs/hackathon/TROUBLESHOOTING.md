# Troubleshooting

**The page says a team session is required.** Paste the team token from the console startup log. The token is not in the page source.

**Approval says the passphrase was not accepted.** Use `ADAP_APPROVER_PASSPHRASE` from startup. `treasury-demo` is rejected.

**Pay €750 did not create a payment.** That is the intended wait. Approve that nonce. A second approval does not create another payment.

**The label says OUTCOME UNKNOWN.** The sandbox did not answer before the timeout, or the answer was lost. Use Reconcile on that case. The console does not send the payment again. If the sandbox reports no row, the call was not committed. If it reports a `pay_` id, that row is the one that committed.

**Reset is refused.** `ADAP_DEMO_ENV` must be `hackathon`, `ADAP_PG_URL` must be unset, and the sandbox file path must contain `hackathon` or `demo` and must not look like production.

**The console will not bind to `0.0.0.0`.** That is intentional outside a container. Use a proxy. Inside Docker, set `ADAP_CONTAINER=1` and publish `127.0.0.1:4317:4317` on the host.

**Port 4317 is in use.** Set `ADAP_DEMO_PORT` and `SANDBOX_PORT` to a free pair.
