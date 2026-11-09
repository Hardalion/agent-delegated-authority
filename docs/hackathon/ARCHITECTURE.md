# Architecture

The event model is one console process and one sandbox process per team. A shared multi-tenant process was not used. Isolation is the process boundary plus a team session checked on every protected route.

## Local participant mode

`pnpm hackathon:start` binds both processes to `127.0.0.1`. The sandbox listens on port 4318 and stores synthetic rows in SQLite (`node:sqlite`). The console listens on port 4317. Credentials are environment variables. If they are missing, local mode generates them and prints them once. `treasury-demo` is rejected.

The browser opens a session with `POST /api/session`. The cookie is HttpOnly and SameSite=Strict. Mutations also require `x-adap-request: 1` and a matching `Origin` when an origin is sent. The team token is not written into `app.js`.

## Hosted event mode

`ADAP_DEPLOYMENT=hosted` refuses to start unless the team id, team token, approver passphrase, session secret, sandbox URL, and sandbox token are present and long enough. The default bind is `127.0.0.1`. `0.0.0.0` is allowed only when `ADAP_CONTAINER=1`, so a published Docker port can reach the process. The compose file publishes `127.0.0.1` on the host. Put TLS on a reverse proxy. Do not publish the container port on a public interface.

Each team gets its own `SANDBOX_DB` file. Reset calls only that process's sandbox, and the sandbox refuses a path that does not contain `hackathon` or `demo`.

## Execution path

`Agent intent → signed by the registered treasury agent → delegation and policy in @adap → human approval when required → broker → HTTP adapter → sandbox SQLite → receipt`.

The adapter does not retry a POST. A timeout is `unknown`. `POST /api/cases/:id/reconcile` reads `GET /v1/reconcile/:intentHash` and does not send the side effect again.

Policy for the sandbox is `hackathon-sandbox-authority` 1.1.0. €120 is ALLOW. €750 is REQUIRE_HUMAN. €6,000 is BLOCK. Vendor account changes are REQUIRE_HUMAN. Restricted purchases are BLOCK. The in-memory rail and its original treasury policy remain available when no sandbox URL is configured. The page label says which one is attached.

## Unknown downstream results

When the executor returns `{ executionState: 'unknown' }`, the authority path keeps decision `ALLOW`, sets `execution.executed` to false, writes `extensions.executionState = unknown` on the signed receipt, and consumes the nonce. The same intent is not sent again. `executed: false` means the side effect is not confirmed. It is not a `BLOCK`, and it is not a claim that the downstream system prevented the effect. Reconcile is a later read.
