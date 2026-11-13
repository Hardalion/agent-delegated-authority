# ADAP hackathon console

Participant sandbox for the Gen AI Summit. An agent proposes an action. Deterministic ADAP policy decides. A permitted action is sent to a local sandbox API that stores synthetic EUR records. This process does not transfer real money.

Supported runtime: Node.js 22.19.0 and pnpm 10.15.1.

## Install

From the repository root:

```bash
pnpm install --frozen-lockfile
```

## Start

```bash
pnpm hackathon:start
```

The process binds to `127.0.0.1:4317` and starts a sandbox API on `127.0.0.1:4318`. If team credentials are not set, they are printed once and are not written to disk. There is no default password.

## Test

```bash
pnpm hackathon:test
```

## Reset

With the console already running, and with `ADAP_TEAM_TOKEN` and `ADAP_APPROVER_PASSPHRASE` set to the values from startup:

```bash
pnpm hackathon:reset
```

Reset exports evidence, then clears only this team's sandbox database. The database path must contain `hackathon` or `demo`.

## Mode

Local participant mode is the supported hackathon path: loopback only, one team's synthetic state. See [docs/HACKATHON-QUICKSTART.md](../../docs/HACKATHON-QUICKSTART.md).

The page label comes from the server. `Process memory` means the simulated rail. `Local sandbox API` means SQLite records in the sandbox process.
