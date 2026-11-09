# Quickstart

Node.js 22.19.0. pnpm 10.15.1.

```bash
git clone https://github.com/Hardalion/agent-delegated-authority.git
cd agent-delegated-authority
git checkout hackathon/participant-sandbox
pnpm install --frozen-lockfile
pnpm hackathon:start
```

Open `http://127.0.0.1:4317`. Paste the printed team token. Use the printed approver passphrase only when a decision says it is waiting for a person.

First workflow: run **Pay €120**. The decision is ALLOW and the sandbox returns a `pay_` id. Then run **Pay €750**. Nothing is sent until you approve that same intent. **Pay €6,000** is BLOCK and the sandbox payment count does not increase.

Stop the process with Ctrl+C. Reset with `pnpm hackathon:reset` while it is running.

`pnpm hackathon:test` runs the console suite, including the sandbox API workflows.
