# adap-policy

Reference implementation of the [ADAP](https://github.com/hardalion/agent-delegated-authority) policy evaluator.

Apache 2.0. Reference implementation maintained by Hardalion. The package name is not part of the protocol.

## CLI

The package is not currently published to npm. From a clone of this repository, after `pnpm build`:

```bash
node packages/policy-engine/dist/cli.js --help
node packages/policy-engine/dist/cli.js --tool apply --args "{\"amount\":800}" --json
node packages/policy-engine/dist/cli.js --policy-file ./policy.yaml --tool read
```

Exit code `1` = `BLOCK`. Exit code `0` = allowed or requires human review.

## Programmatic

```typescript
import { evaluateToolCall } from 'adap-policy'

const decision = evaluateToolCall({
  policy: 'basic-agent-authority',
  toolName: 'apply',
  toolArgs: { amount: 800 },
})
```

## Bundled example

`basic-agent-authority` demonstrates protocol semantics. Pin: `basic-agent-authority@1.0.0`.

Specification: [github.com/hardalion/agent-delegated-authority](https://github.com/hardalion/agent-delegated-authority)
