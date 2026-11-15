#!/usr/bin/env node
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { evaluateToolCall, loadPolicyFromFile, type PolicyDecision } from './engine.js'
import { resolvePolicyRegistryEntry } from './registry/catalog.js'
import { parsePolicyPin } from './registry/uri.js'
import { CANONICAL_BASIC_AGENT_AUTHORITY } from './schema.js'

export interface PolicyEvalCliInput {
  readonly toolName: string
  readonly toolArgs?: Record<string, unknown>
  readonly agentRole?: string
  readonly policy?: string
  readonly policyFile?: string
  readonly policyUri?: string
  readonly json?: boolean
}

export function parsePolicyEvalArgs(argv: string[]): PolicyEvalCliInput {
  const args = argv.filter((a) => a !== '--')
  if (args.includes('-h') || args.includes('--help')) {
    throw new Error('help')
  }

  const toolIdx = args.indexOf('--tool')
  if (toolIdx === -1 || !args[toolIdx + 1]) {
    throw new Error('missing_tool')
  }

  const policyIdx = args.indexOf('--policy')
  const policyFileIdx = args.indexOf('--policy-file')
  const policyUriIdx = args.indexOf('--policy-uri')
  const argsIdx = args.indexOf('--args')
  const agentIdx = args.indexOf('--agent')

  let toolArgs: Record<string, unknown> | undefined
  if (argsIdx !== -1 && args[argsIdx + 1]) {
    toolArgs = JSON.parse(args[argsIdx + 1]!) as Record<string, unknown>
  }

  return {
    toolName: args[toolIdx + 1]!,
    toolArgs,
    agentRole: agentIdx !== -1 ? args[agentIdx + 1] : undefined,
    policy: policyIdx !== -1 ? args[policyIdx + 1] : undefined,
    policyFile: policyFileIdx !== -1 ? args[policyFileIdx + 1] : undefined,
    policyUri: policyUriIdx !== -1 ? args[policyUriIdx + 1] : undefined,
    json: args.includes('--json'),
  }
}

export async function runPolicyEval(input: PolicyEvalCliInput): Promise<PolicyDecision> {
  let policy: string | ReturnType<typeof loadPolicyFromFile> =
    input.policy ?? CANONICAL_BASIC_AGENT_AUTHORITY

  if (input.policyFile) {
    policy = loadPolicyFromFile(resolve(input.policyFile))
  } else if (input.policyUri) {
    const pin = parsePolicyPin(input.policyUri)
    const entry = resolvePolicyRegistryEntry(pin)
    if (!entry) {
      return {
        matched: true,
        action: 'BLOCK',
        ruleId: 'PIN_UNRESOLVED',
        reason: `Policy pin ${input.policyUri} could not be resolved from a local document`,
        alertSeverity: 'CRITICAL',
      }
    }
    policy = entry.policy
  }

  return evaluateToolCall({
    policy,
    toolName: input.toolName,
    toolArgs: input.toolArgs,
    agentRole: input.agentRole,
  })
}

function printUsage(): never {
  console.error(`Usage: adap-policy --tool <name> [options]

Evaluate a policy against a tool call. The bundled example resolves locally.

Options:
  --policy <id>           Bundled policy id (default: basic-agent-authority)
  --policy-file <path>    Load policy from YAML/JSON file
  --policy-uri <pin>      Resolve {policy-id}@{semver} from the local example catalog
  --args <json>           Tool arguments as JSON object
  --agent <role>          Agent role for targetAgents scoping
  --json                  Print full decision JSON

Examples:
  adap-policy --tool apply --args "{\\"amount\\":800}"
  adap-policy --tool read
  adap-policy --policy-file ./my-policy.yaml --tool apply
  adap-policy --policy-uri basic-agent-authority@1.0.0 --tool read`)
  process.exit(2)
}

async function main() {
  try {
    const input = parsePolicyEvalArgs(process.argv.slice(2))
    const decision = await runPolicyEval(input)

    if (input.json) {
      console.log(JSON.stringify(decision, null, 2))
    } else {
      console.log(`action: ${decision.action}`)
      console.log(`ruleId: ${decision.ruleId}`)
      console.log(`matched: ${decision.matched}`)
      console.log(`reason: ${decision.reason}`)
      console.log(`alertSeverity: ${decision.alertSeverity}`)
    }

    process.exit(decision.action === 'BLOCK' ? 1 : 0)
  } catch (error) {
    if (error instanceof Error && error.message === 'help') printUsage()
    if (error instanceof Error && error.message === 'missing_tool') printUsage()
    console.error(error instanceof Error ? error.message : String(error))
    process.exit(2)
  }
}

const entryPath = process.argv[1] ? resolve(process.argv[1]) : ''
const isDirectRun = entryPath === fileURLToPath(import.meta.url)

if (isDirectRun) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error))
    process.exit(2)
  })
}
