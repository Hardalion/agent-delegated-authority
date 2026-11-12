import { verifyAuthority, type SignedDelegation, type SignedIntent } from 'adap'
import { evaluateToolCall, type PolicyDecision } from 'adap-policy'
import type { Policy } from 'adap-policy'

/** Identity used by the copy-paste snippets. Teams replace this with their own. */
export const WEEKEND_AGENT = 'agt_hackathon_demo'

const READ_TOOLS = [
  'search_web',
  'scrape_url',
  'firecrawl_scrape',
  'read_page',
  'read_file',
  'list_files',
  'get_record',
  'query_database',
  'generate_draft',
  'generate_image',
] as const

const REVIEW_TOOLS = [
  'send_email',
  'send_message',
  'post_slack',
  'publish_post',
  'create_ticket',
  'update_crm',
  'book_calendar',
  'submit_form',
  'write_file',
] as const

const BLOCKED_TOOLS = [
  'delete_record',
  'drop_table',
  'transfer_funds',
  'send_payment',
  'wire_transfer',
  'read_secret',
  'export_credentials',
] as const

/**
 * Policy for tools a team invents during the GenAI Summit hackathon.
 * Research tools are allowed. Anything that leaves the machine waits for a person.
 * Deletes, payments, and secret access are blocked. An unlisted tool waits for a person.
 */
export const WEEKEND_POLICY: Policy = {
  version: '1.0.0',
  policyName: 'hackathon-weekend-agent',
  description:
    'GenAI Summit weekend policy. The agent proposes a tool call. ADAP decides before the tool runs. This is a sandbox policy for a 36-hour build, not a production authority pack.',
  targetAgents: [WEEKEND_AGENT],
  defaultAction: 'REQUIRE_HUMAN',
  rules: [
    {
      ruleId: 'block_dangerous',
      action: 'BLOCK',
      condition: `tool.name in [${BLOCKED_TOOLS.map((name) => `'${name}'`).join(', ')}]`,
      alertSeverity: 'CRITICAL',
    },
    {
      // Amount caps must name the tool first. A bare args.amount comparison fail-closes
      // every call that omits amount, including research tools.
      ruleId: 'block_payment_over_cap',
      action: 'BLOCK',
      condition: `tool.name in ['transfer_funds', 'send_payment', 'wire_transfer'] && args.amount > 500`,
      alertSeverity: 'CRITICAL',
    },
    {
      ruleId: 'review_side_effect',
      action: 'REQUIRE_HUMAN',
      condition: `tool.name in [${REVIEW_TOOLS.map((name) => `'${name}'`).join(', ')}]`,
      alertSeverity: 'MEDIUM',
    },
    {
      ruleId: 'read_allow',
      action: 'ALLOW',
      condition: `tool.name in [${READ_TOOLS.map((name) => `'${name}'`).join(', ')}]`,
      alertSeverity: 'LOW',
    },
  ],
}

export interface GateResult {
  readonly decision: PolicyDecision
  readonly executed: boolean
  readonly output: unknown
}

export interface NormalizedToolCall {
  readonly toolName: string
  readonly toolArgs: Record<string, unknown>
  readonly framework: string
}

/**
 * One shape for every framework the teams will bring.
 * OpenAI, LangChain, Vercel AI SDK, Claude, Gemini, CrewAI-style HTTP, and a raw tool call.
 */
export function normalizeToolCall(payload: unknown): NormalizedToolCall | { readonly error: string } {
  if (payload == null || typeof payload !== 'object' || Array.isArray(payload)) {
    return { error: 'tool call must be an object' }
  }
  const record = payload as Record<string, unknown>
  const fn = record.function
  if (fn != null && typeof fn === 'object' && !Array.isArray(fn)) {
    const call = fn as Record<string, unknown>
    const name = readName(call.name)
    const args = readArgs(call.arguments ?? call.args)
    if (!name || !args.ok) return { error: args.ok === false ? args.error : 'tool name is missing' }
    return { toolName: name, toolArgs: args.value, framework: 'openai-chat' }
  }
  const name = readName(record.name ?? record.toolName ?? record.tool)
  const args = readArgs(record.arguments ?? record.input ?? record.args ?? record.toolArgs ?? {})
  if (!name) return { error: 'tool name is missing' }
  if (!args.ok) return { error: args.error }
  const framework = frameworkOf(record)
  return { toolName: name, toolArgs: args.value, framework }
}

/**
 * Decide, then run the tool only when the decision is ALLOW.
 * agentRole is required. A missing identity does not fall through to a default.
 */
export async function gateTool(input: {
  readonly agentRole: string | undefined
  readonly toolName: string
  readonly toolArgs?: Record<string, unknown>
  readonly policy?: Policy
  readonly execute?: (toolName: string, toolArgs: Record<string, unknown>) => Promise<unknown> | unknown
}): Promise<GateResult> {
  const decision = evaluateToolCall({
    policy: input.policy ?? WEEKEND_POLICY,
    toolName: input.toolName,
    toolArgs: input.toolArgs ?? {},
    agentRole: input.agentRole,
  })
  if (decision.action !== 'ALLOW') {
    return { decision, executed: false, output: null }
  }
  if (input.execute == null) {
    return { decision, executed: false, output: null }
  }
  const output = await input.execute(input.toolName, input.toolArgs ?? {})
  return { decision, executed: true, output }
}

function readName(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 && value.length <= 80 ? value : null
}

function readArgs(value: unknown): { ok: true; value: Record<string, unknown> } | { ok: false; error: string } {
  if (value == null) return { ok: true, value: {} }
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value) as unknown
      if (parsed == null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return { ok: false, error: 'tool arguments must be an object' }
      }
      return { ok: true, value: parsed as Record<string, unknown> }
    } catch {
      return { ok: false, error: 'tool arguments are not valid JSON' }
    }
  }
  if (typeof value === 'object' && !Array.isArray(value)) {
    return { ok: true, value: value as Record<string, unknown> }
  }
  return { ok: false, error: 'tool arguments must be an object' }
}

/**
 * Drop-in wrap for a LangChain or LangGraph tool.
 * The original invoke/func runs only when ADAP returns ALLOW.
 * A refusal is returned to the agent as text. The tool body is not called.
 */
export async function wrapLangChainTool<T extends { name: string }>(
  tool: T,
  agentRole: string,
): Promise<T & { invoke: (input: unknown) => Promise<unknown> }> {
  const callable = tool as T & {
    invoke?: (input: unknown) => Promise<unknown> | unknown
    func?: (input: unknown) => Promise<unknown> | unknown
  }
  const original = callable.invoke?.bind(callable) ?? callable.func?.bind(callable)
  return {
    ...tool,
    invoke: async (input: unknown) => {
      const toolArgs = toolArgsFrom(input)
      const result = await gateTool({
        agentRole,
        toolName: tool.name,
        toolArgs,
        execute: original ? () => original(input) : undefined,
      })
      if (!result.executed) {
        return { executed: false, decision: result.decision }
      }
      return result.output
    },
  }
}

export interface NodeGate {
  readonly proceed: boolean
  readonly reason: string
  readonly decision?: PolicyDecision
}

/**
 * LangGraph node middleware.
 * A tool in the state is gated. A handoff to another agent proceeds only when
 * verifyAuthority accepts the signed delegation chain in that state.
 */
export function adapNode<S extends Record<string, unknown>>(
  node: (state: S) => Promise<S> | S,
  options: { readonly agentRole: string; readonly now?: Date },
): (state: S) => Promise<S & { adap?: NodeGate }> {
  return async (state: S) => {
    const gate = await inspectNode(state, options)
    if (!gate.proceed) {
      return { ...state, adap: gate }
    }
    const next = await node(state)
    return next
  }
}

export async function inspectNode(
  state: Record<string, unknown>,
  options: { readonly agentRole: string; readonly now?: Date },
): Promise<NodeGate> {
  const toolName = typeof state.toolName === 'string' ? state.toolName : typeof state.tool === 'string' ? state.tool : null
  if (toolName) {
    const toolArgs =
      state.toolArgs != null && typeof state.toolArgs === 'object' && !Array.isArray(state.toolArgs)
        ? (state.toolArgs as Record<string, unknown>)
        : state.args != null && typeof state.args === 'object' && !Array.isArray(state.args)
          ? (state.args as Record<string, unknown>)
          : {}
    const result = await gateTool({
      agentRole: options.agentRole,
      toolName,
      toolArgs,
    })
    if (result.decision.action !== 'ALLOW') {
      return { proceed: false, reason: result.decision.reason, decision: result.decision }
    }
  }
  const fromAgent = typeof state.fromAgent === 'string' ? state.fromAgent : null
  const toAgent = typeof state.toAgent === 'string' ? state.toAgent : null
  if (fromAgent && toAgent && fromAgent !== toAgent) {
    const handoff = verifyHandoff(state, options.now ?? new Date())
    if (!handoff.ok) return { proceed: false, reason: handoff.reason }
  }
  return { proceed: true, reason: 'allowed' }
}

/** Cryptographic check. A missing or invalid chain does not proceed. */
export function verifyHandoff(
  state: Record<string, unknown>,
  now: Date,
): { ok: true } | { ok: false; reason: string } {
  const chain = state.chain
  const intent = state.intent
  const directory = state.directory
  if (!Array.isArray(chain) || chain.length === 0 || intent == null || !(directory instanceof Map)) {
    return { ok: false, reason: 'delegation chain required' }
  }
  try {
    verifyAuthority({
      chain: chain as SignedDelegation[],
      intent: intent as SignedIntent,
      directory: directory as Map<string, string>,
      now,
    })
    return { ok: true }
  } catch (error) {
    const reason = error instanceof Error ? error.message : 'delegation rejected'
    return { ok: false, reason }
  }
}

function toolArgsFrom(input: unknown): Record<string, unknown> {
  if (input != null && typeof input === 'object' && !Array.isArray(input)) {
    return input as Record<string, unknown>
  }
  return { input }
}

function frameworkOf(record: Record<string, unknown>): string {
  if ('input' in record) return 'anthropic'
  if ('arguments' in record) return 'openai'
  if ('toolName' in record || 'toolArgs' in record) return 'adap'
  if ('tool' in record) return 'http'
  if ('args' in record) return 'langchain'
  return 'tool-call'
}
