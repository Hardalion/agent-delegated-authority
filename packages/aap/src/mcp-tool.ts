import type { AuthorizationReceiptV1 } from 'adap-receipt'
import { sha256 } from './crypto.js'

/** Server ids cannot contain `.` or `/`, so `server.tool` does not collide with a dotted tool name. */
const SERVER_ID = /^[A-Za-z0-9_-]+$/

export interface McpToolDefinition {
  readonly server_id: string
  readonly tool_name: string
  readonly description: string
  /** MCP `inputSchema`. */
  readonly input_schema: unknown
  readonly title?: string
  readonly icons?: unknown
  /** MCP `outputSchema`. */
  readonly output_schema?: unknown
  readonly annotations?: unknown
}

function assertServerId(serverId: string): void {
  if (!SERVER_ID.test(serverId)) {
    throw new Error('mcp server_id must match [A-Za-z0-9_-]+ and must not contain "." or "/"')
  }
}

/**
 * SHA-256 of the RFC 8785 encoding of the pinned tool definition.
 * Absent optional fields are omitted. Present `title`, `icons`, `output_schema`,
 * and `annotations` are part of the preimage, so a change to any of them changes the pin.
 */
export function hashMcpToolDefinition(definition: McpToolDefinition): string {
  assertServerId(definition.server_id)
  const body: Record<string, unknown> = {
    description: definition.description,
    input_schema: definition.input_schema,
    server_id: definition.server_id,
    tool_name: definition.tool_name,
  }
  if (definition.annotations !== undefined) body.annotations = definition.annotations
  if (definition.icons !== undefined) body.icons = definition.icons
  if (definition.output_schema !== undefined) body.output_schema = definition.output_schema
  if (definition.title !== undefined) body.title = definition.title
  return `sha256:${sha256(body)}`
}

export type AuthorityMcpCall =
  | { readonly kind: 'not-mcp' }
  | { readonly kind: 'malformed'; readonly reason: string }
  | { readonly kind: 'call'; readonly serverId: string; readonly toolName: string }

/**
 * Classify a presented action and target. Anything under `mcp/` is an
 * authority-enforcing MCP call and must use `mcp/<server_id>/<tool_name>`
 * with `server_id` matching `[A-Za-z0-9_-]+`. A dot or slash in `server_id`,
 * an empty segment, or an action that is not `server_id.tool_name` is malformed.
 */
export function authorityMcpCall(action: string, target: string): AuthorityMcpCall {
  if (!target.startsWith('mcp/')) return { kind: 'not-mcp' }
  const parts = target.split('/')
  if (parts.length !== 3 || parts[0] !== 'mcp') {
    return { kind: 'malformed', reason: 'mcp target must be mcp/<server_id>/<tool_name>' }
  }
  const serverId = parts[1] ?? ''
  const toolName = parts[2] ?? ''
  if (!SERVER_ID.test(serverId)) {
    return {
      kind: 'malformed',
      reason: 'mcp server_id must match [A-Za-z0-9_-]+ and must not contain "." or "/"',
    }
  }
  if (toolName.length === 0) {
    return { kind: 'malformed', reason: 'mcp tool_name must be non-empty and must not contain "/"' }
  }
  if (action !== `${serverId}.${toolName}`) {
    return { kind: 'malformed', reason: 'mcp action must be server_id.tool_name' }
  }
  return { kind: 'call', serverId, toolName }
}

/** `server_id.tool_name` is the action. `mcp/<server_id>/<tool_name>` is the target. */
export function adapBindingForMcpCall(serverId: string, toolName: string): {
  readonly action: string
  readonly target: string
} {
  assertServerId(serverId)
  if (toolName.length === 0 || toolName.includes('/')) {
    throw new Error('mcp tool_name must be non-empty and must not contain "/"')
  }
  return {
    action: `${serverId}.${toolName}`,
    target: `mcp/${serverId}/${toolName}`,
  }
}

/**
 * Offline check that a receipt was issued for this MCP tool definition.
 *
 * Passes only when `execution.toolDefinitionHash` equals `hashMcpToolDefinition(definition)`,
 * and the receipt's `intent.toolName` and `execution.targetSystem` are the action and target
 * derived from the definition's server and tool name.
 *
 * This does not check the receipt signature. Verify the receipt with the issuer public key first.
 */
export function verifyReceiptMcpToolBinding(
  receipt: Pick<AuthorizationReceiptV1, 'intent' | 'execution'>,
  definition: McpToolDefinition,
): { readonly valid: boolean; readonly errors: readonly string[] } {
  const errors: string[] = []
  let expected: string | undefined
  let binding: { readonly action: string; readonly target: string } | undefined
  try {
    expected = hashMcpToolDefinition(definition)
    binding = adapBindingForMcpCall(definition.server_id, definition.tool_name)
  } catch {
    errors.push('tool definition is malformed or could not be canonicalized')
  }
  const bound = receipt.execution?.toolDefinitionHash
  if (bound === undefined) {
    errors.push('receipt does not bind a tool definition')
  } else if (expected !== undefined && bound !== expected) {
    errors.push('receipt binds a different tool definition')
  }
  if (binding !== undefined) {
    if (receipt.intent.toolName !== binding.action) {
      errors.push(`receipt action is not ${binding.action}`)
    }
    if (receipt.execution?.targetSystem !== binding.target) {
      errors.push(`receipt target is not ${binding.target}`)
    }
  }
  return { valid: errors.length === 0, errors }
}
