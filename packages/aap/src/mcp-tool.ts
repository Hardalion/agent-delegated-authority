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
