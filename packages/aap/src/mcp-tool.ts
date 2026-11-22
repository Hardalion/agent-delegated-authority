import { sha256 } from './crypto.js'

export interface McpToolDefinition {
  readonly server_id: string
  readonly tool_name: string
  readonly description: string
  readonly input_schema: unknown
}

/** SHA-256 of the RFC 8785 encoding of the pinned tool definition. */
export function hashMcpToolDefinition(definition: McpToolDefinition): string {
  return `sha256:${sha256({
    server_id: definition.server_id,
    tool_name: definition.tool_name,
    description: definition.description,
    input_schema: definition.input_schema,
  })}`
}

/** `server_id.tool_name` is the action. `mcp/<server_id>/<tool_name>` is the target. */
export function adapBindingForMcpCall(serverId: string, toolName: string): {
  readonly action: string
  readonly target: string
} {
  return {
    action: `${serverId}.${toolName}`,
    target: `mcp/${serverId}/${toolName}`,
  }
}
