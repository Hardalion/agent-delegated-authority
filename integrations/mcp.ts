import { McpToolGate, type McpToolCall, type McpToolResult } from 'adap-policy'

/**
 * Example policy-only MCP gate. Not a full ADAP authority binding.
 * See `spec/mcp-binding.md` for signed intent, delegation, and receipt requirements.
 */
export class McpAgentAuthorityGate {
  private readonly gate: McpToolGate

  constructor(policy = 'basic-agent-authority', agentRole = 'agt_reader') {
    this.gate = new McpToolGate({ policy, agentRole })
  }

  /**
   * Handle an MCP CallToolRequest:
   * 1. Evaluates toolName and arguments against ADAP policy.
   * 2. Returns structured MCP error without invoking tool if unauthorized.
   * 3. Invokes handler and returns MCP content on ALLOW.
   */
  async handleToolCall(
    call: McpToolCall,
    handler: (args: Record<string, unknown>) => Promise<unknown>
  ): Promise<McpToolResult> {
    return this.gate.execute(call, handler)
  }
}
