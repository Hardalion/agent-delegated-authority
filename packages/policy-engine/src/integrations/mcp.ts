import { evaluateToolCall, type PolicyDecision } from '../engine.js'

/**
 * Represents an incoming tool call in the Model Context Protocol (MCP).
 */
export interface McpToolCall {
  readonly name: string
  readonly arguments?: Record<string, unknown>
}

/**
 * Standard content item returned in an MCP tool execution result.
 */
export interface McpContentItem {
  readonly type: 'text' | 'image' | 'resource'
  readonly text?: string
  readonly data?: string
  readonly mimeType?: string
}

/**
 * Standard tool execution result payload in the Model Context Protocol (MCP).
 */
export interface McpToolResult {
  readonly content: readonly McpContentItem[]
  readonly isError?: boolean
  readonly _meta?: Record<string, unknown>
}

/**
 * Configuration options for the ADAP MCP tool execution gate.
 */
export interface McpToolGateOptions {
  /**
   * Pinned policy name or file URI (for example, 'basic-agent-authority').
   */
  readonly policy: string

  /**
   * Optional agent role identity passed to the policy evaluator (e.g., 'agt_reader').
   */
  readonly agentRole?: string

  /**
   * If true, throws an Error on BLOCK or REQUIRE_HUMAN decisions instead of returning
   * an McpToolResult with isError: true. Defaults to false.
   */
  readonly throwOnError?: boolean
}

/**
 * Policy-only MCP helper. Evaluates tool name/args against an ADAP policy document.
 *
 * This is not a full ADAP authority binding: it does not verify signed intents,
 * delegation chains, capability minting, single-use execution, or Authorization Receipts.
 * See `spec/mcp-binding.md` for the normative authority-enforcing MCP profile.
 */
export class McpToolGate {
  constructor(private readonly options: McpToolGateOptions) {}

  /**
   * Evaluates an incoming tool call without executing the underlying tool.
   */
  evaluate(call: McpToolCall): PolicyDecision {
    return evaluateToolCall({
      policy: this.options.policy,
      toolName: call.name,
      toolArgs: call.arguments ?? {},
      agentRole: this.options.agentRole,
    })
  }

  /**
   * Guards the execution of an MCP tool call.
   *
   * On ALLOW: invokes the provided tool executor and attaches ADAP decision metadata.
   * On BLOCK: halts execution immediately without calling the executor, returning an error payload.
   * On REQUIRE_HUMAN: halts execution and requests human intervention.
   */
  async execute<T = unknown>(
    call: McpToolCall,
    executor: (args: Record<string, unknown>) => Promise<T> | T
  ): Promise<McpToolResult> {
    const args = call.arguments ?? {}
    const decision = this.evaluate(call)

    if (decision.action === 'BLOCK') {
      if (this.options.throwOnError) {
        throw new Error(`[ADAP BLOCK] Execution refused by rule '${decision.ruleId}': ${decision.reason}`)
      }
      return {
        isError: true,
        content: [
          {
            type: 'text',
            text: `[ADAP BLOCK] Execution refused by rule '${decision.ruleId}': ${decision.reason}`,
          },
        ],
        _meta: {
          adap: {
            action: decision.action,
            ruleId: decision.ruleId,
            reason: decision.reason,
            alertSeverity: decision.alertSeverity,
          },
        },
      }
    }

    if (decision.action === 'REQUIRE_HUMAN') {
      if (this.options.throwOnError) {
        throw new Error(
          `[ADAP REQUIRE_HUMAN] Human approval required before tool execution by rule '${decision.ruleId}': ${decision.reason}`
        )
      }
      return {
        isError: true,
        content: [
          {
            type: 'text',
            text: `[ADAP REQUIRE_HUMAN] Human approval required before tool execution by rule '${decision.ruleId}': ${decision.reason}`,
          },
        ],
        _meta: {
          adap: {
            action: decision.action,
            ruleId: decision.ruleId,
            reason: decision.reason,
            alertSeverity: decision.alertSeverity,
            deferred: true,
          },
        },
      }
    }

    // On ALLOW: proceed to execute the underlying tool
    const rawResult = await executor(args)

    if (
      typeof rawResult === 'object' &&
      rawResult !== null &&
      'content' in rawResult &&
      Array.isArray((rawResult as McpToolResult).content)
    ) {
      const existingResult = rawResult as McpToolResult
      return {
        ...existingResult,
        _meta: {
          ...(existingResult._meta ?? {}),
          adap: {
            action: 'ALLOW',
            ruleId: decision.ruleId,
            alertSeverity: decision.alertSeverity,
          },
        },
      }
    }

    return {
      isError: false,
      content: [
        {
          type: 'text',
          text: typeof rawResult === 'string' ? rawResult : JSON.stringify(rawResult),
        },
      ],
      _meta: {
        adap: {
          action: 'ALLOW',
          ruleId: decision.ruleId,
          alertSeverity: decision.alertSeverity,
        },
      },
    }
  }
}
