import { describe, expect, it, vi } from 'vitest'
import { McpToolGate, type McpToolCall, type McpToolResult } from './mcp.js'

describe('McpToolGate', () => {
  const policyName = 'basic-agent-authority'
  const agentRole = 'agt_reader'

  it('allows tool execution when policy returns ALLOW', async () => {
    const gate = new McpToolGate({
      policy: policyName,
      agentRole,
    })

    const executor = vi.fn().mockResolvedValue({ status: 'ok', data: 'flight details' })

    const call: McpToolCall = {
      name: 'read',
      arguments: { file: 'records.txt' },
    }

    const result = await gate.execute(call, executor)

    expect(executor).toHaveBeenCalledTimes(1)
    expect(executor).toHaveBeenCalledWith({ file: 'records.txt' })
    expect(result.isError).toBe(false)
    expect(result.content).toEqual([
      {
        type: 'text',
        text: JSON.stringify({ status: 'ok', data: 'flight details' }),
      },
    ])
    expect(result._meta?.adap).toEqual({
      action: 'ALLOW',
      ruleId: 'read_allow',
      alertSeverity: 'LOW',
    })
  })

  it('blocks tool execution when policy returns BLOCK and does not call executor', async () => {
    const gate = new McpToolGate({
      policy: policyName,
      agentRole,
    })

    const executor = vi.fn().mockResolvedValue('executed')

    const call: McpToolCall = {
      name: 'apply',
      arguments: { amount: 800 },
    }

    const result = await gate.execute(call, executor)

    expect(executor).not.toHaveBeenCalled()
    expect(result.isError).toBe(true)
    expect(result.content[0].text).toContain('[ADAP BLOCK]')
    expect(result.content[0].text).toContain('block_over_cap')
    expect(result._meta?.adap).toEqual({
      action: 'BLOCK',
      ruleId: 'block_over_cap',
      reason: expect.any(String),
      alertSeverity: 'CRITICAL',
    })
  })

  it('intercepts tool execution when policy returns REQUIRE_HUMAN and marks as deferred', async () => {
    const gate = new McpToolGate({
      policy: policyName,
      agentRole,
    })

    const executor = vi.fn().mockResolvedValue('executed')

    const call: McpToolCall = {
      name: 'apply',
      arguments: { amount: 300 },
    }

    const result = await gate.execute(call, executor)

    expect(executor).not.toHaveBeenCalled()
    expect(result.isError).toBe(true)
    expect(result.content[0].text).toContain('[ADAP REQUIRE_HUMAN]')
    expect(result._meta?.adap).toEqual({
      action: 'REQUIRE_HUMAN',
      ruleId: 'apply_needs_human',
      reason: expect.any(String),
      alertSeverity: 'MEDIUM',
      deferred: true,
    })
  })

  it('throws an error when throwOnError is configured and action is BLOCK', async () => {
    const gate = new McpToolGate({
      policy: policyName,
      agentRole,
      throwOnError: true,
    })

    const executor = vi.fn()

    const call: McpToolCall = {
      name: 'apply',
      arguments: { amount: 1000 },
    }

    await expect(gate.execute(call, executor)).rejects.toThrow(/ADAP BLOCK/)
    expect(executor).not.toHaveBeenCalled()
  })

  it('preserves pre-formatted McpToolResult from tool executor while attaching ADAP metadata', async () => {
    const gate = new McpToolGate({
      policy: policyName,
      agentRole,
    })

    const customResult: McpToolResult = {
      content: [{ type: 'text', text: 'custom mcp content' }],
      _meta: { existingKey: 'preserved' },
    }

    const executor = vi.fn().mockResolvedValue(customResult)

    const call: McpToolCall = {
      name: 'read',
      arguments: {},
    }

    const result = await gate.execute(call, executor)

    expect(result.content).toEqual(customResult.content)
    expect(result._meta).toEqual({
      existingKey: 'preserved',
      adap: {
        action: 'ALLOW',
        ruleId: 'read_allow',
        alertSeverity: 'LOW',
      },
    })
  })

  it('evaluates decisions without executing the tool via evaluate()', () => {
    const gate = new McpToolGate({
      policy: policyName,
      agentRole,
    })

    const allowed = gate.evaluate({ name: 'read' })
    expect(allowed.action).toBe('ALLOW')
    expect(allowed.ruleId).toBe('read_allow')

    const blocked = gate.evaluate({ name: 'apply', arguments: { amount: 999 } })
    expect(blocked.action).toBe('BLOCK')
    expect(blocked.ruleId).toBe('block_over_cap')
  })
})
