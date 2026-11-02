import { describe, expect, it } from 'vitest'
import { buildStages, outcomeLabel, timelineFromAuthority, type AuthorityView } from './timeline.js'

function view(overrides: Partial<AuthorityView> = {}): AuthorityView {
  return {
    authenticated: true,
    decision: 'ALLOW',
    ruleId: 'status_allow',
    reason: 'Rule status_allow matched',
    intentHash: 'abc',
    executed: true,
    downstreamStatus: 'completed',
    receiptPresent: true,
    receiptValid: true,
    approvalState: 'none',
    correlationId: 'corr_test',
    at: '2026-11-01T12:00:00.000Z',
    ...overrides,
  }
}

describe('outcome labels', () => {
  it('marks a completed allow as executed', () => {
    expect(outcomeLabel(view())).toBe('EXECUTED')
  })

  it('keeps a pending approval visibly unexecuted', () => {
    expect(
      outcomeLabel(view({ decision: 'REQUIRE_HUMAN', executed: false, downstreamStatus: 'not_called', approvalState: 'pending' })),
    ).toBe('NOT EXECUTED · AWAITING APPROVAL')
  })

  it('does not describe a block as execution', () => {
    expect(outcomeLabel(view({ decision: 'BLOCK', executed: false, downstreamStatus: 'not_called', ruleId: 'block_beneficiary' }))).toBe(
      'NOT EXECUTED · BLOCKED',
    )
  })

  it('uses OUTCOME UNKNOWN when the rail outcome is unknown', () => {
    expect(outcomeLabel(view({ decision: 'BLOCK', executed: false, downstreamStatus: 'unknown' }))).toBe('OUTCOME UNKNOWN')
  })

  it('uses OUTCOME UNKNOWN when a completed rail result is not marked executed', () => {
    expect(outcomeLabel(view({ executed: false, downstreamStatus: 'completed' }))).toBe('OUTCOME UNKNOWN')
  })
})

describe('stages and timeline', () => {
  it('does not complete execution for a policy block', () => {
    const blocked = view({
      decision: 'BLOCK',
      ruleId: 'block_beneficiary',
      executed: false,
      downstreamStatus: 'not_called',
      receiptValid: true,
    })
    const execution = buildStages(blocked).find((stage) => stage.id === 'execution')
    expect(execution?.status).toBe('not_executed')
    const types = timelineFromAuthority(blocked).map((event) => event.type)
    expect(types).toContain('policy.evaluated')
    expect(types).toContain('execution.not_called')
    expect(types).not.toContain('execution.completed')
  })

  it('skips policy when the delegation rejects the action', () => {
    const types = timelineFromAuthority(
      view({ decision: 'BLOCK', ruleId: 'capability', executed: false, downstreamStatus: 'not_called', reason: 'capability not granted' }),
    ).map((event) => event.type)
    expect(types).toContain('delegation.rejected')
    expect(types).toContain('policy.not_reached')
    expect(types).not.toContain('execution.completed')
  })

  it('requests approval without an execution event', () => {
    const types = timelineFromAuthority(
      view({
        decision: 'REQUIRE_HUMAN',
        ruleId: 'create_needs_human',
        executed: false,
        downstreamStatus: 'not_called',
        approvalState: 'pending',
        receiptValid: true,
      }),
    ).map((event) => event.type)
    expect(types).toContain('approval.requested')
    expect(types).toContain('execution.not_called')
    expect(types).not.toContain('execution.completed')
  })
})
