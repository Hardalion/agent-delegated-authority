export type DecisionName = 'ALLOW' | 'REQUIRE_HUMAN' | 'BLOCK'
export type DownstreamStatus = 'completed' | 'accepted' | 'failed' | 'unknown' | 'not_called'
export type ApprovalState = 'none' | 'pending' | 'approved' | 'rejected'
export type StageStatus = 'complete' | 'blocked' | 'not_executed' | 'skipped' | 'failed' | 'unknown' | 'waiting'

export interface AuthorityView {
  readonly authenticated: boolean
  readonly decision: DecisionName
  readonly ruleId: string
  readonly reason: string
  readonly intentHash: string
  readonly executed: boolean
  readonly downstreamStatus: DownstreamStatus
  readonly receiptPresent: boolean
  readonly receiptValid: boolean | null
  readonly approvalState: ApprovalState
  readonly correlationId: string
  readonly at: string
}

export interface StageView {
  id: string
  label: string
  status: StageStatus
  detail: string
}

export interface TimelineEvent {
  type: string
  timestamp: string
  correlationId: string
  intentHash?: string
  decision?: string
  reason?: string
  source: 'authority-result' | 'adap-gateway' | 'demo-approver'
}

const DELEGATION_BLOCK = new Set([
  'capability',
  'constraint',
  'narrowing',
  'expired',
  'actor',
  'chain',
  'amount',
  'target',
  'currency',
])

const PRE_POLICY = new Set([
  ...DELEGATION_BLOCK,
  'signature_invalid',
  'canonicalization',
  'identity',
  'schema',
  'nonce',
  'policy',
])

export function outcomeLabel(view: Pick<AuthorityView, 'decision' | 'executed' | 'downstreamStatus' | 'approvalState'>): string {
  if (view.downstreamStatus === 'unknown' || (view.downstreamStatus === 'completed' && !view.executed)) {
    return 'OUTCOME UNKNOWN'
  }
  if (view.executed && (view.downstreamStatus === 'completed' || view.downstreamStatus === 'accepted')) {
    return 'EXECUTED'
  }
  if (view.approvalState === 'pending') return 'NOT EXECUTED · AWAITING APPROVAL'
  if (view.approvalState === 'rejected') return 'NOT EXECUTED · REJECTED'
  if (view.approvalState === 'approved' && !view.executed) return 'NOT EXECUTED · CONTINUED'
  if (view.decision === 'BLOCK') return 'NOT EXECUTED · BLOCKED'
  return 'NOT EXECUTED'
}

export function buildStages(view: AuthorityView): StageView[] {
  const unknown = outcomeLabel(view) === 'OUTCOME UNKNOWN'
  const delegationBlocked = view.authenticated && DELEGATION_BLOCK.has(view.ruleId)
  const policyReached = view.authenticated && !PRE_POLICY.has(view.ruleId) && view.ruleId !== 'replay'
  const executionStatus: StageStatus = unknown
    ? 'unknown'
    : view.executed && (view.downstreamStatus === 'completed' || view.downstreamStatus === 'accepted')
      ? 'complete'
      : 'not_executed'
  const executionDetail = unknown
    ? 'OUTCOME UNKNOWN'
    : executionStatus === 'complete'
      ? 'The gateway called the downstream rail and received a completed result.'
      : view.approvalState === 'pending'
        ? 'Not called. Waiting for human approval.'
        : view.approvalState === 'rejected'
          ? 'Not called. The approver rejected the intent.'
          : view.approvalState === 'approved' && !view.executed
            ? 'This record did not execute. A later approval continued the intent.'
            : 'Not called.'

  return [
    {
      id: 'principal',
      label: 'Principal',
      status: view.authenticated ? 'complete' : 'failed',
      detail: view.authenticated ? 'Issuer key verified.' : 'Signature was not verified.',
    },
    {
      id: 'delegation',
      label: 'Delegation',
      status: !view.authenticated ? 'skipped' : delegationBlocked ? 'blocked' : 'complete',
      detail: delegationBlocked ? view.reason : view.authenticated ? 'Delegation accepted for this intent.' : 'Not reached.',
    },
    {
      id: 'agent',
      label: 'Agent',
      status: view.authenticated ? 'complete' : 'failed',
      detail: view.authenticated ? 'Agent signature verified.' : 'Agent signature was not verified.',
    },
    {
      id: 'intent',
      label: 'Intent',
      status: view.authenticated && view.intentHash ? 'complete' : 'failed',
      detail: view.intentHash ? view.intentHash : 'Intent hash was not established.',
    },
    {
      id: 'policy',
      label: 'Policy',
      status: policyReached ? 'complete' : 'skipped',
      detail: policyReached ? `${view.decision} · ${view.ruleId}` : 'Policy evaluation was not reached.',
    },
    {
      id: 'authorization',
      label: 'Authorization',
      status: unknown
        ? 'unknown'
        : view.approvalState === 'pending'
          ? 'waiting'
          : view.decision === 'BLOCK' || view.approvalState === 'rejected'
            ? 'blocked'
            : view.decision === 'ALLOW'
              ? 'complete'
              : 'waiting',
      detail: `${view.decision} · ${view.reason}`,
    },
    {
      id: 'gateway',
      label: 'Gateway',
      status: 'complete',
      detail: unknown
        ? 'Executor was invoked. The downstream outcome is unknown.'
        : executionStatus === 'complete'
          ? 'Executor invoked.'
          : 'Authority path finished. Executor not invoked.',
    },
    {
      id: 'execution',
      label: 'Execution',
      status: executionStatus,
      detail: executionDetail,
    },
    {
      id: 'receipt',
      label: 'Receipt',
      status: view.receiptValid === true ? 'complete' : view.receiptPresent ? 'failed' : 'skipped',
      detail:
        view.receiptValid === true
          ? 'verifyProtocolReceipt accepted the issuer signature.'
          : view.receiptPresent
            ? 'Receipt present and verification failed.'
            : 'No receipt.',
    },
  ]
}

export function timelineFromAuthority(view: AuthorityView): TimelineEvent[] {
  const events: TimelineEvent[] = []
  const push = (type: string, extra?: Partial<TimelineEvent>) => {
    events.push({
      type,
      timestamp: view.at,
      correlationId: view.correlationId,
      intentHash: view.intentHash || undefined,
      source: 'authority-result',
      ...extra,
    })
  }

  push('intent.received')
  if (!view.authenticated) {
    push('decision.issued', { decision: view.decision, reason: view.reason })
    push('execution.not_called', { reason: 'Unauthenticated input. The executor was not called.' })
    return events
  }

  push('identity.verified')
  if (DELEGATION_BLOCK.has(view.ruleId)) push('delegation.rejected', { reason: view.reason })
  else if (view.ruleId !== 'replay') push('delegation.validated')

  if (PRE_POLICY.has(view.ruleId) || view.ruleId === 'replay') push('policy.not_reached', { reason: view.reason })
  else push('policy.evaluated', { decision: view.decision, reason: view.reason })

  push('decision.issued', { decision: view.decision, reason: view.reason })

  if (view.approvalState === 'pending') {
    push('approval.requested', { reason: view.reason })
  }
  if (view.approvalState === 'approved' && view.executed) push('approval.authenticated')
  if (view.approvalState === 'rejected') {
    push('approval.rejected', { source: 'demo-approver', reason: view.reason })
  }

  const label = outcomeLabel(view)
  if (label === 'OUTCOME UNKNOWN') {
    push('outcome.unknown', { reason: 'OUTCOME UNKNOWN' })
  } else if (label === 'EXECUTED') {
    push('execution.authorized')
    push('execution.started')
    push('execution.completed')
  } else if (view.downstreamStatus === 'failed') {
    push('execution.failed', { reason: view.reason })
  } else {
    push('execution.not_called', { reason: 'The executor was not called.' })
  }

  if (view.receiptPresent) push('receipt.generated')
  if (view.receiptValid === true) push('receipt.verified')
  if (view.receiptValid === false) push('receipt.invalid')
  return events
}
