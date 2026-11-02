import { randomBytes, timingSafeEqual } from 'node:crypto'
import { mkdir, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  createIdentity,
  FixedClock,
  ImmutablePolicyResolver,
  importPublicKey,
  NonceLedger,
  PendingAuthorizationStore,
  publicKeyFingerprint,
  signApproval,
  signDelegation,
  signIntent,
  verifyProtocolReceipt,
  type HumanApproval,
  type Identity,
  type SignedDelegation,
  type SignedIntent,
} from 'adap'
import { verifyReceiptChain, type AuthorizationReceiptV1 } from 'adap-receipt'
import type { Policy } from 'adap-policy'
import { executeAuthorized, MemorySecurityEventSink, type SecurityEvent } from 'adap-gateway'
import { TreasuryAgent } from './agent.js'
import { DemoBroker } from './broker.js'
import { DemoError } from './errors.js'
import { assertDemoResetAllowed, RESET_CONFIRM, type DemoEnv } from './guard.js'
import {
  createSimulatedRail,
  type RailCall,
  type RailSideEffects,
  type SimulatedPaymentSystem,
  type SimPayment,
} from './payments.js'
import { authorityNote, POLICY_URI, PURPOSE, TREASURY_POLICY, AUTONOMOUS_LIMIT_CENTS, HARD_LIMIT_CENTS } from './policy.js'
import { SCENARIOS, type ScenarioId } from './scenarios.js'
import {
  buildStages,
  outcomeLabel,
  timelineFromAuthority,
  type ApprovalState,
  type AuthorityView,
  type DecisionName,
  type DownstreamStatus,
  type StageView,
  type TimelineEvent,
} from './timeline.js'

export interface RuntimeOptions {
  readonly env?: DemoEnv
  readonly now?: () => Date
  readonly passphrase?: string
}

export interface Verification {
  readonly valid: boolean
  readonly errors: readonly string[]
  readonly verifier: 'adap.verifyProtocolReceipt'
}

export interface PublicCase {
  id: string
  scenarioId: string
  nonce: string
  action: string
  target: string
  parameters: Record<string, unknown>
  intentHash: string
  delegationHash: string
  policyHash: string
  ruleId: string
  reason: string
  decision: DecisionName
  executed: boolean
  authenticated: boolean
  correlationId: string
  downstreamStatus: DownstreamStatus
  outcomeLabel: string
  approvalState: ApprovalState
  authorityNote: string | null
  nonceState: string
  receiptId: string | null
  receipt: AuthorizationReceiptV1 | null
  verification: Verification | null
  stages: StageView[]
  createdAt: string
  latencyMs: number
  continuedBy: string | null
}

export interface HealthReport {
  readonly ok: boolean
  readonly problems: readonly string[]
  readonly store: 'process-local-memory'
  readonly simulatedRail: true
  readonly demoEnv: string
  readonly postgresAttached: false
  readonly postgresUrlIgnored: boolean
}

export interface PublicState {
  readonly environment: {
    readonly label: 'HACKATHON DEMO'
    readonly simulatedRail: true
    readonly store: 'process-local memory'
  }
  readonly health: HealthReport
  readonly principal: { readonly id: string; readonly label: string; readonly fingerprint: string }
  readonly agent: { readonly id: string; readonly label: string; readonly fingerprint: string }
  readonly issuer: { readonly id: string; readonly fingerprint: string; readonly publicKey: string }
  readonly delegation: {
    readonly id: string
    readonly issuer: string
    readonly subject: string
    readonly capabilities: readonly { readonly action: string; readonly target?: string }[]
    readonly constraints: Readonly<Record<string, string | number | boolean>>
    readonly issuedAt: string
    readonly expiresAt: string
  }
  readonly policy: {
    readonly uri: string
    readonly name: string
    readonly version: string
    readonly description?: string
    readonly hash: string
    readonly defaultAction: string
    readonly targetAgents: readonly string[]
    readonly rules: readonly { readonly ruleId: string; readonly action: string; readonly condition: string }[]
  }
  readonly limits: { readonly autonomousCents: number; readonly hardCapCents: number; readonly currency: 'USD' }
  readonly payments: readonly SimPayment[]
  readonly sideEffects: RailSideEffects
  readonly railCalls: readonly RailCall[]
  readonly cases: readonly PublicCase[]
  readonly pending: readonly PublicCase[]
  readonly timeline: readonly TimelineEvent[]
  readonly gatewayEvents: readonly SecurityEvent[]
  readonly metrics: {
    readonly decisions: number
    readonly pending: number
    readonly executed: number
    readonly blocked: number
    readonly receiptsValid: number
    readonly receiptsInvalid: number
  }
  readonly timings: {
    readonly lastAuthorizationMs: number | null
    readonly lastApprovalMs: number | null
    readonly lastVerifyMs: number | null
  }
  readonly receiptChain: { readonly valid: boolean; readonly errors: readonly string[]; readonly verifier: 'adap-receipt.verifyReceiptChain' } | null
  readonly scenarios: readonly { readonly id: ScenarioId; readonly title: string; readonly action: string }[]
}

export interface EvidenceBundle {
  readonly exportedAt: string
  readonly environment: 'hackathon'
  readonly simulatedRail: true
  readonly note: string
  readonly cases: readonly PublicCase[]
  readonly payments: readonly SimPayment[]
  readonly timeline: readonly TimelineEvent[]
  readonly gatewayEvents: readonly SecurityEvent[]
  readonly sideEffects: RailSideEffects
}

interface OpenIntent {
  readonly intent: SignedIntent
  readonly chain: readonly SignedDelegation[]
  readonly scenarioId: string
}

interface DispatchInput {
  readonly scenarioId: string
  readonly intent: SignedIntent
  readonly chain: readonly SignedDelegation[]
  readonly approval?: HumanApproval
  readonly policy?: Policy
  readonly instant: Date
  readonly measure: 'authorization' | 'approval' | 'none'
}

function roundMs(value: number | null): number | null {
  if (value == null) return null
  return Math.round(value * 10) / 10
}

function exportDirectory(): string {
  const here = dirname(fileURLToPath(import.meta.url))
  return join(here, '..', '..', '..', '.demo', 'exports')
}

function passphraseMatches(input: string, expected: string): boolean {
  const left = Buffer.from(input)
  const right = Buffer.from(expected)
  if (left.length !== right.length) return false
  return timingSafeEqual(left, right)
}

function plainParameters(parameters: Readonly<Record<string, unknown>>): Record<string, unknown> {
  return { ...parameters }
}

export class DemoRuntime {
  readonly #env: DemoEnv
  readonly #now: () => Date
  readonly #passphrase: string
  readonly #principal: Identity
  readonly #agentIdentity: Identity
  readonly #outsider: Identity
  readonly #signer: Identity
  readonly #directory: Map<string, string>
  readonly #policyResolver = new ImmutablePolicyResolver()
  readonly #policyHash: string
  readonly #agent: TreasuryAgent
  #delegation: SignedDelegation
  #payments: SimulatedPaymentSystem
  #broker: DemoBroker
  #ledger: NonceLedger
  #pending: PendingAuthorizationStore
  #seenApprovals = new Set<string>()
  #events = new MemorySecurityEventSink()
  #cases: PublicCase[] = []
  #timeline: TimelineEvent[] = []
  #sequence = 0
  #prevReceiptHash: string | null = null
  #tail: Promise<void> = Promise.resolve()
  #open = new Map<string, OpenIntent>()
  #lastAuthorizationMs: number | null = null
  #lastApprovalMs: number | null = null
  #lastVerifyMs: number | null = null

  constructor(options: RuntimeOptions = {}) {
    this.#env = options.env ?? { ADAP_DEMO_ENV: 'hackathon', NODE_ENV: 'demo' }
    this.#now = options.now ?? (() => new Date())
    this.#passphrase = options.passphrase ?? 'treasury-demo'
    this.#principal = createIdentity('prn_treasury')
    this.#agentIdentity = createIdentity('agt_treasury')
    this.#outsider = createIdentity('agt_outsider')
    this.#signer = createIdentity('iss_hackathon')
    this.#directory = new Map([
      [this.#principal.id, this.#principal.publicKey],
      [this.#agentIdentity.id, this.#agentIdentity.publicKey],
      [this.#outsider.id, this.#outsider.publicKey],
    ])
    this.#policyHash = this.#policyResolver.register(TREASURY_POLICY, POLICY_URI).contentHash
    this.#agent = new TreasuryAgent(this.#agentIdentity, 'del_treasury_root')
    this.#delegation = this.#signDelegation(this.#now())
    const rail = createSimulatedRail()
    this.#payments = rail.payments
    this.#broker = new DemoBroker(rail.payments, rail.capability)
    this.#ledger = new NonceLedger()
    this.#pending = new PendingAuthorizationStore()
    const health = this.health()
    if (!health.ok) throw new DemoError(500, 'fixture_invalid', health.problems.join('; '))
  }

  health(): HealthReport {
    const problems: string[] = []
    const payments = this.#payments.list()
    const seed = payments.find((payment) => payment.id === 'pay_seed_1001')
    if (!seed || seed.beneficiary !== 'vendor_northwind') problems.push('seed payment pay_seed_1001 is missing')
    if (!payments.some((payment) => payment.id === 'pay_seed_1002')) problems.push('seed payment pay_seed_1002 is missing')
    const pin = this.#policyResolver.resolveByUri(POLICY_URI)
    if (!pin || pin.contentHash !== this.#policyHash) problems.push('policy pin is missing')
    const actions = this.#broker.listActions()
    if (!actions.includes('get_payment_status') || !actions.includes('create_payment')) {
      problems.push('broker routes are incomplete')
    }
    if (actions.includes('change_beneficiary')) problems.push('beneficiary route must stay unregistered')
    if (Date.parse(this.#delegation.expires_at) <= this.#now().getTime()) problems.push('delegation is expired')
    return {
      ok: problems.length === 0,
      problems,
      store: 'process-local-memory',
      simulatedRail: true,
      demoEnv: this.#env.ADAP_DEMO_ENV ?? 'unset',
      postgresAttached: false,
      postgresUrlIgnored: Boolean(this.#env.ADAP_DEMO_PG_URL),
    }
  }

  issuerPublicKey(): string {
    return this.#signer.publicKey
  }

  async runScenario(id: ScenarioId, options?: { readonly nonce?: string }): Promise<PublicState> {
    return this.#exclusive(async () => {
      const spec = SCENARIOS[id]
      const instant = this.#now()
      const nonce = options?.nonce ?? `n-${id}-${randomBytes(8).toString('hex')}`
      const intent = this.#agent.propose({
        intentId: `int-${nonce}`,
        nonce,
        action: spec.action,
        target: spec.target,
        parameters: spec.parameters,
        issuedAt: new Date(instant.getTime() - 2_000).toISOString(),
        expiresAt: new Date(instant.getTime() + 20 * 60_000).toISOString(),
      })
      await this.#dispatch({
        scenarioId: id,
        intent,
        chain: [this.#delegation],
        instant,
        measure: 'authorization',
      })
      return this.publicState()
    })
  }

  async approve(nonce: string, passphrase: string): Promise<PublicState> {
    return this.#exclusive(async () => {
      this.#assertNonce(nonce)
      this.#assertPassphrase(passphrase)
      const open = this.#open.get(nonce)
      const pending = this.#cases.find((item) => item.nonce === nonce && item.approvalState === 'pending')
      if (!open || !pending) {
        const existing = this.#cases.find((item) => item.nonce === nonce)
        if (existing) {
          throw new DemoError(
            409,
            'approval_replay',
            'This intent is no longer awaiting approval. No additional execution was performed.',
          )
        }
        throw new DemoError(404, 'approval_not_found', 'No pending approval matches this nonce.')
      }
      const instant = this.#now()
      const approval = signApproval(
        {
          intent_hash: pending.intentHash,
          approver_id: this.#principal.id,
          approved_at: new Date(instant.getTime() - 500).toISOString(),
          decision: 'APPROVE',
          agent_id: open.intent.actor,
          delegation_chain_hash: pending.delegationHash,
          policy_content_hash: pending.policyHash,
          matched_rule_id: pending.ruleId,
        },
        this.#principal,
      )
      const created = await this.#dispatch({
        scenarioId: pending.scenarioId,
        intent: open.intent,
        chain: open.chain,
        approval,
        instant,
        measure: 'approval',
      })
      if (created.executed) {
        pending.approvalState = 'approved'
        pending.continuedBy = created.id
        pending.outcomeLabel = 'NOT EXECUTED · CONTINUED'
        pending.nonceState = this.#nonceState(nonce)
        pending.stages = buildStages({
          authenticated: pending.authenticated,
          decision: pending.decision,
          ruleId: pending.ruleId,
          reason: pending.reason,
          intentHash: pending.intentHash,
          executed: false,
          downstreamStatus: 'not_called',
          receiptPresent: pending.receipt != null,
          receiptValid: pending.verification?.valid ?? null,
          approvalState: 'approved',
          correlationId: pending.correlationId,
          at: pending.createdAt,
        })
        this.#open.delete(nonce)
      }
      if (!created.executed && (created.ruleId === 'replay' || created.reason.includes('duplicate approval'))) {
        throw new DemoError(
          409,
          'approval_replay',
          'This approval was not applied again. The intent was already decided. No additional execution was performed.',
        )
      }
      return this.publicState()
    })
  }

  async reject(nonce: string, passphrase: string): Promise<PublicState> {
    return this.#exclusive(async () => {
      this.#assertNonce(nonce)
      this.#assertPassphrase(passphrase)
      const pending = this.#cases.find((item) => item.nonce === nonce && item.approvalState === 'pending')
      if (!pending) {
        const existing = this.#cases.find((item) => item.nonce === nonce)
        if (existing) {
          throw new DemoError(
            409,
            'approval_replay',
            'This intent is no longer awaiting approval. No additional execution was performed.',
          )
        }
        throw new DemoError(404, 'approval_not_found', 'No pending approval matches this nonce.')
      }
      this.#ledger.consume(nonce, pending.intentHash)
      pending.approvalState = 'rejected'
      pending.executed = false
      pending.downstreamStatus = 'not_called'
      pending.outcomeLabel = 'NOT EXECUTED · REJECTED'
      pending.reason = 'Human approver rejected the pending intent. The executor was not called.'
      pending.nonceState = this.#nonceState(nonce)
      pending.stages = buildStages(this.#viewFromCase(pending))
      this.#open.delete(nonce)
      const at = this.#now().toISOString()
      this.#timeline.push({
        type: 'approval.rejected',
        timestamp: at,
        correlationId: pending.correlationId,
        intentHash: pending.intentHash,
        reason: pending.reason,
        source: 'demo-approver',
      })
      this.#timeline.push({
        type: 'execution.not_called',
        timestamp: at,
        correlationId: pending.correlationId,
        intentHash: pending.intentHash,
        reason: 'The approver rejected the intent. The executor was not called.',
        source: 'demo-approver',
      })
      this.#events.emit({
        type: 'approval.rejected',
        timestamp: at,
        correlationId: pending.correlationId,
        intentHash: pending.intentHash,
        reason: pending.reason,
      })
      return this.publicState()
    })
  }

  verifyReceipt(receipt: unknown): Verification {
    const started = performance.now()
    const verifier = 'adap.verifyProtocolReceipt' as const
    try {
      if (receipt == null || typeof receipt !== 'object') {
        return { valid: false, errors: ['receipt is not an object'], verifier }
      }
      const result = verifyProtocolReceipt(receipt as AuthorizationReceiptV1, importPublicKey(this.#signer.publicKey))
      this.#lastVerifyMs = performance.now() - started
      return { valid: result.valid, errors: [...result.errors], verifier }
    } catch {
      this.#lastVerifyMs = performance.now() - started
      return { valid: false, errors: ['receipt could not be verified'], verifier }
    }
  }

  verifyStored(receiptId: string): Verification {
    const found = this.#cases.find((item) => item.receiptId === receiptId)
    if (!found?.receipt) {
      return { valid: false, errors: ['receipt was not found'], verifier: 'adap.verifyProtocolReceipt' }
    }
    return this.verifyReceipt(found.receipt)
  }

  exportEvidence(): EvidenceBundle {
    const state = this.publicState()
    return {
      exportedAt: new Date().toISOString(),
      environment: 'hackathon',
      simulatedRail: true,
      note: 'Simulated payment rail. No production credentials. No private keys.',
      cases: state.cases,
      payments: state.payments,
      timeline: state.timeline,
      gatewayEvents: state.gatewayEvents,
      sideEffects: state.sideEffects,
    }
  }

  async reset(input: {
    readonly confirm: string
    readonly passphrase: string
    readonly acknowledgeExport: boolean
  }): Promise<{ readonly evidence: EvidenceBundle; readonly file: string; readonly state: PublicState }> {
    return this.#exclusive(async () => {
      assertDemoResetAllowed(this.#env)
      if (input.acknowledgeExport !== true) {
        throw new DemoError(400, 'export_required', 'Reset requires acknowledgeExport: true so evidence is exported first.')
      }
      if (input.confirm !== RESET_CONFIRM) {
        throw new DemoError(400, 'reset_confirm_required', 'Reset requires the exact confirmation phrase.')
      }
      this.#assertPassphrase(input.passphrase)
      const evidence = this.exportEvidence()
      const dir = exportDirectory()
      await mkdir(dir, { recursive: true })
      const file = join(dir, `evidence-${Date.now()}.json`)
      await writeFile(file, JSON.stringify(evidence), 'utf8')
      this.#reseed()
      return { evidence, file, state: this.publicState() }
    })
  }

  publicState(): PublicState {
    const cases = this.#cases.map((item) => structuredClone(item))
    const pending = cases.filter((item) => item.approvalState === 'pending')
    const orderedReceipts = [...this.#cases]
      .reverse()
      .map((item) => item.receipt)
      .filter((receipt): receipt is AuthorizationReceiptV1 => receipt != null)
    const chain =
      orderedReceipts.length === 0
        ? null
        : verifyReceiptChain(orderedReceipts, {
            publicKeySpki: this.#signer.publicKey,
            prevReceiptHash: null,
          })
    return {
      environment: {
        label: 'HACKATHON DEMO',
        simulatedRail: true,
        store: 'process-local memory',
      },
      health: this.health(),
      principal: {
        id: this.#principal.id,
        label: 'Treasury Operations',
        fingerprint: publicKeyFingerprint(this.#principal.publicKey),
      },
      agent: {
        id: this.#agent.id,
        label: 'Treasury Assistant',
        fingerprint: publicKeyFingerprint(this.#agentIdentity.publicKey),
      },
      issuer: {
        id: this.#signer.id,
        fingerprint: publicKeyFingerprint(this.#signer.publicKey),
        publicKey: this.#signer.publicKey,
      },
      delegation: {
        id: this.#delegation.delegation_id,
        issuer: this.#delegation.issuer,
        subject: this.#delegation.subject,
        capabilities: this.#delegation.capabilities.map((capability) => ({
          action: capability.action,
          target: capability.target,
        })),
        constraints: { ...this.#delegation.constraints },
        issuedAt: this.#delegation.issued_at,
        expiresAt: this.#delegation.expires_at,
      },
      policy: {
        uri: POLICY_URI,
        name: TREASURY_POLICY.policyName,
        version: TREASURY_POLICY.version,
        description: TREASURY_POLICY.description,
        hash: this.#policyHash,
        defaultAction: TREASURY_POLICY.defaultAction,
        targetAgents: TREASURY_POLICY.targetAgents,
        rules: TREASURY_POLICY.rules.map((rule) => ({
          ruleId: rule.ruleId,
          action: rule.action,
          condition: rule.condition,
        })),
      },
      limits: {
        autonomousCents: AUTONOMOUS_LIMIT_CENTS,
        hardCapCents: HARD_LIMIT_CENTS,
        currency: 'USD',
      },
      payments: this.#payments.list(),
      sideEffects: this.#payments.sideEffects(),
      railCalls: this.#payments.calls(),
      cases,
      pending,
      timeline: this.#timeline.map((event) => ({ ...event })),
      gatewayEvents: this.#events.events.map((event) => ({ ...event })),
      metrics: {
        decisions: cases.length,
        pending: pending.length,
        executed: cases.filter((item) => item.executed && item.downstreamStatus === 'completed').length,
        blocked: cases.filter((item) => item.decision === 'BLOCK').length,
        receiptsValid: cases.filter((item) => item.verification?.valid === true).length,
        receiptsInvalid: cases.filter((item) => item.verification != null && item.verification.valid === false).length,
      },
      timings: {
        lastAuthorizationMs: roundMs(this.#lastAuthorizationMs),
        lastApprovalMs: roundMs(this.#lastApprovalMs),
        lastVerifyMs: roundMs(this.#lastVerifyMs),
      },
      receiptChain:
        chain == null
          ? null
          : { valid: chain.valid, errors: [...chain.errors], verifier: 'adap-receipt.verifyReceiptChain' },
      scenarios: (Object.keys(SCENARIOS) as ScenarioId[]).map((id) => ({
        id,
        title: SCENARIOS[id].title,
        action: SCENARIOS[id].action,
      })),
    }
  }

  async probeAmount(amount: number, nonce?: string): Promise<PublicCase> {
    return this.#exclusive(async () => {
      const instant = this.#now()
      const id = nonce ?? `n-amt-${amount}-${randomBytes(4).toString('hex')}`
      const intent = this.#agent.propose({
        intentId: `int-${id}`,
        nonce: id,
        action: 'create_payment',
        target: 'payments/outgoing',
        parameters: {
          purpose: PURPOSE,
          amount,
          currency: 'USD',
          beneficiary: 'vendor_acme',
          reference: 'PROBE',
        },
        issuedAt: new Date(instant.getTime() - 2_000).toISOString(),
        expiresAt: new Date(instant.getTime() + 20 * 60_000).toISOString(),
      })
      return structuredClone(
        await this.#dispatch({ scenarioId: 'probe-amount', intent, chain: [this.#delegation], instant, measure: 'authorization' }),
      )
    })
  }

  async probeExpiredDelegation(): Promise<PublicCase> {
    return this.#exclusive(async () => {
      const instant = this.#now()
      const delegation = signDelegation(
        {
          delegation_id: 'del_expired',
          issuer: this.#principal.id,
          subject: this.#agentIdentity.id,
          capabilities: [{ action: 'get_payment_status', target: 'payments/*', delegable: false }],
          constraints: { purpose: PURPOSE },
          issued_at: new Date(instant.getTime() - 60_000).toISOString(),
          expires_at: new Date(instant.getTime() - 1_000).toISOString(),
        },
        this.#principal,
      )
      const nonce = `n-expired-${randomBytes(4).toString('hex')}`
      const intent = this.#agent.propose({
        intentId: `int-${nonce}`,
        nonce,
        action: 'get_payment_status',
        target: 'payments/pay_seed_1001',
        parameters: { purpose: PURPOSE },
        issuedAt: new Date(instant.getTime() - 2_000).toISOString(),
        expiresAt: new Date(instant.getTime() + 20 * 60_000).toISOString(),
        delegationId: delegation.delegation_id,
      })
      return structuredClone(
        await this.#dispatch({
          scenarioId: 'probe-expired',
          intent,
          chain: [delegation],
          instant,
          measure: 'none',
        }),
      )
    })
  }

  async probeWrongAgent(): Promise<PublicCase> {
    return this.#exclusive(async () => {
      const instant = this.#now()
      const nonce = `n-outsider-${randomBytes(4).toString('hex')}`
      const intent = signIntent(
        {
          intent_id: `int-${nonce}`,
          actor: this.#outsider.id,
          delegation_chain: [this.#delegation.delegation_id],
          action: 'get_payment_status',
          target: 'payments/pay_seed_1001',
          parameters: { purpose: PURPOSE },
          nonce,
          issued_at: new Date(instant.getTime() - 2_000).toISOString(),
          expires_at: new Date(instant.getTime() + 20 * 60_000).toISOString(),
        },
        this.#outsider,
      )
      return structuredClone(
        await this.#dispatch({
          scenarioId: 'probe-agent',
          intent,
          chain: [this.#delegation],
          instant,
          measure: 'none',
        }),
      )
    })
  }

  async probeWrongTarget(): Promise<PublicCase> {
    return this.#exclusive(async () => {
      const instant = this.#now()
      const nonce = `n-target-${randomBytes(4).toString('hex')}`
      const intent = this.#agent.propose({
        intentId: `int-${nonce}`,
        nonce,
        action: 'get_payment_status',
        target: 'vault/root',
        parameters: { purpose: PURPOSE },
        issuedAt: new Date(instant.getTime() - 2_000).toISOString(),
        expiresAt: new Date(instant.getTime() + 20 * 60_000).toISOString(),
      })
      return structuredClone(
        await this.#dispatch({
          scenarioId: 'probe-target',
          intent,
          chain: [this.#delegation],
          instant,
          measure: 'none',
        }),
      )
    })
  }

  async probeInvalidSignature(): Promise<PublicCase> {
    return this.#exclusive(async () => {
      const instant = this.#now()
      const nonce = `n-bad-sig-${randomBytes(4).toString('hex')}`
      const intent = this.#agent.propose({
        intentId: `int-${nonce}`,
        nonce,
        action: 'get_payment_status',
        target: 'payments/pay_seed_1001',
        parameters: { purpose: PURPOSE },
        issuedAt: new Date(instant.getTime() - 2_000).toISOString(),
        expiresAt: new Date(instant.getTime() + 20 * 60_000).toISOString(),
      })
      const chars = intent.signature.split('')
      const index = Math.min(8, chars.length - 1)
      chars[index] = chars[index] === 'a' ? 'b' : 'a'
      const flipped = chars.join('')
      return structuredClone(
        await this.#dispatch({
          scenarioId: 'probe-signature',
          intent: { ...intent, signature: flipped },
          chain: [this.#delegation],
          instant,
          measure: 'none',
        }),
      )
    })
  }

  async probePolicySubstitution(): Promise<PublicCase> {
    return this.#exclusive(async () => {
      const instant = this.#now()
      const nonce = `n-policy-${randomBytes(4).toString('hex')}`
      const intent = this.#agent.propose({
        intentId: `int-${nonce}`,
        nonce,
        action: 'get_payment_status',
        target: 'payments/pay_seed_1001',
        parameters: { purpose: PURPOSE },
        issuedAt: new Date(instant.getTime() - 2_000).toISOString(),
        expiresAt: new Date(instant.getTime() + 20 * 60_000).toISOString(),
      })
      const substituted: Policy = { ...TREASURY_POLICY, description: 'substituted policy document' }
      return structuredClone(
        await this.#dispatch({
          scenarioId: 'probe-policy',
          intent,
          chain: [this.#delegation],
          policy: substituted,
          instant,
          measure: 'none',
        }),
      )
    })
  }

  async probeParallelSameApproval(): Promise<{ readonly created: number; readonly calls: number; readonly decisions: readonly string[] }> {
    await this.runScenario('payment', { nonce: 'n-parallel-payment' })
    const open = this.#open.get('n-parallel-payment')
    const pending = this.#cases.find((item) => item.nonce === 'n-parallel-payment')
    if (!open || !pending) throw new DemoError(500, 'fixture_invalid', 'parallel probe is missing its pending intent')
    const instant = this.#now()
    const approval = signApproval(
      {
        intent_hash: pending.intentHash,
        approver_id: this.#principal.id,
        approved_at: new Date(instant.getTime() - 500).toISOString(),
        decision: 'APPROVE',
        agent_id: open.intent.actor,
        delegation_chain_hash: pending.delegationHash,
        policy_content_hash: pending.policyHash,
        matched_rule_id: pending.ruleId,
      },
      this.#principal,
    )
    const before = this.#payments.sideEffects().paymentsCreated
    const [first, second] = await Promise.all([
      this.#dispatch({
        scenarioId: 'payment',
        intent: open.intent,
        chain: open.chain,
        approval,
        instant,
        measure: 'approval',
      }),
      this.#dispatch({
        scenarioId: 'payment',
        intent: open.intent,
        chain: open.chain,
        approval,
        instant,
        measure: 'approval',
      }),
    ])
    return {
      created: this.#payments.sideEffects().paymentsCreated - before,
      calls: this.#payments.calls().filter((call) => call.action === 'create_payment' && !call.duplicate).length,
      decisions: [first.decision, second.decision],
    }
  }

  armDownstreamForTests(mode: 'unknown' | 'failed' | null): void {
    this.#payments.arm(mode)
  }

  attemptUnauthorizedSideEffectForTests(): { readonly status: string; readonly beneficiary: string } {
    const outcome = this.#payments.rejectUnauthorized({
      action: 'change_beneficiary',
      target: 'payments/pay_seed_1001',
      parameters: { beneficiary: 'vendor_unknown', purpose: PURPOSE },
      intentHash: 'forged',
      correlationId: 'corr_forged',
    })
    const beneficiary = this.#payments.list().find((payment) => payment.id === 'pay_seed_1001')?.beneficiary ?? ''
    return { status: outcome.status, beneficiary }
  }

  async #dispatch(input: DispatchInput): Promise<PublicCase> {
    const started = performance.now()
    let result: Awaited<ReturnType<typeof executeAuthorized>>
    try {
      result = await executeAuthorized({
        chain: input.chain,
        intent: input.intent,
        directory: this.#directory,
        policy: input.policy ?? TREASURY_POLICY,
        policyUri: POLICY_URI,
        ledger: this.#ledger,
        signer: this.#signer,
        approval: input.approval,
        clock: new FixedClock(input.instant),
        pendingStore: this.#pending,
        policyResolver: this.#policyResolver,
        seenApprovals: this.#seenApprovals,
        receiptSequence: this.#sequence,
        prevReceiptHash: this.#prevReceiptHash,
        broker: this.#broker,
        events: this.#events,
        tenantId: 'hackathon',
      })
    } catch (error) {
      const message = error instanceof Error ? error.message : 'authority path failed'
      const failed = this.#storeCase({
        scenarioId: input.scenarioId,
        intent: input.intent,
        decision: 'BLOCK',
        ruleId: 'system',
        reason: message,
        intentHash: '',
        delegationHash: '',
        policyHash: this.#policyHash,
        executed: false,
        authenticated: false,
        correlationId: `corr_fail_${randomBytes(4).toString('hex')}`,
        downstreamStatus: 'unknown',
        approvalState: 'none',
        receipt: null,
        latencyMs: performance.now() - started,
        at: input.instant.toISOString(),
      })
      this.#timeline.push(...timelineFromAuthority(this.#viewFromCase(failed)))
      return failed
    }

    const latencyMs = performance.now() - started
    if (input.measure === 'authorization') this.#lastAuthorizationMs = latencyMs
    if (input.measure === 'approval') this.#lastApprovalMs = latencyMs
    if (result.receipt) {
      this.#sequence += 1
      const hash = result.receipt.integrity?.contentHash
      if (typeof hash === 'string' && hash.length === 64) this.#prevReceiptHash = hash
    }
    const downstreamStatus: DownstreamStatus = result.downstream?.status ?? 'not_called'
    let approvalState: ApprovalState = 'none'
    if (result.decision === 'REQUIRE_HUMAN' && !result.executed) approvalState = 'pending'
    else if (input.approval && result.executed) approvalState = 'approved'
    const created = this.#storeCase({
      scenarioId: input.scenarioId,
      intent: input.intent,
      decision: result.decision,
      ruleId: result.ruleId,
      reason: result.reason,
      intentHash: result.intentHash,
      delegationHash: result.delegationHash,
      policyHash: result.policyHash,
      executed: result.executed,
      authenticated: result.authenticated,
      correlationId: result.correlationId,
      downstreamStatus,
      approvalState,
      receipt: result.receipt ?? null,
      latencyMs,
      at: input.instant.toISOString(),
    })
    if (approvalState === 'pending') {
      this.#open.set(input.intent.nonce, {
        intent: input.intent,
        chain: input.chain,
        scenarioId: input.scenarioId,
      })
    }
    this.#timeline.push(...timelineFromAuthority(this.#viewFromCase(created)))
    return created
  }

  #storeCase(input: {
    readonly scenarioId: string
    readonly intent: SignedIntent
    readonly decision: DecisionName
    readonly ruleId: string
    readonly reason: string
    readonly intentHash: string
    readonly delegationHash: string
    readonly policyHash: string
    readonly executed: boolean
    readonly authenticated: boolean
    readonly correlationId: string
    readonly downstreamStatus: DownstreamStatus
    readonly approvalState: ApprovalState
    readonly receipt: AuthorizationReceiptV1 | null
    readonly latencyMs: number
    readonly at: string
  }): PublicCase {
    const verification = input.receipt ? this.verifyReceipt(input.receipt) : null
    const view: AuthorityView = {
      authenticated: input.authenticated,
      decision: input.decision,
      ruleId: input.ruleId,
      reason: input.reason,
      intentHash: input.intentHash,
      executed: input.executed,
      downstreamStatus: input.downstreamStatus,
      receiptPresent: input.receipt != null,
      receiptValid: verification ? verification.valid : null,
      approvalState: input.approvalState,
      correlationId: input.correlationId,
      at: input.at,
    }
    const created: PublicCase = {
      id: input.correlationId,
      scenarioId: input.scenarioId,
      nonce: input.intent.nonce,
      action: input.intent.action,
      target: input.intent.target,
      parameters: plainParameters(input.intent.parameters),
      intentHash: input.intentHash,
      delegationHash: input.delegationHash,
      policyHash: input.policyHash,
      ruleId: input.ruleId,
      reason: input.reason,
      decision: input.decision,
      executed: input.executed,
      authenticated: input.authenticated,
      correlationId: input.correlationId,
      downstreamStatus: input.downstreamStatus,
      outcomeLabel: outcomeLabel(view),
      approvalState: input.approvalState,
      authorityNote: authorityNote(input.ruleId, input.decision),
      nonceState: this.#nonceState(input.intent.nonce),
      receiptId: input.receipt?.receiptId ?? null,
      receipt: input.receipt,
      verification,
      stages: buildStages(view),
      createdAt: input.at,
      latencyMs: roundMs(input.latencyMs) ?? input.latencyMs,
      continuedBy: null,
    }
    this.#cases.unshift(created)
    return created
  }

  #viewFromCase(item: PublicCase): AuthorityView {
    return {
      authenticated: item.authenticated,
      decision: item.decision,
      ruleId: item.ruleId,
      reason: item.reason,
      intentHash: item.intentHash,
      executed: item.executed,
      downstreamStatus: item.downstreamStatus,
      receiptPresent: item.receipt != null,
      receiptValid: item.verification?.valid ?? null,
      approvalState: item.approvalState,
      correlationId: item.correlationId,
      at: item.createdAt,
    }
  }

  #nonceState(nonce: string): string {
    try {
      return this.#ledger.statusOf(nonce) ?? 'absent'
    } catch {
      return 'absent'
    }
  }

  #signDelegation(instant: Date): SignedDelegation {
    return signDelegation(
      {
        delegation_id: 'del_treasury_root',
        issuer: this.#principal.id,
        subject: this.#agentIdentity.id,
        capabilities: [
          { action: 'get_payment_status', target: 'payments/*', delegable: false },
          { action: 'create_payment', target: 'payments/*', delegable: false },
          { action: 'change_beneficiary', target: 'payments/*', delegable: false },
        ],
        constraints: { purpose: PURPOSE },
        issued_at: new Date(instant.getTime() - 2_000).toISOString(),
        expires_at: new Date(instant.getTime() + 12 * 60 * 60 * 1000).toISOString(),
      },
      this.#principal,
    )
  }

  #reseed(): void {
    const instant = this.#now()
    const rail = createSimulatedRail()
    this.#payments = rail.payments
    this.#broker = new DemoBroker(rail.payments, rail.capability)
    this.#ledger = new NonceLedger()
    this.#pending = new PendingAuthorizationStore()
    this.#seenApprovals = new Set()
    this.#events = new MemorySecurityEventSink()
    this.#cases = []
    this.#timeline = []
    this.#sequence = 0
    this.#prevReceiptHash = null
    this.#open.clear()
    this.#lastAuthorizationMs = null
    this.#lastApprovalMs = null
    this.#lastVerifyMs = null
    this.#delegation = this.#signDelegation(instant)
  }

  #assertPassphrase(input: string): void {
    if (!passphraseMatches(input, this.#passphrase)) {
      throw new DemoError(401, 'approver_rejected', 'Demo approver passphrase was not accepted.')
    }
  }

  #assertNonce(nonce: string): void {
    if (!/^[A-Za-z0-9._~-]{1,128}$/.test(nonce)) {
      throw new DemoError(400, 'malformed_input', 'nonce is malformed')
    }
  }

  async #exclusive<T>(fn: () => Promise<T>): Promise<T> {
    const previous = this.#tail
    let release = () => {}
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    this.#tail = previous.then(() => gate)
    await previous
    try {
      return await fn()
    } finally {
      release()
    }
  }
}
