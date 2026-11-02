import { PURPOSE } from './policy.js'

export const SCENARIO_IDS = ['status', 'payment', 'beneficiary', 'hard-cap'] as const

export type ScenarioId = (typeof SCENARIO_IDS)[number]

export interface ScenarioSpec {
  readonly id: ScenarioId
  readonly title: string
  readonly action: string
  readonly target: string
  readonly parameters: Readonly<Record<string, string | number | boolean>>
}

export const SCENARIOS: Readonly<Record<ScenarioId, ScenarioSpec>> = {
  status: {
    id: 'status',
    title: 'Scenario A · Authorized status read',
    action: 'get_payment_status',
    target: 'payments/pay_seed_1001',
    parameters: { purpose: PURPOSE },
  },
  payment: {
    id: 'payment',
    title: 'Scenario B · Payment above the autonomous limit',
    action: 'create_payment',
    target: 'payments/outgoing',
    parameters: {
      purpose: PURPOSE,
      amount: 250_000,
      currency: 'USD',
      beneficiary: 'vendor_acme',
      reference: 'INV-2041',
    },
  },
  beneficiary: {
    id: 'beneficiary',
    title: 'Scenario C · Beneficiary change',
    action: 'change_beneficiary',
    target: 'payments/pay_seed_1001',
    parameters: {
      purpose: PURPOSE,
      beneficiary: 'vendor_unknown',
    },
  },
  'hard-cap': {
    id: 'hard-cap',
    title: 'Hard-cap payment',
    action: 'create_payment',
    target: 'payments/outgoing',
    parameters: {
      purpose: PURPOSE,
      amount: 900_000,
      currency: 'USD',
      beneficiary: 'vendor_acme',
      reference: 'INV-OVER-CAP',
    },
  },
}

export function isScenarioId(value: string): value is ScenarioId {
  return (SCENARIO_IDS as readonly string[]).includes(value)
}
