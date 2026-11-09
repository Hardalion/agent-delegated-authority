import { PURPOSE } from './policy.js'
import { SANDBOX_PURPOSE } from './sandbox-policy.js'

export const SCENARIO_IDS = ['status', 'payment', 'beneficiary', 'hard-cap'] as const

export type ScenarioId = (typeof SCENARIO_IDS)[number]

export interface ScenarioSpec {
  readonly id: string
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

export const SANDBOX_SCENARIO_IDS = [
  'status',
  'pay-120',
  'pay-750',
  'pay-6000',
  'vendor-change',
  'purchase-allow',
  'purchase-review',
  'purchase-block',
] as const

export type SandboxScenarioId = (typeof SANDBOX_SCENARIO_IDS)[number]

export const SANDBOX_SCENARIOS: Readonly<Record<SandboxScenarioId, ScenarioSpec>> = {
  status: {
    id: 'status',
    title: 'Read a synthetic payment',
    action: 'get_payment_status',
    target: 'payments/pay_seed_1001',
    parameters: { purpose: SANDBOX_PURPOSE },
  },
  'pay-120': {
    id: 'pay-120',
    title: 'Pay €120',
    action: 'create_payment',
    target: 'payments/outgoing',
    parameters: {
      purpose: SANDBOX_PURPOSE,
      amount: 12_000,
      currency: 'EUR',
      beneficiary: 'vendor_acme',
      reference: 'INV-120',
    },
  },
  'pay-750': {
    id: 'pay-750',
    title: 'Pay €750 (needs a person)',
    action: 'create_payment',
    target: 'payments/outgoing',
    parameters: {
      purpose: SANDBOX_PURPOSE,
      amount: 75_000,
      currency: 'EUR',
      beneficiary: 'vendor_acme',
      reference: 'INV-750',
    },
  },
  'pay-6000': {
    id: 'pay-6000',
    title: 'Pay €6,000 (over the cap)',
    action: 'create_payment',
    target: 'payments/outgoing',
    parameters: {
      purpose: SANDBOX_PURPOSE,
      amount: 600_000,
      currency: 'EUR',
      beneficiary: 'vendor_acme',
      reference: 'INV-6000',
    },
  },
  'vendor-change': {
    id: 'vendor-change',
    title: 'Change a vendor account',
    action: 'update_vendor_account',
    target: 'vendors/vendor_northwind',
    parameters: {
      purpose: SANDBOX_PURPOSE,
      iban: 'GR9900000000000000000000099',
    },
  },
  'purchase-allow': {
    id: 'purchase-allow',
    title: 'Office purchase within limit',
    action: 'create_purchase_request',
    target: 'purchases/new',
    parameters: {
      purpose: SANDBOX_PURPOSE,
      category: 'office',
      amount: 10_000,
      title: 'Notebooks',
    },
  },
  'purchase-review': {
    id: 'purchase-review',
    title: 'Office purchase that needs a person',
    action: 'create_purchase_request',
    target: 'purchases/new',
    parameters: {
      purpose: SANDBOX_PURPOSE,
      category: 'office',
      amount: 80_000,
      title: 'Workstations',
    },
  },
  'purchase-block': {
    id: 'purchase-block',
    title: 'Restricted purchase',
    action: 'create_purchase_request',
    target: 'purchases/new',
    parameters: {
      purpose: SANDBOX_PURPOSE,
      category: 'restricted',
      amount: 1_000,
      title: 'Restricted item',
    },
  },
}

export function isSandboxScenarioId(value: string): value is SandboxScenarioId {
  return (SANDBOX_SCENARIO_IDS as readonly string[]).includes(value)
}
