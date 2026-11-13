import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { parsePolicyEvalArgs, runPolicyEval } from './cli.js'

describe('adap-policy CLI', () => {
  it('parses minimal args', () => {
    expect(parsePolicyEvalArgs(['--tool', 'read'])).toEqual({
      toolName: 'read',
      toolArgs: undefined,
      agentRole: undefined,
      policy: undefined,
      policyFile: undefined,
      policyUri: undefined,
      json: false,
    })
  })

  it('blocks an apply over the cap via the bundled example', async () => {
    const decision = await runPolicyEval({
      toolName: 'apply',
      toolArgs: { amount: 800 },
      agentRole: 'agt_reader',
    })
    expect(decision.action).toBe('BLOCK')
    expect(decision.ruleId).toBe('block_over_cap')
  })

  it('resolves a local policy pin', async () => {
    const decision = await runPolicyEval({
      toolName: 'read',
      policyUri: 'basic-agent-authority@1.0.0',
      agentRole: 'agt_reader',
    })
    expect(decision.action).toBe('ALLOW')
  })

  it('fails closed when a pin has no local document', async () => {
    const decision = await runPolicyEval({
      toolName: 'read',
      policyUri: 'missing-example@1.0.0',
    })
    expect(decision.action).toBe('BLOCK')
    expect(decision.ruleId).toBe('PIN_UNRESOLVED')
  })
})

describe('adap-policy CLI argument parsing', () => {
  it('maps each documented option to its field', () => {
    expect(
      parsePolicyEvalArgs([
        '--tool', 'apply',
        '--args', '{"amount":800}',
        '--agent', 'agt_reader',
        '--policy', 'basic-agent-authority',
        '--policy-file', './policy.yaml',
        '--policy-uri', 'basic-agent-authority@1.0.0',
        '--json',
      ]),
    ).toEqual({
      toolName: 'apply',
      toolArgs: { amount: 800 },
      agentRole: 'agt_reader',
      policy: 'basic-agent-authority',
      policyFile: './policy.yaml',
      policyUri: 'basic-agent-authority@1.0.0',
      json: true,
    })
  })

  it('signals usage for -h and --help', () => {
    expect(() => parsePolicyEvalArgs(['-h'])).toThrow('help')
    expect(() => parsePolicyEvalArgs(['--tool', 'read', '--help'])).toThrow('help')
  })

  it('requires --tool with a value', () => {
    expect(parsePolicyEvalArgs(['--tool', 'read']).toolName).toBe('read')
    expect(() => parsePolicyEvalArgs(['--agent', 'agt_reader'])).toThrow('missing_tool')
    expect(() => parsePolicyEvalArgs(['--tool'])).toThrow('missing_tool')
  })

  it('parses --args as JSON and rejects malformed JSON', () => {
    expect(parsePolicyEvalArgs(['--tool', 'apply', '--args', '{"amount":800}']).toolArgs).toEqual({
      amount: 800,
    })
    expect(() => parsePolicyEvalArgs(['--tool', 'apply', '--args', '{bad'])).toThrow(SyntaxError)
  })
})

describe('adap-policy CLI policy selection', () => {
  let dir: string
  let denyReadPolicy: string

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'adap-policy-cli-'))
    denyReadPolicy = join(dir, 'deny-read.yaml')
    writeFileSync(
      denyReadPolicy,
      `version: "1.0.0"
policyName: deny-read-fixture
targetAgents: ["*"]
defaultAction: BLOCK
rules:
  - ruleId: deny_read
    action: BLOCK
    condition: "tool.name == 'read'"
    alertSeverity: CRITICAL
`,
    )
  })

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  it('evaluates --policy-file instead of the bundled example', async () => {
    const decision = await runPolicyEval({
      toolName: 'read',
      agentRole: 'agt_reader',
      policyFile: denyReadPolicy,
    })
    expect(decision.action).toBe('BLOCK')
    expect(decision.ruleId).toBe('deny_read')
  })

  it('gives --policy-file precedence over --policy-uri', async () => {
    const decision = await runPolicyEval({
      toolName: 'read',
      agentRole: 'agt_reader',
      policyFile: denyReadPolicy,
      policyUri: 'basic-agent-authority@1.0.0',
    })
    expect(decision.ruleId).toBe('deny_read')
  })

  it('rejects a missing policy file rather than evaluating another policy', async () => {
    await expect(
      runPolicyEval({
        toolName: 'read',
        agentRole: 'agt_reader',
        policyFile: join(dir, 'does-not-exist.yaml'),
      }),
    ).rejects.toThrow()
  })
})

describe('adap-policy CLI policy pins', () => {
  it('resolves a pin whose publisher matches the local document', async () => {
    const decision = await runPolicyEval({
      toolName: 'read',
      agentRole: 'agt_reader',
      policyUri: 'basic-agent-authority@1.0.0/publisher/example',
    })
    expect(decision.action).toBe('ALLOW')
  })

  it('fails closed when the pin names a different publisher', async () => {
    const decision = await runPolicyEval({
      toolName: 'read',
      agentRole: 'agt_reader',
      policyUri: 'basic-agent-authority@1.0.0/publisher/other',
    })
    expect(decision).toMatchObject({
      action: 'BLOCK',
      ruleId: 'PIN_UNRESOLVED',
      alertSeverity: 'CRITICAL',
    })
  })

  it('fails closed when the pinned version has no local document', async () => {
    const decision = await runPolicyEval({
      toolName: 'read',
      agentRole: 'agt_reader',
      policyUri: 'basic-agent-authority@1.0.1',
    })
    expect(decision.action).toBe('BLOCK')
    expect(decision.ruleId).toBe('PIN_UNRESOLVED')
  })

  it('rejects a pin without a full semver', async () => {
    await expect(
      runPolicyEval({ toolName: 'read', policyUri: 'basic-agent-authority@1' }),
    ).rejects.toThrow(/Required form/)
  })
})
