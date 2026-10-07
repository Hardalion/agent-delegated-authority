import { describe, expect, it } from 'vitest'
import { runAgentToAgentDemo } from './agents.js'
import { importPublicKey, sha256 } from './crypto.js'
import { verifyProtocolReceipt } from './path.js'
import { unsignedDelegation } from './protocol.js'

describe('agent to agent authority', () => {
  it('lets agent B read, holds apply for the principal, then receipts the approved action', async () => {
    const demo = await runAgentToAgentDemo()
    const published = JSON.stringify({
      agentBView: demo.agentBView,
      contexts: demo.contexts,
      receipts: [
        demo.read.receipt,
        demo.applyPending.receipt,
        demo.apply.receipt,
        demo.agentBApply.receipt,
        demo.replay.receipt,
      ],
      result: demo.apply.result,
    })

    expect(demo.agentBView.capabilities).toEqual(['read'])
    expect(demo.read.decision).toBe('ALLOW')
    expect(demo.read.executed).toBe(true)
    expect(demo.read.receipt.identity.delegationChain).toEqual(['agt_a', 'agt_b'])
    expect(demo.read.receipt.authority).toEqual({
      principalId: 'prn_example',
      chain: [
        { delegationId: 'del_root', subject: 'agt_a', hash: sha256(unsignedDelegation(demo.root)) },
        { delegationId: 'del_b', subject: 'agt_b', hash: sha256(unsignedDelegation(demo.toAgentB)) },
      ],
    })

    expect(demo.agentBApply.decision).toBe('BLOCK')
    expect(demo.agentBApply.ruleId).toBe('capability')
    expect(demo.agentBApply.executed).toBe(false)

    expect(demo.redelegatedApply.ruleId).toBe('narrowing')
    expect(demo.redelegatedApply.executed).toBe(false)
    expect(demo.overCap.ruleId).toBe('constraint')

    expect(demo.applyPending.decision).toBe('REQUIRE_HUMAN')
    expect(demo.applyPending.executed).toBe(false)
    expect(demo.applyPending.receipt.human?.status).toBe('pending')
    expect(demo.applyPending.receipt.identity.principalId).toBe('prn_example')
    expect(demo.applyPending.receipt.identity.delegationChain).toEqual(['agt_a'])

    expect(demo.apply.decision).toBe('ALLOW')
    expect(demo.apply.executed).toBe(true)
    expect(demo.apply.receipt.human?.status).toBe('approved')
    expect(demo.apply.receipt.execution?.targetSystem).toBe('resource/example')
    expect(demo.apply.result).toEqual({ ref: 'act-example', amount: 420 })

    expect(demo.replay.decision).toBe('BLOCK')
    expect(demo.replay.ruleId).toBe('replay')
    expect(demo.replay.executed).toBe(false)
    expect(demo.executionCount).toBe(2)

    const signerKey = importPublicKey(demo.signerPublicKey)
    expect(verifyProtocolReceipt(demo.apply.receipt, signerKey).valid).toBe(true)
    expect(published).not.toContain('pan')
    expect(published).not.toContain('secret')
  })
})
