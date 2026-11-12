#!/usr/bin/env node
/**
 * Reproducible micro-benchmarks for ADAP hot paths.
 * Methodology: warm-up N iterations, then measure M iterations with process.hrtime.bigint.
 * Does not weaken security checks. Not a load test of a networked deployment.
 */
import { performance } from 'node:perf_hooks'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)

async function loadAdap() {
  try {
    return await import('adap')
  } catch {
    return await import('../packages/aap/dist/index.js')
  }
}

function summarize(label, samplesMs) {
  const sorted = [...samplesMs].sort((a, b) => a - b)
  const pct = (p) => sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))]
  const mean = samplesMs.reduce((a, b) => a + b, 0) / samplesMs.length
  return {
    label,
    n: samplesMs.length,
    mean_ms: Number(mean.toFixed(4)),
    p50_ms: Number(pct(50).toFixed(4)),
    p95_ms: Number(pct(95).toFixed(4)),
    p99_ms: Number(pct(99).toFixed(4)),
  }
}

async function main() {
  const adap = await loadAdap()
  const {
    createIdentity,
    signDelegation,
    signIntent,
    runAuthorityPath,
    NonceLedger,
    ImmutablePolicyResolver,
    FixedClock,
    sha256,
    signObject,
    verifyObject,
    importPublicKey,
  } = adap

  const NOW = new Date('2026-10-06T18:00:00.000Z')
  const ISSUED = NOW.toISOString()
  const EXPIRES = new Date(NOW.getTime() + 15 * 60 * 1000).toISOString()
  const policy = {
    version: '1.0.0',
    policyName: 'bench-allow',
    targetAgents: ['*'],
    defaultAction: 'BLOCK',
    rules: [
      { ruleId: 'allow_apply', action: 'ALLOW', condition: "tool.name == 'apply'", alertSeverity: 'LOW' },
    ],
  }
  const uri = 'bench-allow@1.0.0'
  const principal = createIdentity('prn_example')
  const agent = createIdentity('agt_personal')
  const signer = createIdentity('reference-runtime')
  const directory = new Map([
    [principal.id, principal.publicKey],
    [agent.id, agent.publicKey],
  ])
  const root = signDelegation(
    {
      delegation_id: 'del_root',
      issuer: principal.id,
      subject: agent.id,
      capabilities: [{ action: 'apply', target: 'resource/*', delegable: false }],
      constraints: { max_amount: 800 },
      issued_at: ISSUED,
      expires_at: EXPIRES,
    },
    principal,
  )

  const warm = 50
  const n = Number(process.env.ADAP_BENCH_N ?? 200)
  const sigSamples = []
  const policySamples = []
  const pathSamples = []

  for (let i = 0; i < warm + n; i++) {
    const payload = { i, t: ISSUED }
    const t0 = performance.now()
    const sig = signObject(payload, principal.privateKey)
    verifyObject(payload, sig, importPublicKey(principal.publicKey))
    const t1 = performance.now()
    if (i >= warm) sigSamples.push(t1 - t0)
  }

  for (let i = 0; i < warm + n; i++) {
    const t0 = performance.now()
    sha256(policy)
    const t1 = performance.now()
    if (i >= warm) policySamples.push(t1 - t0)
  }

  for (let i = 0; i < warm + n; i++) {
    const resolver = new ImmutablePolicyResolver()
    resolver.register(policy, uri)
    const intent = signIntent(
      {
        intent_id: `int_${i}`,
        actor: agent.id,
        delegation_chain: [root.delegation_id],
        action: 'apply',
        target: 'resource/example',
        parameters: { amount: 10 },
        nonce: `nonce-bench-${i}`,
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      agent,
    )
    const t0 = performance.now()
    await runAuthorityPath({
      chain: [root],
      intent,
      directory,
      trustedRootIssuers: [principal.id],
      policy,
      policyUri: uri,
      ledger: new NonceLedger(),
      signer,
      policyResolver: resolver,
      clock: new FixedClock(NOW),
      execute: () => ({ ok: true }),
    })
    const t1 = performance.now()
    if (i >= warm) pathSamples.push(t1 - t0)
  }

  const report = {
    methodology: {
      warm,
      measured: n,
      note: 'In-process reference path; excludes network and PostgreSQL contention unless ADAP_PG_URL set separately.',
    },
    results: [
      summarize('sign+verify Ed25519 object', sigSamples),
      summarize('policy content hash (sha256)', policySamples),
      summarize('full ALLOW path + execute (memory nonce)', pathSamples),
    ],
  }
  console.log(JSON.stringify(report, null, 2))
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
