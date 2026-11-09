const errorEl = document.querySelector('#error')
const metricsEl = document.querySelector('#metrics')
const flowEl = document.querySelector('#flow')
const inspectorEl = document.querySelector('#inspector')
const inboxEl = document.querySelector('#inbox')
const paymentsEl = document.querySelector('#payments')
const effectsEl = document.querySelector('#effects')
const timelineEl = document.querySelector('#timeline')
const historyEl = document.querySelector('#history')
const receiptEl = document.querySelector('#receipt')
const verifyEl = document.querySelector('#verify-result')
const outcomeEl = document.querySelector('#outcome')
const healthFlag = document.querySelector('#health-flag')
const railFlag = document.querySelector('#rail-flag')
const teamFlag = document.querySelector('#team-flag')
const bannerEl = document.querySelector('#banner')
const loginEl = document.querySelector('#login')
const scenarioEl = document.querySelector('#scenario-buttons')
const timingsEl = document.querySelector('#timings')
const guideEl = document.querySelector('#guide')
const passphraseEl = document.querySelector('#passphrase')

let state = null
let selectedId = null
let inflight = false
let guideIndex = -1
let renderedKey = ''

const GUIDE = [
  {
    kind: 'narrate',
    kicker: '30 seconds',
    title: 'Authority before execution',
    body: 'The treasury assistant can propose a payment operation. ADAP checks the principal, the delegation, the intent, and the policy before any simulated payment exists.',
  },
  { kind: 'run', scenario: 'status', kicker: 'Scenario A', title: 'Authorized status read' },
  { kind: 'result', title: 'Why this was allowed' },
  { kind: 'run', scenario: 'payment', kicker: 'Scenario B', title: 'Payment above the autonomous limit' },
  {
    kind: 'expect',
    title: 'Nothing has executed',
    body: 'The inbox is holding a pending approval. The simulated rail has not recorded a new payment.',
    check: (current) => current.pending.length === 1 && current.sideEffects.paymentsCreated === 0,
  },
  { kind: 'approve', kicker: 'Human approval', title: 'Principal approves the same intent' },
  { kind: 'result', title: 'One execution' },
  { kind: 'run', scenario: 'beneficiary', kicker: 'Scenario C', title: 'Beneficiary change' },
  {
    kind: 'expect',
    title: 'The beneficiary is unchanged',
    body: 'BLOCK means the executor was not called. The seed payment still names vendor_northwind.',
    check: (current) =>
      current.cases[0] &&
      current.cases[0].decision === 'BLOCK' &&
      current.cases[0].executed === false &&
      current.sideEffects.beneficiaryChanges === 0,
  },
  {
    kind: 'narrate',
    kicker: 'Evidence',
    title: 'Receipt',
    body: 'Open the receipt panel. Verification uses adap.verifyProtocolReceipt on the server. A green result is that check, not a label chosen by the page.',
  },
]

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]))
}

function money(cents, currency) {
  if (typeof cents !== 'number') return ''
  const code = currency === 'EUR' ? 'EUR' : 'USD'
  return (cents / 100).toLocaleString('en-US', { style: 'currency', currency: code })
}

function tone(label) {
  if (label === 'EXECUTED') return 'executed'
  if (label === 'OUTCOME UNKNOWN') return 'unknown'
  if (String(label).includes('AWAITING')) return 'waiting'
  return 'stopped'
}

function selected() {
  if (!state) return null
  return state.cases.find((item) => item.id === selectedId) || state.cases[0] || null
}

function showError(message) {
  errorEl.textContent = message || ''
}

async function request(path, options) {
  const headers = { 'x-adap-request': '1', ...(options && options.headers ? options.headers : {}) }
  const response = await fetch(path, { cache: 'no-store', credentials: 'same-origin', ...options, headers })
  const body = await response.json().catch(() => null)
  if (response.status === 401) {
    loginEl.hidden = false
  }
  if (!response.ok) {
    const message = body && body.error && body.error.message ? body.error.message : `Request failed (${response.status})`
    const error = new Error(message)
    error.status = response.status
    throw error
  }
  return body
}

async function load() {
  try {
    state = await request('/api/state')
    if (!selectedId && state.cases[0]) selectedId = state.cases[0].id
    render()
    showError('')
  } catch (error) {
    showError(error.message || 'The console could not reach the demo server.')
  }
}

function render() {
  if (!state) return
  const key = JSON.stringify({ state, selectedId, guideIndex })
  if (key === renderedKey) return
  renderedKey = key
  healthFlag.textContent = state.health.ok ? 'GATEWAY READY' : 'CHECK FAILED'
  railFlag.textContent = state.environment.railLabel
  teamFlag.textContent = `Team ${state.environment.teamId}`
  bannerEl.textContent = state.environment.simulatedRail
    ? 'Process memory. These records are simulated inside this process. No real money moves.'
    : 'Connected to the local sandbox API. Records are synthetic and persisted by that API. No real money moves.'
  loginEl.hidden = true
  scenarioEl.innerHTML = state.scenarios
    .map((item) => `<button type="button" data-action="run" data-scenario="${esc(item.id)}">${esc(item.title)}</button>`)
    .join('')
  const metrics = [
    ['Decisions', state.metrics.decisions],
    ['Pending', state.metrics.pending],
    ['Executed', state.metrics.executed],
    ['Blocked', state.metrics.blocked],
    ['Receipts valid', state.metrics.receiptsValid],
    ['Receipts invalid', state.metrics.receiptsInvalid],
  ]
  metricsEl.innerHTML = metrics.map(([label, value]) => `<div class="metric"><b>${esc(value)}</b><span>${esc(label)}</span></div>`).join('')

  const item = selected()
  outcomeEl.className = `outcome ${item ? tone(item.outcomeLabel) : ''}`
  outcomeEl.textContent = item ? item.outcomeLabel : 'No decision yet.'
  if (item && item.outcomeLabel === 'OUTCOME UNKNOWN') {
    outcomeEl.insertAdjacentHTML('beforeend', ` <button type="button" data-action="reconcile" data-id="${esc(item.correlationId)}">Reconcile</button>`)
  }
  flowEl.innerHTML = item
    ? item.stages.map((stage) => `<li><b>${esc(stage.label)}</b><span class="status ${esc(stage.status)}">${esc(stage.status)}</span><span>${esc(stage.detail)}</span></li>`).join('')
    : '<li class="empty">Run a scenario to see the authority path.</li>'

  const rows = item
    ? [
        ['Principal', state.principal.id],
        ['Agent', state.agent.id],
        ['Delegation', state.delegation.id],
        ['Action', item.action],
        ['Target', item.target],
        ['Amount', typeof item.parameters.amount === 'number' ? `${item.parameters.amount} minor units (${money(item.parameters.amount, item.parameters.currency)})` : '—'],
        ['Currency', item.parameters.currency || '—'],
        ['Execution', item.executionMode || '—'],
        ['Downstream id', item.downstreamResourceId || '—'],
        ['Receipt claim', item.receiptClaimsExecuted ? 'Receipt says executed' : 'Receipt does not say executed'],
        ['Policy', `${state.policy.name} @ ${state.policy.version}`],
        ['Policy hash', item.policyHash || state.policy.hash],
        ['Decision', item.decision],
        ['Rule', item.ruleId],
        ['Reason', item.reason],
        ['Note', item.authorityNote || '—'],
        ['Intent hash', item.intentHash || '—'],
        ['Nonce', `${item.nonce} · ${item.nonceState}`],
        ['Correlation', item.correlationId],
        ['Downstream', item.downstreamStatus],
      ]
    : [['Policy', state.policy.name], ['Hash', state.policy.hash], ['Agent', state.agent.id]]
  inspectorEl.innerHTML = rows.map(([key, value]) => `<dt>${esc(key)}</dt><dd>${esc(value)}</dd>`).join('')

  inboxEl.innerHTML = state.pending.length
    ? state.pending.map((pending) => `
        <article class="inbox-item">
          <strong>${esc(pending.outcomeLabel)}</strong>
          <p>${esc(pending.action)} · ${esc(pending.reason)}</p>
          <p>Intent ${esc(pending.intentHash)}</p>
          <p>Expires with the intent. Nonce ${esc(pending.nonce)}</p>
          <button type="button" data-action="approve" data-nonce="${esc(pending.nonce)}">Approve</button>
          <button type="button" data-action="reject" data-nonce="${esc(pending.nonce)}">Reject</button>
        </article>`).join('')
    : '<p class="empty">No approvals waiting. A pending decision stays here until an approver acts. Pending is not execution.</p>'

  effectsEl.textContent = `Reads ${state.sideEffects.statusReads} · payments created ${state.sideEffects.paymentsCreated} · beneficiary changes ${state.sideEffects.beneficiaryChanges} · unauthorized calls ${state.sideEffects.unauthorizedRejections}`
  paymentsEl.innerHTML = `<table><thead><tr><th>Id</th><th>Beneficiary</th><th>Amount</th><th>Status</th></tr></thead><tbody>${
    state.payments.map((payment) => `<tr><td>${esc(payment.id)}</td><td>${esc(payment.beneficiary)}</td><td>${esc(money(payment.amount, payment.currency))}</td><td>${esc(payment.status)}</td></tr>`).join('')
  }</tbody></table>`

  timelineEl.innerHTML = state.timeline.length
    ? state.timeline.slice(0, 40).map((event) => `<article class="event"><strong>${esc(event.type)}</strong> <small>${esc(event.source)} · ${esc(event.correlationId)}</small><div>${esc(event.reason || event.decision || '')}</div></article>`).join('')
    : '<p class="empty">No authority events yet.</p>'

  historyEl.innerHTML = state.cases.length
    ? state.cases.map((entry) => `
        <article class="history-item">
          <button type="button" data-action="select" data-id="${esc(entry.id)}">${esc(entry.outcomeLabel)}</button>
          <span>${esc(entry.action)} · ${esc(entry.decision)} · ${esc(entry.ruleId)}</span>
          <small>${esc(entry.createdAt)} · ${esc(entry.correlationId)}</small>
        </article>`).join('')
    : '<p class="empty">No executions yet.</p>'

  if (item && item.receipt) {
    receiptEl.textContent = JSON.stringify(item.receipt, null, 2)
    verifyEl.textContent = item.verification
      ? `${item.verification.valid ? 'Valid' : 'Invalid'} · ${item.verification.verifier}${item.verification.errors.length ? ` · ${item.verification.errors.join('; ')}` : ''}`
      : 'Not verified.'
  } else {
    receiptEl.textContent = item ? 'This decision has no receipt.' : 'No receipt selected.'
    verifyEl.textContent = ''
  }

  const timing = state.timings
  timingsEl.textContent = `Measured · authorization ${timing.lastAuthorizationMs ?? '—'} ms · approval ${timing.lastApprovalMs ?? '—'} ms · verify ${timing.lastVerifyMs ?? '—'} ms`
}

async function runScenario(scenario) {
  const body = await request(`/api/scenarios/${encodeURIComponent(scenario)}`, { method: 'POST' })
  state = body
  selectedId = body.cases[0] ? body.cases[0].id : selectedId
  render()
}

async function decide(kind, nonce) {
  const passphrase = passphraseEl.value
  try {
    state = await request(`/api/approvals/${encodeURIComponent(nonce)}/${kind}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ passphrase }),
    })
    selectedId = state.cases[0] ? state.cases[0].id : selectedId
    showError('')
  } catch (error) {
    showError(error.message)
    await load()
    return
  }
  render()
}

function download(filename, value) {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' })
  const link = document.createElement('a')
  link.href = URL.createObjectURL(blob)
  link.download = filename
  link.click()
  URL.revokeObjectURL(link.href)
}

async function exportEvidence() {
  const evidence = await request('/api/export')
  download('adap-hackathon-evidence.json', evidence)
}

async function resetDemo() {
  if (!window.confirm('Export evidence and reset the hackathon demo fixtures?')) return
  const evidence = await request('/api/export')
  download('adap-hackathon-evidence.json', evidence)
  const passphrase = passphraseEl.value
  const result = await request('/api/reset', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ confirm: 'RESET HACKATHON DEMO', passphrase, acknowledgeExport: true }),
  })
  state = result.state
  selectedId = null
  render()
}

function showGuide() {
  const step = GUIDE[guideIndex]
  guideEl.hidden = false
  document.querySelector('#guide-kicker').textContent = step.kicker || 'Presentation'
  document.querySelector('#guide-title').textContent = step.title
  const item = selected()
  const body = step.kind === 'result' && item ? `${item.reason} ${item.authorityNote || ''}`.trim() : step.body || 'Continue when you are ready.'
  document.querySelector('#guide-body').textContent = body
  const check = document.querySelector('#guide-check')
  if (step.check) {
    const ok = state && step.check(state)
    check.textContent = ok ? 'Observed outcome matches this step.' : 'Observed outcome does not match this step. The authority result above is unchanged.'
  } else {
    check.textContent = ''
  }
}

async function guideNext() {
  const step = GUIDE[guideIndex]
  if (step && step.check && state && !step.check(state)) return
  guideIndex += 1
  if (guideIndex >= GUIDE.length) {
    guideEl.hidden = true
    guideIndex = -1
    return
  }
  const next = GUIDE[guideIndex]
  if (next.kind === 'run') await runScenario(next.scenario)
  if (next.kind === 'approve') {
    const pending = state.pending[0]
    if (!pending) {
      showError('There is no pending approval to continue.')
      return
    }
    await decide('approve', pending.nonce)
  }
  showGuide()
}

document.querySelector('#login-button').addEventListener('click', async () => {
  const token = document.querySelector('#team-token').value
  try {
    await request('/api/session', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token }),
    })
    document.querySelector('#team-token').value = ''
    await load()
  } catch (error) {
    showError(error.message || 'Sign-in failed.')
  }
})

document.body.addEventListener('click', async (event) => {
  const button = event.target.closest('button')
  if (!button || inflight) return
  const action = button.dataset.action
  if (!action && button.id !== 'guide-next' && button.id !== 'guide-stop') return
  inflight = true
  document.querySelectorAll('button').forEach((node) => { node.disabled = true })
  try {
    if (button.id === 'guide-stop') {
      guideEl.hidden = true
      guideIndex = -1
    } else if (button.id === 'guide-next') {
      await guideNext()
    } else if (action === 'run') {
      await runScenario(button.dataset.scenario)
    } else if (action === 'approve' || action === 'reject') {
      await decide(action, button.dataset.nonce)
    } else if (action === 'select') {
      selectedId = button.dataset.id
      render()
    } else if (action === 'present') {
      guideIndex = 0
      showGuide()
    } else if (action === 'reconcile') {
      state = await request(`/api/cases/${encodeURIComponent(button.dataset.id)}/reconcile`, { method: 'POST' })
      selectedId = state.cases[0] ? state.cases[0].id : selectedId
      render()
    } else if (action === 'verify') {
      const item = selected()
      if (!item || !item.receipt) {
        showError('Select a decision that has a receipt.')
      } else {
        const result = await request('/api/receipts/verify', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ receipt: item.receipt }),
        })
        verifyEl.textContent = `${result.valid ? 'Valid' : 'Invalid'} · ${result.verifier}${result.errors.length ? ` · ${result.errors.join('; ')}` : ''}`
      }
    } else if (action === 'export') {
      await exportEvidence()
    } else if (action === 'reset') {
      await resetDemo()
    }
  } catch (error) {
    showError(error.message || 'The request failed.')
    await load()
  } finally {
    inflight = false
    document.querySelectorAll('button').forEach((node) => { node.disabled = false })
  }
})

load()
setInterval(() => {
  if (!inflight) {
    load().catch(() => {
      setTimeout(() => { if (!inflight) load() }, 400)
    })
  }
}, 2000)
