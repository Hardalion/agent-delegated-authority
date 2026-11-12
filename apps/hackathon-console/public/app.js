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

const MEMORY_GUIDE = [
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

const SANDBOX_GUIDE = [
  {
    kind: 'narrate',
    kicker: '30 seconds',
    title: 'Authority before execution',
    body: 'The treasury assistant proposes operations against synthetic EUR records. ADAP checks authority before the sandbox API is called.',
  },
  { kind: 'run', scenario: 'status', kicker: 'Scenario A', title: 'Authorized status read' },
  { kind: 'run', scenario: 'pay-120', kicker: 'Scenario B', title: 'Autonomous €120 payment' },
  { kind: 'result', title: 'Why this was allowed' },
  { kind: 'run', scenario: 'pay-750', kicker: 'Scenario C', title: '€750 payment requires approval' },
  {
    kind: 'expect',
    title: 'Nothing has executed',
    body: 'The inbox holds a pending approval. The sandbox has not recorded the payment.',
    check: (current) => current.pending.length === 1,
  },
  { kind: 'approve', kicker: 'Approval', title: 'The demo operator approves the same intent' },
  { kind: 'run', scenario: 'pay-6000', kicker: 'Scenario D', title: '€6,000 payment is blocked' },
  { kind: 'result', title: 'The hard cap stopped execution' },
  { kind: 'run', scenario: 'vendor-change', kicker: 'Scenario E', title: 'Vendor account change requires approval' },
  { kind: 'run', scenario: 'purchase-block', kicker: 'Scenario F', title: 'Restricted purchase is blocked' },
  { kind: 'result', title: 'Receipt' },
]

function guideSteps() {
  return state && state.environment.rail === 'sandbox' ? SANDBOX_GUIDE : MEMORY_GUIDE
}

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]))
}

const i18n = window.ADAP_I18N

function money(cents, currency) {
  if (typeof cents !== 'number') return ''
  const code = currency === 'EUR' ? 'EUR' : 'USD'
  return (cents / 100).toLocaleString(i18n.locale(), { style: 'currency', currency: code })
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
  let response
  let body
  for (let attempt = 0; attempt < 3; attempt += 1) {
    response = await fetch(path, { cache: 'no-store', credentials: 'same-origin', ...options, headers })
    body = await response.json().catch(() => null)
    if (response.status !== 429 || attempt === 2) break
    await new Promise((resolve) => window.setTimeout(resolve, 250 * (2 ** attempt)))
  }
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
    showError(error.message || i18n.t('unreachable'))
  }
}

function render() {
  if (!state) return
  const key = JSON.stringify({ state, selectedId, guideIndex, lang: i18n.getLang() })
  if (key === renderedKey) return
  renderedKey = key
  healthFlag.textContent = state.health.ok ? i18n.t('ready') : i18n.t('checkFailed')
  railFlag.textContent = state.environment.simulatedRail ? i18n.t('railMemory') : i18n.t('railSandbox')
  teamFlag.textContent = `${i18n.t('team')} ${state.environment.teamId}`
  bannerEl.textContent = state.environment.simulatedRail ? i18n.t('bannerMemory') : i18n.t('bannerSandbox')
  loginEl.hidden = true
  scenarioEl.innerHTML = state.scenarios
    .map((item) => `<button type="button" data-action="run" data-scenario="${esc(item.id)}">${esc(i18n.scenario(item.title))}</button>`)
    .join('')
  const metrics = [
    [i18n.t('decisions'), state.metrics.decisions],
    [i18n.t('pending'), state.metrics.pending],
    [i18n.t('executed'), state.metrics.executed],
    [i18n.t('blocked'), state.metrics.blocked],
    [i18n.t('receiptsValid'), state.metrics.receiptsValid],
    [i18n.t('receiptsInvalid'), state.metrics.receiptsInvalid],
  ]
  metricsEl.innerHTML = metrics.map(([label, value]) => `<div class="metric"><b>${esc(value)}</b><span>${esc(label)}</span></div>`).join('')

  const item = selected()
  outcomeEl.className = `outcome ${item ? tone(item.outcomeLabel) : ''}`
  outcomeEl.textContent = item ? i18n.outcome(item.outcomeLabel) : i18n.t('noDecision')
  if (item && item.outcomeLabel === 'OUTCOME UNKNOWN') {
    outcomeEl.insertAdjacentHTML('beforeend', ` <button type="button" data-action="reconcile" data-id="${esc(item.correlationId)}">${esc(i18n.t('reconcile'))}</button>`)
  }
  flowEl.innerHTML = item
    ? item.stages.map((stage) => `<li><b>${esc(i18n.stage(stage.label))}</b><span class="status ${esc(stage.status)}">${esc(i18n.status(stage.status))}</span><span>${esc(i18n.detail(stage.detail))}</span></li>`).join('')
    : `<li class="empty">${esc(i18n.t('runScenario'))}</li>`

  const rows = item
    ? [
        [i18n.t('principal'), state.principal.id],
        [i18n.t('agent'), state.agent.id],
        [i18n.t('delegation'), state.delegation.id],
        [i18n.t('action'), item.action],
        [i18n.t('target'), item.target],
        [i18n.t('amount'), typeof item.parameters.amount === 'number' ? `${item.parameters.amount} ${i18n.t('minor')} (${money(item.parameters.amount, item.parameters.currency)})` : '—'],
        [i18n.t('currency'), item.parameters.currency || '—'],
        [i18n.t('execution'), item.executionMode || '—'],
        [i18n.t('downstreamId'), item.downstreamResourceId || '—'],
        [i18n.t('receiptStage'), item.receiptClaimsExecuted ? i18n.t('receiptSays') : i18n.t('receiptDoesNot')],
        [i18n.t('policy'), `${state.policy.name} @ ${state.policy.version}`],
        [i18n.t('policyHash'), item.policyHash || state.policy.hash],
        [i18n.t('decision'), item.decision],
        [i18n.t('rule'), item.ruleId],
        [i18n.t('reason'), item.reason],
        [i18n.t('note'), item.authorityNote || '—'],
        [i18n.t('intentHash'), item.intentHash || '—'],
        [i18n.t('nonce'), `${item.nonce} · ${item.nonceState}`],
        [i18n.t('correlation'), item.correlationId],
        [i18n.t('downstream'), item.downstreamStatus],
      ]
    : [[i18n.t('policy'), state.policy.name], [i18n.t('hash'), state.policy.hash], [i18n.t('agent'), state.agent.id]]
  inspectorEl.innerHTML = rows.map(([key, value]) => `<dt>${esc(key)}</dt><dd>${esc(value)}</dd>`).join('')

  inboxEl.innerHTML = state.pending.length
    ? state.pending.map((pending) => `
        <article class="inbox-item">
          <strong>${esc(i18n.outcome(pending.outcomeLabel))}</strong>
          <p>${esc(pending.action)} · ${esc(pending.reason)}</p>
          <p>${esc(i18n.t('intentLine'))} ${esc(pending.intentHash)}</p>
          <p>${esc(i18n.t('expires'))} ${esc(pending.nonce)}</p>
          <button type="button" data-action="approve" data-nonce="${esc(pending.nonce)}">${esc(i18n.t('approve'))}</button>
          <button type="button" data-action="reject" data-nonce="${esc(pending.nonce)}">${esc(i18n.t('reject'))}</button>
        </article>`).join('')
    : `<p class="empty">${esc(i18n.t('inboxEmpty'))}</p>`

  effectsEl.textContent = i18n.fill('effects', {
    reads: state.sideEffects.statusReads,
    payments: state.sideEffects.paymentsCreated,
    changes: state.sideEffects.beneficiaryChanges,
    denied: state.sideEffects.unauthorizedRejections,
  })
  paymentsEl.innerHTML = `<table><thead><tr><th>${esc(i18n.t('id'))}</th><th>${esc(i18n.t('beneficiary'))}</th><th>${esc(i18n.t('amount'))}</th><th>${esc(i18n.t('status'))}</th></tr></thead><tbody>${
    state.payments.map((payment) => `<tr><td>${esc(payment.id)}</td><td>${esc(payment.beneficiary)}</td><td>${esc(money(payment.amount, payment.currency))}</td><td>${esc(payment.status)}</td></tr>`).join('')
  }</tbody></table>`

  timelineEl.innerHTML = state.timeline.length
    ? state.timeline.slice(0, 40).map((event) => `<article class="event"><strong>${esc(event.type)}</strong> <small>${esc(event.source)} · ${esc(event.correlationId)}</small><div>${esc(event.reason || event.decision || '')}</div></article>`).join('')
    : `<p class="empty">${esc(i18n.t('noEvents'))}</p>`

  historyEl.innerHTML = state.cases.length
    ? state.cases.map((entry) => `
        <article class="history-item">
          <button type="button" data-action="select" data-id="${esc(entry.id)}">${esc(i18n.outcome(entry.outcomeLabel))}</button>
          <span>${esc(entry.action)} · ${esc(entry.decision)} · ${esc(entry.ruleId)}</span>
          <small>${esc(entry.createdAt)} · ${esc(entry.correlationId)}</small>
        </article>`).join('')
    : `<p class="empty">${esc(i18n.t('noHistory'))}</p>`

  if (item && item.receipt) {
    receiptEl.textContent = JSON.stringify(item.receipt, null, 2)
    verifyEl.textContent = item.verification
      ? `${item.verification.valid ? i18n.t('valid') : i18n.t('invalid')} · ${item.verification.verifier}${item.verification.errors.length ? ` · ${item.verification.errors.join('; ')}` : ''}`
      : i18n.t('notVerified')
  } else {
    receiptEl.textContent = item ? i18n.t('noReceiptCase') : i18n.t('noReceipt')
    verifyEl.textContent = ''
  }

  const timing = state.timings
  timingsEl.textContent = i18n.fill('timings', {
    auth: timing.lastAuthorizationMs ?? '—',
    approval: timing.lastApprovalMs ?? '—',
    verify: timing.lastVerifyMs ?? '—',
  })
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
  if (!window.confirm(i18n.t('resetConfirm'))) return
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
  const step = guideSteps()[guideIndex]
  guideEl.hidden = false
  document.querySelector('#guide-kicker').textContent = step.kicker ? i18n.guide(step.kicker) : i18n.t('presentation')
  document.querySelector('#guide-title').textContent = i18n.guide(step.title)
  const item = selected()
  const body = step.kind === 'result' && item ? `${item.reason} ${item.authorityNote || ''}`.trim() : (step.body ? i18n.guide(step.body) : i18n.t('continueReady'))
  document.querySelector('#guide-body').textContent = body
  const check = document.querySelector('#guide-check')
  if (step.check) {
    const ok = state && step.check(state)
    check.textContent = ok ? i18n.t('stepMatch') : i18n.t('stepMismatch')
  } else {
    check.textContent = ''
  }
}

async function guideNext() {
  const guide = guideSteps()
  const step = guide[guideIndex]
  if (step && step.check && state && !step.check(state)) return
  guideIndex += 1
  if (guideIndex >= guide.length) {
    guideEl.hidden = true
    guideIndex = -1
    return
  }
  const next = guide[guideIndex]
  if (next.kind === 'run') await runScenario(next.scenario)
  if (next.kind === 'approve') {
    const pending = state.pending[0]
    if (!pending) {
      showError(i18n.t('noPending'))
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
    showError(error.message || i18n.t('signInFailed'))
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
        showError(i18n.t('selectReceipt'))
      } else {
        const result = await request('/api/receipts/verify', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ receipt: item.receipt }),
        })
        verifyEl.textContent = `${result.valid ? i18n.t('valid') : i18n.t('invalid')} · ${result.verifier}${result.errors.length ? ` · ${result.errors.join('; ')}` : ''}`
      }
    } else if (action === 'export') {
      await exportEvidence()
    } else if (action === 'reset') {
      await resetDemo()
    }
  } catch (error) {
    showError(error.message || i18n.t('requestFailed'))
    await load()
  } finally {
    inflight = false
    document.querySelectorAll('button').forEach((node) => { node.disabled = false })
  }
})

document.querySelectorAll('input[name="sandbox-lang"]').forEach((input) => {
  input.checked = input.value === i18n.getLang()
  input.addEventListener('change', () => {
    if (!input.checked) return
    renderedKey = ''
    i18n.setLang(input.value)
    if (state) render()
  })
})

load()
setInterval(() => {
  if (!inflight) {
    load().catch(() => {
      setTimeout(() => { if (!inflight) load() }, 400)
    })
  }
}, 2000)
