import { evaluateToolCall } from 'adap-policy'

// 1. Το "επικίνδυνο" function που έχει φτιάξει η ομάδα
async function executeAgentAction(toolName: string, args: Record<string, unknown>) {
  console.log(`[EXECUTING] Τρέχει το εργαλείο: ${toolName} με δεδομένα:`, args)
  // Εδώ θα έμπαινε η πραγματική λογική του εργαλείου τους (π.χ. διαγραφή εγγραφών)
}

// 2. Το ADAP Wrapper
async function safeExecute(agentIntent: { toolName: string; toolArgs: Record<string, unknown> }) {
  console.log(`\n--- Έλεγχος Πρόθεσης Agent: ${agentIntent.toolName} ---`)

  // Η κλήση προς το ADAP
  const decision = evaluateToolCall({
    policy: 'basic-agent-authority', // Σύνδεση με το YAML policy
    toolName: agentIntent.toolName,
    toolArgs: agentIntent.toolArgs,
  })

  console.log(`[ADAP ΑΠΟΦΑΣΗ] Κανόνας: ${decision.ruleId} -> Ενέργεια: ${decision.action}`)

  if (decision.action === 'BLOCK') {
    console.error('❌ Η ενέργεια απορρίφθηκε από το Policy.')
    return
  }

  if (decision.action === 'REQUIRE_HUMAN') {
    console.warn('⚠️ Η ενέργεια απαιτεί έγκριση ανθρώπου. Σε αναμονή...')
    return
  }

  if (decision.action === 'ALLOW') {
    console.log('✅ Η ενέργεια εγκρίθηκε.')
    await executeAgentAction(agentIntent.toolName, agentIntent.toolArgs)
  }
}

// 3. Δοκιμή (Αυτά θα τα δημιουργούσε το LLM τους)
async function runDemo() {
  // Παράδειγμα 1: Ενέργεια που επιτρέπεται
  await safeExecute({ toolName: 'read', toolArgs: {} })

  // Παράδειγμα 2: Ενέργεια που απαιτεί έγκριση (το basic-agent-authority το θέτει σε REQUIRE_HUMAN)
  await safeExecute({ toolName: 'apply', toolArgs: { amount: 300 } })

  // Παράδειγμα 3: Ενέργεια που μπλοκάρεται λόγω ορίου (π.χ. > 500)
  await safeExecute({ toolName: 'apply', toolArgs: { amount: 800 } })
}

await runDemo()
