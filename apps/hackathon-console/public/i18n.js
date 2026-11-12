const PACK = {
  skip: { el: 'Μετάβαση στο περιεχόμενο', en: 'Skip to content', fr: 'Aller au contenu', de: 'Zum Inhalt' },
  title: { el: 'Κονσόλα εξουσιοδότησης ADAP', en: 'ADAP Authority Console', fr: 'Console d’autorité ADAP', de: 'ADAP-Autoritätskonsole' },
  lede: {
    el: 'Ο agent μπορεί να προτείνει μια ενέργεια. Εκτελείται μόνο όταν το ADAP δίνει την εξουσιοδότηση.',
    en: 'An agent may propose an action. It can execute a consequential operation only when ADAP grants the authority.',
    fr: 'Un agent peut proposer une action. Elle ne s’exécute que si ADAP accorde l’autorité.',
    de: 'Ein Agent darf eine Aktion vorschlagen. Sie wird nur ausgeführt, wenn ADAP die Autorität erteilt.',
  },
  guideLink: { el: 'Σύνδεσε τον agent σου', en: 'Plug your agent in', fr: 'Branchez votre agent', de: 'Agent anschließen' },
  guideRest: {
    el: '. Η ίδια πύλη μπαίνει μπροστά από OpenAI, LangChain, Vercel AI SDK, Claude, Gemini, CrewAI και τα υπόλοιπα stacks του Σαββατοκύριακου.',
    en: '. The same gate sits in front of OpenAI, LangChain, Vercel AI SDK, Claude, Gemini, CrewAI, and the other weekend stacks.',
    fr: '. La même porte se place devant OpenAI, LangChain, Vercel AI SDK, Claude, Gemini, CrewAI et les autres stacks du week-end.',
    de: '. Dasselbe Gate sitzt vor OpenAI, LangChain, Vercel AI SDK, Claude, Gemini, CrewAI und den anderen Wochenend-Stacks.',
  },
  sandboxFlag: { el: 'SANDBOX HACKATHON', en: 'HACKATHON SANDBOX', fr: 'SANDBOX HACKATHON', de: 'HACKATHON-SANDBOX' },
  railLoading: { el: 'Η κατάσταση του rail φορτώνει από τον server', en: 'Rail status loads from the server', fr: 'L’état du rail vient du serveur', de: 'Der Rail-Status kommt vom Server' },
  railMemory: { el: 'Μνήμη διεργασίας. Προσομοιωμένο rail. Δεν κινούνται αληθινά χρήματα.', en: 'Process memory. Simulated rail. No real money.', fr: 'Mémoire du processus. Rail simulé. Pas d’argent réel.', de: 'Prozessspeicher. Simuliertes Rail. Kein echtes Geld.' },
  railSandbox: { el: 'Τοπικό sandbox API. Συνθετικά αρχεία. Δεν κινούνται αληθινά χρήματα.', en: 'Local sandbox API. Synthetic records. No real money.', fr: 'API sandbox locale. Enregistrements synthétiques. Pas d’argent réel.', de: 'Lokale Sandbox-API. Synthetische Datensätze. Kein echtes Geld.' },
  team: { el: 'Ομάδα', en: 'Team', fr: 'Équipe', de: 'Team' },
  checking: { el: 'Έλεγχος', en: 'Checking', fr: 'Vérification', de: 'Prüfung' },
  ready: { el: 'GATEWAY ΕΤΟΙΜΟ', en: 'GATEWAY READY', fr: 'GATEWAY PRÊT', de: 'GATEWAY BEREIT' },
  checkFailed: { el: 'Ο ΕΛΕΓΧΟΣ ΑΠΕΤΥΧΕ', en: 'CHECK FAILED', fr: 'ÉCHEC DU CONTRÔLE', de: 'PRÜFUNG FEHLGESCHLAGEN' },
  bannerMemory: { el: 'Μνήμη διεργασίας. Αυτά τα αρχεία είναι προσομοίωση μέσα σε αυτή τη διεργασία. Δεν κινούνται αληθινά χρήματα.', en: 'Process memory. These records are simulated inside this process. No real money moves.', fr: 'Mémoire du processus. Ces enregistrements sont simulés dans ce processus. Aucun argent réel ne circule.', de: 'Prozessspeicher. Diese Datensätze sind in diesem Prozess simuliert. Es fließt kein echtes Geld.' },
  bannerSandbox: { el: 'Συνδεδεμένο στο τοπικό sandbox API. Τα αρχεία είναι συνθετικά και τα κρατά αυτό το API. Δεν κινούνται αληθινά χρήματα.', en: 'Connected to the local sandbox API. Records are synthetic and persisted by that API. No real money moves.', fr: 'Connecté à l’API sandbox locale. Les enregistrements sont synthétiques et persistés par cette API. Aucun argent réel ne circule.', de: 'Mit der lokalen Sandbox-API verbunden. Die Datensätze sind synthetisch und werden von dieser API gespeichert. Es fließt kein echtes Geld.' },
  bannerSignedOut: { el: 'Sandbox hackathon. Αυτή η κονσόλα δεν μεταφέρει αληθινά χρήματα. Η ετικέτα του rail έρχεται από τον server μετά τη σύνδεση.', en: 'Hackathon sandbox. This console does not move real money. The rail label comes from the server after sign-in.', fr: 'Sandbox du hackathon. Cette console ne déplace pas d’argent réel. L’étiquette du rail vient du serveur après la connexion.', de: 'Hackathon-Sandbox. Diese Konsole bewegt kein echtes Geld. Die Rail-Bezeichnung kommt nach der Anmeldung vom Server.' },
  loginTitle: { el: 'Πρόσβαση ομάδας', en: 'Team access', fr: 'Accès équipe', de: 'Teamzugang' },
  loginHint: { el: 'Επικόλλησε το team token που τυπώθηκε στην εκκίνηση. Δεν αποθηκεύεται σε αυτή τη σελίδα.', en: 'Paste the team token printed at startup. It is not stored in this page.', fr: 'Collez le jeton d’équipe affiché au démarrage. Il n’est pas stocké dans cette page.', de: 'Fügen Sie das beim Start gedruckte Team-Token ein. Es wird auf dieser Seite nicht gespeichert.' },
  teamToken: { el: 'Team token', en: 'Team token', fr: 'Jeton d’équipe', de: 'Team-Token' },
  openSession: { el: 'Άνοιγμα συνεδρίας', en: 'Open session', fr: 'Ouvrir la session', de: 'Sitzung öffnen' },
  scenarios: { el: 'Σενάρια', en: 'Scenarios', fr: 'Scénarios', de: 'Szenarien' },
  scenariosHint: { el: 'Κάθε κουμπί ζητά από τον treasury agent να υπογράψει ένα intent. Το gateway αποφασίζει.', en: 'Each button asks the treasury agent to sign an intent. The gateway decides.', fr: 'Chaque bouton demande à l’agent treasury de signer une intention. La passerelle décide.', de: 'Jede Schaltfläche lässt den Treasury-Agenten eine Absicht signieren. Das Gateway entscheidet.' },
  present: { el: 'Λειτουργία παρουσίασης', en: 'Presentation mode', fr: 'Mode présentation', de: 'Präsentationsmodus' },
  continue: { el: 'Συνέχεια', en: 'Continue', fr: 'Continuer', de: 'Weiter' },
  exit: { el: 'Έξοδος', en: 'Exit', fr: 'Quitter', de: 'Beenden' },
  approver: { el: 'Εγκριτής', en: 'Approver', fr: 'Approbateur', de: 'Genehmiger' },
  passphrase: { el: 'Συνθηματικό εγκριτή', en: 'Demo approver passphrase', fr: 'Phrase de l’approbateur', de: 'Passphrase des Genehmigers' },
  passphraseHint: { el: 'Ελέγχεται στον server. Ο browser δεν υπογράφει την έγκριση.', en: 'Checked on the server. The browser does not sign the approval.', fr: 'Vérifié sur le serveur. Le navigateur ne signe pas l’approbation.', de: 'Wird auf dem Server geprüft. Der Browser signiert die Genehmigung nicht.' },
  live: { el: 'Ζωντανή εκτέλεση', en: 'Live execution', fr: 'Exécution en direct', de: 'Live-Ausführung' },
  noDecision: { el: 'Δεν υπάρχει απόφαση ακόμα.', en: 'No decision yet.', fr: 'Pas encore de décision.', de: 'Noch keine Entscheidung.' },
  inspector: { el: 'Επιθεώρηση εξουσιοδότησης', en: 'Authorization inspector', fr: 'Inspecteur d’autorisation', de: 'Autoritätsprüfung' },
  inbox: { el: 'Εισερχόμενα εγκρίσεων', en: 'Human approval inbox', fr: 'Boîte des approbations', de: 'Posteingang für Genehmigungen' },
  records: { el: 'Αρχεία downstream', en: 'Downstream records', fr: 'Enregistrements downstream', de: 'Downstream-Datensätze' },
  timeline: { el: 'Χρονολόγιο', en: 'Event timeline', fr: 'Chronologie', de: 'Zeitverlauf' },
  history: { el: 'Ιστορικό εκτελέσεων', en: 'Execution history', fr: 'Historique d’exécution', de: 'Ausführungsverlauf' },
  receiptTitle: { el: 'Επαλήθευση απόδειξης', en: 'Receipt verification', fr: 'Vérification du reçu', de: 'Belegprüfung' },
  verify: { el: 'Επαλήθευση επιλεγμένης απόδειξης', en: 'Verify selected receipt', fr: 'Vérifier le reçu sélectionné', de: 'Ausgewählten Beleg prüfen' },
  export: { el: 'Εξαγωγή τεκμηρίων', en: 'Export evidence', fr: 'Exporter les preuves', de: 'Nachweise exportieren' },
  reset: { el: 'Επαναφορά demo', en: 'Reset demo', fr: 'Réinitialiser la démo', de: 'Demo zurücksetzen' },
  noReceipt: { el: 'Δεν έχει επιλεγεί απόδειξη.', en: 'No receipt selected.', fr: 'Aucun reçu sélectionné.', de: 'Kein Beleg ausgewählt.' },
  noReceiptCase: { el: 'Αυτή η απόφαση δεν έχει απόδειξη.', en: 'This decision has no receipt.', fr: 'Cette décision n’a pas de reçu.', de: 'Diese Entscheidung hat keinen Beleg.' },
  footer: {
    el: 'Το ADAP είναι ανοιχτό πρωτόκολλο της Hardalion. Αυτό το sandbox είναι η reference implementation για το hackathon του GenAI Summit. Η ετικέτα ολοκλήρωσης σημαίνει ότι το downstream επέστρεψε αποτέλεσμα. Η ετικέτα άγνωστου σημαίνει ότι το αποτέλεσμα δεν επιβεβαιώθηκε και η κονσόλα δεν επαναλαμβάνει την κλήση.',
    en: 'ADAP is an open protocol by Hardalion. This sandbox is the reference implementation for the GenAI Summit hackathon. A completed label means the downstream system returned a result. An unknown label means the outcome was not confirmed, and the console does not repeat the call.',
    fr: 'ADAP est un protocole ouvert de Hardalion. Ce sandbox est l’implémentation de référence pour le hackathon du GenAI Summit. Une étiquette terminée signifie que le système downstream a renvoyé un résultat. Une étiquette inconnue signifie que le résultat n’est pas confirmé et que la console ne répète pas l’appel.',
    de: 'ADAP ist ein offenes Protokoll von Hardalion. Diese Sandbox ist die Referenzimplementierung für das Hackathon des GenAI Summit. Eine abgeschlossene Bezeichnung bedeutet, dass das Downstream-System ein Ergebnis geliefert hat. Eine unbekannte Bezeichnung bedeutet, dass das Ergebnis nicht bestätigt ist und die Konsole den Aufruf nicht wiederholt.',
  },
  decisions: { el: 'Αποφάσεις', en: 'Decisions', fr: 'Décisions', de: 'Entscheidungen' },
  pending: { el: 'Σε αναμονή', en: 'Pending', fr: 'En attente', de: 'Ausstehend' },
  executed: { el: 'Εκτελέστηκαν', en: 'Executed', fr: 'Exécutées', de: 'Ausgeführt' },
  blocked: { el: 'Αποκλείστηκαν', en: 'Blocked', fr: 'Bloquées', de: 'Blockiert' },
  receiptsValid: { el: 'Έγκυρες αποδείξεις', en: 'Receipts valid', fr: 'Reçus valides', de: 'Gültige Belege' },
  receiptsInvalid: { el: 'Άκυρες αποδείξεις', en: 'Receipts invalid', fr: 'Reçus invalides', de: 'Ungültige Belege' },
  runScenario: { el: 'Τρέξε ένα σενάριο για να δεις τη διαδρομή εξουσιοδότησης.', en: 'Run a scenario to see the authority path.', fr: 'Lancez un scénario pour voir le chemin d’autorité.', de: 'Starten Sie ein Szenario, um den Autoritätspfad zu sehen.' },
  inboxEmpty: { el: 'Δεν υπάρχουν εγκρίσεις σε αναμονή. Μια απόφαση σε αναμονή μένει εδώ μέχρι να ενεργήσει ένας άνθρωπος. Η αναμονή δεν είναι εκτέλεση.', en: 'No approvals waiting. A pending decision stays here until an approver acts. Pending is not execution.', fr: 'Aucune approbation en attente. Une décision en attente reste ici jusqu’à l’action d’une personne. En attente n’est pas une exécution.', de: 'Keine Genehmigungen warten. Eine ausstehende Entscheidung bleibt hier, bis jemand handelt. Ausstehend ist keine Ausführung.' },
  noEvents: { el: 'Δεν υπάρχουν γεγονότα εξουσιοδότησης ακόμα.', en: 'No authority events yet.', fr: 'Pas encore d’événements d’autorité.', de: 'Noch keine Autoritätsereignisse.' },
  noHistory: { el: 'Δεν υπάρχουν εκτελέσεις ακόμα.', en: 'No executions yet.', fr: 'Pas encore d’exécutions.', de: 'Noch keine Ausführungen.' },
  approve: { el: 'Έγκριση', en: 'Approve', fr: 'Approuver', de: 'Genehmigen' },
  reject: { el: 'Απόρριψη', en: 'Reject', fr: 'Rejeter', de: 'Ablehnen' },
  reconcile: { el: 'Συμφιλίωση', en: 'Reconcile', fr: 'Réconcilier', de: 'Abgleichen' },
  valid: { el: 'Έγκυρη', en: 'Valid', fr: 'Valide', de: 'Gültig' },
  invalid: { el: 'Άκυρη', en: 'Invalid', fr: 'Invalide', de: 'Ungültig' },
  notVerified: { el: 'Δεν επαληθεύτηκε.', en: 'Not verified.', fr: 'Non vérifié.', de: 'Nicht geprüft.' },
  principal: { el: 'Εντολέας', en: 'Principal', fr: 'Principal', de: 'Auftraggeber' },
  agent: { el: 'Agent', en: 'Agent', fr: 'Agent', de: 'Agent' },
  delegation: { el: 'Ανάθεση', en: 'Delegation', fr: 'Délégation', de: 'Delegation' },
  action: { el: 'Ενέργεια', en: 'Action', fr: 'Action', de: 'Aktion' },
  target: { el: 'Στόχος', en: 'Target', fr: 'Cible', de: 'Ziel' },
  amount: { el: 'Ποσό', en: 'Amount', fr: 'Montant', de: 'Betrag' },
  minor: { el: 'μικρές μονάδες', en: 'minor units', fr: 'unités mineures', de: 'Kleineinheiten' },
  currency: { el: 'Νόμισμα', en: 'Currency', fr: 'Devise', de: 'Währung' },
  execution: { el: 'Εκτέλεση', en: 'Execution', fr: 'Exécution', de: 'Ausführung' },
  downstreamId: { el: 'Downstream id', en: 'Downstream id', fr: 'Id downstream', de: 'Downstream-Id' },
  receiptSays: { el: 'Η απόδειξη λέει ότι εκτελέστηκε', en: 'Receipt says executed', fr: 'Le reçu dit exécuté', de: 'Beleg sagt ausgeführt' },
  receiptDoesNot: { el: 'Η απόδειξη δεν λέει ότι εκτελέστηκε', en: 'Receipt does not say executed', fr: 'Le reçu ne dit pas exécuté', de: 'Beleg sagt nicht ausgeführt' },
  intentStage: { el: 'Intent', en: 'Intent', fr: 'Intention', de: 'Absicht' },
  authorizationStage: { el: 'Εξουσιοδότηση', en: 'Authorization', fr: 'Autorisation', de: 'Autorisierung' },
  gatewayStage: { el: 'Gateway', en: 'Gateway', fr: 'Passerelle', de: 'Gateway' },
  receiptStage: { el: 'Απόδειξη', en: 'Receipt', fr: 'Reçu', de: 'Beleg' },
  policy: { el: 'Πολιτική', en: 'Policy', fr: 'Politique', de: 'Policy' },
  policyHash: { el: 'Hash πολιτικής', en: 'Policy hash', fr: 'Hash de politique', de: 'Policy-Hash' },
  decision: { el: 'Απόφαση', en: 'Decision', fr: 'Décision', de: 'Entscheidung' },
  rule: { el: 'Κανόνας', en: 'Rule', fr: 'Règle', de: 'Regel' },
  reason: { el: 'Αιτία', en: 'Reason', fr: 'Motif', de: 'Grund' },
  note: { el: 'Σημείωση', en: 'Note', fr: 'Note', de: 'Notiz' },
  intentHash: { el: 'Hash intent', en: 'Intent hash', fr: 'Hash d’intention', de: 'Absicht-Hash' },
  nonce: { el: 'Nonce', en: 'Nonce', fr: 'Nonce', de: 'Nonce' },
  correlation: { el: 'Correlation', en: 'Correlation', fr: 'Corrélation', de: 'Korrelation' },
  downstream: { el: 'Downstream', en: 'Downstream', fr: 'Downstream', de: 'Downstream' },
  hash: { el: 'Hash', en: 'Hash', fr: 'Hash', de: 'Hash' },
  id: { el: 'Id', en: 'Id', fr: 'Id', de: 'Id' },
  beneficiary: { el: 'Δικαιούχος', en: 'Beneficiary', fr: 'Bénéficiaire', de: 'Empfänger' },
  status: { el: 'Κατάσταση', en: 'Status', fr: 'Statut', de: 'Status' },
  effects: {
    el: 'Αναγνώσεις {reads} · πληρωμές {payments} · αλλαγές δικαιούχου {changes} · μη εξουσιοδοτημένες κλήσεις {denied}',
    en: 'Reads {reads} · payments created {payments} · beneficiary changes {changes} · unauthorized calls {denied}',
    fr: 'Lectures {reads} · paiements créés {payments} · changements de bénéficiaire {changes} · appels non autorisés {denied}',
    de: 'Lesungen {reads} · erstellte Zahlungen {payments} · Empfängeränderungen {changes} · unautorisierte Aufrufe {denied}',
  },
  intentLine: { el: 'Intent', en: 'Intent', fr: 'Intention', de: 'Absicht' },
  expires: { el: 'Λήγει μαζί με το intent. Nonce', en: 'Expires with the intent. Nonce', fr: 'Expire avec l’intention. Nonce', de: 'Läuft mit der Absicht ab. Nonce' },
  timings: {
    el: 'Μέτρηση · εξουσιοδότηση {auth} ms · έγκριση {approval} ms · επαλήθευση {verify} ms',
    en: 'Measured · authorization {auth} ms · approval {approval} ms · verify {verify} ms',
    fr: 'Mesuré · autorisation {auth} ms · approbation {approval} ms · vérification {verify} ms',
    de: 'Gemessen · Autorisierung {auth} ms · Genehmigung {approval} ms · Prüfung {verify} ms',
  },
  resetConfirm: { el: 'Να εξαχθούν τα τεκμήρια και να γίνει επαναφορά του demo;', en: 'Export evidence and reset the hackathon demo fixtures?', fr: 'Exporter les preuves et réinitialiser la démo ?', de: 'Nachweise exportieren und die Demo zurücksetzen?' },
  signInFailed: { el: 'Η σύνδεση απέτυχε.', en: 'Sign-in failed.', fr: 'La connexion a échoué.', de: 'Anmeldung fehlgeschlagen.' },
  unreachable: { el: 'Η κονσόλα δεν έφτασε τον server.', en: 'The console could not reach the demo server.', fr: 'La console n’a pas atteint le serveur.', de: 'Die Konsole hat den Server nicht erreicht.' },
  requestFailed: { el: 'Το αίτημα απέτυχε.', en: 'The request failed.', fr: 'La requête a échoué.', de: 'Die Anfrage ist fehlgeschlagen.' },
  noPending: { el: 'Δεν υπάρχει έγκριση σε αναμονή για να συνεχίσεις.', en: 'There is no pending approval to continue.', fr: 'Il n’y a pas d’approbation en attente.', de: 'Es gibt keine ausstehende Genehmigung.' },
  selectReceipt: { el: 'Επίλεξε μια απόφαση που έχει απόδειξη.', en: 'Select a decision that has a receipt.', fr: 'Sélectionnez une décision qui a un reçu.', de: 'Wählen Sie eine Entscheidung mit Beleg.' },
  continueReady: { el: 'Συνέχισε όταν είσαι έτοιμος.', en: 'Continue when you are ready.', fr: 'Continuez quand vous êtes prêt.', de: 'Weiter, wenn Sie bereit sind.' },
  presentation: { el: 'Παρουσίαση', en: 'Presentation', fr: 'Présentation', de: 'Präsentation' },
  stepMatch: { el: 'Το παρατηρούμενο αποτέλεσμα ταιριάζει σε αυτό το βήμα.', en: 'Observed outcome matches this step.', fr: 'Le résultat observé correspond à cette étape.', de: 'Das beobachtete Ergebnis passt zu diesem Schritt.' },
  stepMismatch: { el: 'Το παρατηρούμενο αποτέλεσμα δεν ταιριάζει. Το αποτέλεσμα εξουσιοδότησης από πάνω δεν αλλάζει.', en: 'Observed outcome does not match this step. The authority result above is unchanged.', fr: 'Le résultat observé ne correspond pas. Le résultat d’autorité ci-dessus ne change pas.', de: 'Das beobachtete Ergebnis passt nicht. Das Autoritätsergebnis oben bleibt unverändert.' },
}

const OUTCOME = {
  EXECUTED: { el: 'ΕΚΤΕΛΕΣΤΗΚΕ', en: 'EXECUTED', fr: 'EXÉCUTÉ', de: 'AUSGEFÜHRT' },
  'OUTCOME UNKNOWN': { el: 'ΑΓΝΩΣΤΟ ΑΠΟΤΕΛΕΣΜΑ', en: 'OUTCOME UNKNOWN', fr: 'RÉSULTAT INCONNU', de: 'ERGEBNIS UNBEKANNT' },
  'NOT EXECUTED · AWAITING APPROVAL': { el: 'ΔΕΝ ΕΚΤΕΛΕΣΤΗΚΕ · ΑΝΑΜΟΝΗ ΕΓΚΡΙΣΗΣ', en: 'NOT EXECUTED · AWAITING APPROVAL', fr: 'NON EXÉCUTÉ · EN ATTENTE', de: 'NICHT AUSGEFÜHRT · WARTET' },
  'NOT EXECUTED · REJECTED': { el: 'ΔΕΝ ΕΚΤΕΛΕΣΤΗΚΕ · ΑΠΟΡΡΙΦΘΗΚΕ', en: 'NOT EXECUTED · REJECTED', fr: 'NON EXÉCUTÉ · REJETÉ', de: 'NICHT AUSGEFÜHRT · ABGELEHNT' },
  'NOT EXECUTED · CONTINUED': { el: 'ΔΕΝ ΕΚΤΕΛΕΣΤΗΚΕ · ΣΥΝΕΧΙΣΤΗΚΕ', en: 'NOT EXECUTED · CONTINUED', fr: 'NON EXÉCUTÉ · POURSUIVI', de: 'NICHT AUSGEFÜHRT · FORTGESETZT' },
  'NOT EXECUTED · BLOCKED': { el: 'ΔΕΝ ΕΚΤΕΛΕΣΤΗΚΕ · ΑΠΟΚΛΕΙΣΤΗΚΕ', en: 'NOT EXECUTED · BLOCKED', fr: 'NON EXÉCUTÉ · BLOQUÉ', de: 'NICHT AUSGEFÜHRT · BLOCKIERT' },
  'NOT EXECUTED': { el: 'ΔΕΝ ΕΚΤΕΛΕΣΤΗΚΕ', en: 'NOT EXECUTED', fr: 'NON EXÉCUTÉ', de: 'NICHT AUSGEFÜHRT' },
}

const SCENARIO = {
  'Scenario A · Authorized status read': { el: 'Σενάριο Α · Εξουσιοδοτημένη ανάγνωση', en: 'Scenario A · Authorized status read', fr: 'Scénario A · Lecture autorisée', de: 'Szenario A · Autorisierte Lesung' },
  'Scenario B · Payment above the autonomous limit': { el: 'Σενάριο Β · Πληρωμή πάνω από το όριο', en: 'Scenario B · Payment above the autonomous limit', fr: 'Scénario B · Paiement au-dessus de la limite', de: 'Szenario B · Zahlung über dem Limit' },
  'Scenario C · Beneficiary change': { el: 'Σενάριο Γ · Αλλαγή δικαιούχου', en: 'Scenario C · Beneficiary change', fr: 'Scénario C · Changement de bénéficiaire', de: 'Szenario C · Empfängerwechsel' },
  'Hard-cap payment': { el: 'Πληρωμή πάνω από το ανώτατο όριο', en: 'Hard-cap payment', fr: 'Paiement au-dessus du plafond', de: 'Zahlung über der Obergrenze' },
  'Read a synthetic payment': { el: 'Ανάγνωση συνθετικής πληρωμής', en: 'Read a synthetic payment', fr: 'Lire un paiement synthétique', de: 'Synthetische Zahlung lesen' },
  'Pay €120': { el: 'Πληρωμή €120', en: 'Pay €120', fr: 'Payer 120 €', de: '120 € zahlen' },
  'Pay €750 (needs a person)': { el: 'Πληρωμή €750 (χρειάζεται άνθρωπο)', en: 'Pay €750 (needs a person)', fr: 'Payer 750 € (une personne doit approuver)', de: '750 € zahlen (Person nötig)' },
  'Pay €6,000 (over the cap)': { el: 'Πληρωμή €6.000 (πάνω από το όριο)', en: 'Pay €6,000 (over the cap)', fr: 'Payer 6 000 € (au-dessus du plafond)', de: '6.000 € zahlen (über der Grenze)' },
  'Change a vendor account': { el: 'Αλλαγή λογαριασμού προμηθευτή', en: 'Change a vendor account', fr: 'Changer un compte fournisseur', de: 'Lieferantenkonto ändern' },
  'Office purchase within limit': { el: 'Αγορά γραφείου μέσα στο όριο', en: 'Office purchase within limit', fr: 'Achat de bureau dans la limite', de: 'Büroeinkauf innerhalb des Limits' },
  'Office purchase that needs a person': { el: 'Αγορά γραφείου που χρειάζεται άνθρωπο', en: 'Office purchase that needs a person', fr: 'Achat de bureau qui exige une personne', de: 'Büroeinkauf, der eine Person braucht' },
  'Restricted purchase': { el: 'Περιορισμένη αγορά', en: 'Restricted purchase', fr: 'Achat restreint', de: 'Eingeschränkter Einkauf' },
}

const STAGE = {
  Principal: 'principal',
  Delegation: 'delegation',
  Agent: 'agent',
  Intent: 'intentStage',
  Policy: 'policy',
  Authorization: 'authorizationStage',
  Gateway: 'gatewayStage',
  Execution: 'execution',
  Receipt: 'receiptStage',
}

const STATUS = {
  complete: { el: 'ολοκληρώθηκε', en: 'complete', fr: 'terminé', de: 'fertig' },
  blocked: { el: 'αποκλείστηκε', en: 'blocked', fr: 'bloqué', de: 'blockiert' },
  not_executed: { el: 'δεν εκτελέστηκε', en: 'not executed', fr: 'non exécuté', de: 'nicht ausgeführt' },
  skipped: { el: 'παραλείφθηκε', en: 'skipped', fr: 'ignoré', de: 'übersprungen' },
  failed: { el: 'απέτυχε', en: 'failed', fr: 'échoué', de: 'fehlgeschlagen' },
  unknown: { el: 'άγνωστο', en: 'unknown', fr: 'inconnu', de: 'unbekannt' },
  waiting: { el: 'αναμονή', en: 'waiting', fr: 'en attente', de: 'wartend' },
}

const DETAIL = {
  'Issuer key verified.': { el: 'Το κλειδί του εκδότη επαληθεύτηκε.', en: 'Issuer key verified.', fr: 'Clé de l’émetteur vérifiée.', de: 'Ausstellerschlüssel geprüft.' },
  'Signature was not verified.': { el: 'Η υπογραφή δεν επαληθεύτηκε.', en: 'Signature was not verified.', fr: 'La signature n’a pas été vérifiée.', de: 'Signatur wurde nicht geprüft.' },
  'Delegation accepted for this intent.': { el: 'Η ανάθεση έγινε δεκτή για αυτό το intent.', en: 'Delegation accepted for this intent.', fr: 'Délégation acceptée pour cette intention.', de: 'Delegation für diese Absicht akzeptiert.' },
  'Not reached.': { el: 'Δεν έφτασε.', en: 'Not reached.', fr: 'Non atteint.', de: 'Nicht erreicht.' },
  'Agent signature verified.': { el: 'Η υπογραφή του agent επαληθεύτηκε.', en: 'Agent signature verified.', fr: 'Signature de l’agent vérifiée.', de: 'Agentensignatur geprüft.' },
  'Agent signature was not verified.': { el: 'Η υπογραφή του agent δεν επαληθεύτηκε.', en: 'Agent signature was not verified.', fr: 'La signature de l’agent n’a pas été vérifiée.', de: 'Agentensignatur wurde nicht geprüft.' },
  'Intent hash was not established.': { el: 'Το hash του intent δεν σχηματίστηκε.', en: 'Intent hash was not established.', fr: 'Le hash d’intention n’a pas été établi.', de: 'Der Absicht-Hash wurde nicht gebildet.' },
  'Policy evaluation was not reached.': { el: 'Η αξιολόγηση πολιτικής δεν έφτασε.', en: 'Policy evaluation was not reached.', fr: 'L’évaluation de politique n’a pas été atteinte.', de: 'Die Policy-Prüfung wurde nicht erreicht.' },
  'The gateway called the downstream rail and received a completed result.': { el: 'Το gateway κάλεσε το downstream και πήρε ολοκληρωμένο αποτέλεσμα.', en: 'The gateway called the downstream rail and received a completed result.', fr: 'La passerelle a appelé le rail downstream et a reçu un résultat terminé.', de: 'Das Gateway hat das Downstream-Rail aufgerufen und ein abgeschlossenes Ergebnis erhalten.' },
  'Not called. Waiting for human approval.': { el: 'Δεν καλέστηκε. Αναμονή για έγκριση ανθρώπου.', en: 'Not called. Waiting for human approval.', fr: 'Non appelé. En attente d’une personne.', de: 'Nicht aufgerufen. Wartet auf eine Person.' },
  'Not called. The approver rejected the intent.': { el: 'Δεν καλέστηκε. Ο εγκριτής απέρριψε το intent.', en: 'Not called. The approver rejected the intent.', fr: 'Non appelé. L’approbateur a rejeté l’intention.', de: 'Nicht aufgerufen. Der Genehmiger hat die Absicht abgelehnt.' },
  'This record did not execute. A later approval continued the intent.': { el: 'Αυτή η εγγραφή δεν εκτελέστηκε. Μια μεταγενέστερη έγκριση συνέχισε το intent.', en: 'This record did not execute. A later approval continued the intent.', fr: 'Cet enregistrement ne s’est pas exécuté. Une approbation ultérieure a poursuivi l’intention.', de: 'Dieser Datensatz wurde nicht ausgeführt. Eine spätere Genehmigung hat die Absicht fortgesetzt.' },
  'Not called.': { el: 'Δεν καλέστηκε.', en: 'Not called.', fr: 'Non appelé.', de: 'Nicht aufgerufen.' },
  'Executor was invoked. The downstream outcome is unknown.': { el: 'Ο executor κλήθηκε. Το downstream αποτέλεσμα είναι άγνωστο.', en: 'Executor was invoked. The downstream outcome is unknown.', fr: 'L’exécuteur a été appelé. Le résultat downstream est inconnu.', de: 'Der Executor wurde aufgerufen. Das Downstream-Ergebnis ist unbekannt.' },
  'Executor invoked.': { el: 'Ο executor κλήθηκε.', en: 'Executor invoked.', fr: 'Exécuteur appelé.', de: 'Executor aufgerufen.' },
  'Authority path finished. Executor not invoked.': { el: 'Η διαδρομή εξουσιοδότησης τελείωσε. Ο executor δεν κλήθηκε.', en: 'Authority path finished. Executor not invoked.', fr: 'Le chemin d’autorité est terminé. L’exécuteur n’a pas été appelé.', de: 'Der Autoritätspfad ist beendet. Der Executor wurde nicht aufgerufen.' },
  'verifyProtocolReceipt accepted the issuer signature.': { el: 'Το verifyProtocolReceipt δέχτηκε την υπογραφή του εκδότη.', en: 'verifyProtocolReceipt accepted the issuer signature.', fr: 'verifyProtocolReceipt a accepté la signature de l’émetteur.', de: 'verifyProtocolReceipt hat die Ausstellersignatur akzeptiert.' },
  'Receipt present and verification failed.': { el: 'Υπάρχει απόδειξη και η επαλήθευση απέτυχε.', en: 'Receipt present and verification failed.', fr: 'Reçu présent et vérification échouée.', de: 'Beleg vorhanden und Prüfung fehlgeschlagen.' },
  'No receipt.': { el: 'Χωρίς απόδειξη.', en: 'No receipt.', fr: 'Pas de reçu.', de: 'Kein Beleg.' },
}

const GUIDE_TEXT = {
  '30 seconds': { el: '30 δευτερόλεπτα', en: '30 seconds', fr: '30 secondes', de: '30 Sekunden' },
  'Authority before execution': { el: 'Εξουσιοδότηση πριν από την εκτέλεση', en: 'Authority before execution', fr: 'Autorité avant l’exécution', de: 'Autorität vor der Ausführung' },
  'The treasury assistant can propose a payment operation. ADAP checks the principal, the delegation, the intent, and the policy before any simulated payment exists.': {
    el: 'Ο treasury assistant μπορεί να προτείνει μια πληρωμή. Το ADAP ελέγχει τον εντολέα, την ανάθεση, το intent και την πολιτική πριν υπάρξει πληρωμή.',
    en: 'The treasury assistant can propose a payment operation. ADAP checks the principal, the delegation, the intent, and the policy before any simulated payment exists.',
    fr: 'L’assistant treasury peut proposer un paiement. ADAP vérifie le principal, la délégation, l’intention et la politique avant qu’un paiement existe.',
    de: 'Der Treasury-Assistent kann eine Zahlung vorschlagen. ADAP prüft Auftraggeber, Delegation, Absicht und Policy, bevor eine Zahlung existiert.',
  },
  'Scenario A': { el: 'Σενάριο Α', en: 'Scenario A', fr: 'Scénario A', de: 'Szenario A' },
  'Authorized status read': { el: 'Εξουσιοδοτημένη ανάγνωση', en: 'Authorized status read', fr: 'Lecture autorisée', de: 'Autorisierte Lesung' },
  'Why this was allowed': { el: 'Γιατί επιτράπηκε', en: 'Why this was allowed', fr: 'Pourquoi c’était permis', de: 'Warum das erlaubt war' },
  'Scenario B': { el: 'Σενάριο Β', en: 'Scenario B', fr: 'Scénario B', de: 'Szenario B' },
  'Payment above the autonomous limit': { el: 'Πληρωμή πάνω από το όριο', en: 'Payment above the autonomous limit', fr: 'Paiement au-dessus de la limite', de: 'Zahlung über dem Limit' },
  'Nothing has executed': { el: 'Τίποτα δεν εκτελέστηκε', en: 'Nothing has executed', fr: 'Rien ne s’est exécuté', de: 'Nichts wurde ausgeführt' },
  'The inbox is holding a pending approval. The simulated rail has not recorded a new payment.': {
    el: 'Τα εισερχόμενα κρατούν μια έγκριση σε αναμονή. Δεν έχει καταγραφεί νέα πληρωμή.',
    en: 'The inbox is holding a pending approval. The simulated rail has not recorded a new payment.',
    fr: 'La boîte garde une approbation en attente. Aucun nouveau paiement n’a été enregistré.',
    de: 'Der Posteingang hält eine ausstehende Genehmigung. Es wurde keine neue Zahlung erfasst.',
  },
  'Human approval': { el: 'Έγκριση ανθρώπου', en: 'Human approval', fr: 'Approbation humaine', de: 'Menschliche Genehmigung' },
  'Principal approves the same intent': { el: 'Ο εντολέας εγκρίνει το ίδιο intent', en: 'Principal approves the same intent', fr: 'Le principal approuve la même intention', de: 'Der Auftraggeber genehmigt dieselbe Absicht' },
  'One execution': { el: 'Μία εκτέλεση', en: 'One execution', fr: 'Une exécution', de: 'Eine Ausführung' },
  'Scenario C': { el: 'Σενάριο Γ', en: 'Scenario C', fr: 'Scénario C', de: 'Szenario C' },
  'Beneficiary change': { el: 'Αλλαγή δικαιούχου', en: 'Beneficiary change', fr: 'Changement de bénéficiaire', de: 'Empfängerwechsel' },
  'The beneficiary is unchanged': { el: 'Ο δικαιούχος δεν άλλαξε', en: 'The beneficiary is unchanged', fr: 'Le bénéficiaire est inchangé', de: 'Der Empfänger ist unverändert' },
  'BLOCK means the executor was not called. The seed payment still names vendor_northwind.': {
    el: 'Το BLOCK σημαίνει ότι ο executor δεν καλέστηκε. Η αρχική πληρωμή λέει ακόμα vendor_northwind.',
    en: 'BLOCK means the executor was not called. The seed payment still names vendor_northwind.',
    fr: 'BLOCK signifie que l’exécuteur n’a pas été appelé. Le paiement initial nomme encore vendor_northwind.',
    de: 'BLOCK bedeutet, dass der Executor nicht aufgerufen wurde. Die Ausgangszahlung heißt weiter vendor_northwind.',
  },
  Evidence: { el: 'Τεκμήρια', en: 'Evidence', fr: 'Preuve', de: 'Nachweis' },
  Receipt: { el: 'Απόδειξη', en: 'Receipt', fr: 'Reçu', de: 'Beleg' },
  'Open the receipt panel. Verification uses adap.verifyProtocolReceipt on the server. A green result is that check, not a label chosen by the page.': {
    el: 'Άνοιξε την απόδειξη. Η επαλήθευση χρησιμοποιεί adap.verifyProtocolReceipt στον server. Το έγκυρο αποτέλεσμα είναι αυτός ο έλεγχος, όχι μια ετικέτα της σελίδας.',
    en: 'Open the receipt panel. Verification uses adap.verifyProtocolReceipt on the server. A green result is that check, not a label chosen by the page.',
    fr: 'Ouvrez le reçu. La vérification utilise adap.verifyProtocolReceipt sur le serveur. Un résultat valide est ce contrôle, pas une étiquette choisie par la page.',
    de: 'Öffnen Sie den Beleg. Die Prüfung nutzt adap.verifyProtocolReceipt auf dem Server. Ein gültiges Ergebnis ist diese Prüfung, nicht eine Bezeichnung der Seite.',
  },
}

const LOCALES = { el: 'el-GR', en: 'en-US', fr: 'fr-FR', de: 'de-DE' }

function readLang() {
  const stored = localStorage.getItem('adap-lang')
  return PACK.title[stored] ? stored : 'el'
}

let lang = readLang()

function t(key) {
  const row = PACK[key]
  if (!row) return key
  return row[lang] || row.en || key
}

function fill(key, values) {
  return t(key).replace(/\{(\w+)\}/g, (_, name) => (values[name] == null ? '—' : String(values[name])))
}

function phrase(table, value) {
  if (value == null) return ''
  const row = table[value]
  if (!row) return String(value)
  return row[lang] || row.en || String(value)
}

function applyStatic() {
  document.documentElement.lang = lang === 'el' ? 'el' : lang
  document.querySelectorAll('[data-i18n]').forEach((node) => {
    node.textContent = t(node.dataset.i18n)
  })
  document.querySelectorAll('[data-i18n-placeholder]').forEach((node) => {
    node.placeholder = t(node.dataset.i18nPlaceholder)
  })
  const title = document.querySelector('title')
  if (title && document.body.dataset.page === 'sandbox') title.textContent = t('title')
}

function setLang(next) {
  lang = PACK.title[next] ? next : 'el'
  localStorage.setItem('adap-lang', lang)
  applyStatic()
  window.dispatchEvent(new CustomEvent('adap-lang', { detail: lang }))
}

window.ADAP_I18N = {
  t,
  fill,
  setLang,
  getLang: () => lang,
  outcome: (value) => phrase(OUTCOME, value),
  scenario: (title) => phrase(SCENARIO, title),
  stage: (label) => (STAGE[label] ? t(STAGE[label]) : label),
  status: (value) => phrase(STATUS, value),
  detail: (value) => phrase(DETAIL, value),
  guide: (value) => phrase(GUIDE_TEXT, value),
  locale: () => LOCALES[lang] || 'en-US',
}

applyStatic()
