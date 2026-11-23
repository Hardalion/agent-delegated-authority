import { formatAttacks, formatKnownGaps, runAttacks, runKnownGaps } from './attacks.js'

console.log(formatAttacks(await runAttacks()))
console.log('')
console.log(formatKnownGaps(await runKnownGaps()))
