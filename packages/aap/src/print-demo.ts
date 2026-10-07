import { formatLaunchProof, runLaunchProof } from './launch-proof.js'

const proof = await runLaunchProof()
console.log(formatLaunchProof(proof))
