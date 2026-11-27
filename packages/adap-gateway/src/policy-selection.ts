import { assertCanonicalTarget, AuthorityError, type PolicyResolver } from 'adap-core'
import { z } from 'zod'

const BindingSchema = z.object({
  principalId: z.string().min(1),
  action: z.string().regex(/^[a-z][a-z0-9._-]{0,127}$/),
  target: z.string().min(1),
  policyUri: z.string().min(1),
}).strict()

const RequestSchema = z.object({
  chain: z.array(z.object({ issuer: z.string().min(1) })).min(1),
  intent: z.object({ action: z.string().min(1), target: z.string().min(1) }),
})

/** Exact resource bindings, loaded by the operator before serving requests. */
export function createPolicySelector(configuration: unknown, resolver: PolicyResolver) {
  const bindings = z.array(BindingSchema).min(1).parse(configuration)
  const policies = new Map<string, string>()
  for (const binding of bindings) {
    assertCanonicalTarget(binding.target)
    if (!resolver.resolveByUri(binding.policyUri)) {
      throw new Error('governing policy is absent from the operator registry')
    }
    const key = JSON.stringify([binding.principalId, binding.action, binding.target])
    if (policies.has(key)) throw new Error('duplicate governing policy binding')
    policies.set(key, binding.policyUri)
  }

  return (request: unknown, presentedPolicyUri: unknown): string => {
    const { chain, intent } = RequestSchema.parse(request)
    const key = JSON.stringify([chain[0]!.issuer, intent.action, intent.target])
    const policyUri = policies.get(key)
    if (!policyUri) throw new AuthorityError('policy', 'no governing policy for this request')
    if (presentedPolicyUri !== undefined && presentedPolicyUri !== policyUri) {
      throw new AuthorityError('policy', 'presented policy differs from the governing policy')
    }
    // These fields are authenticated by runAuthorityPath before any execution.
    // Selecting a document here does not authorize the submitted chain or intent.
    return policyUri
  }
}
