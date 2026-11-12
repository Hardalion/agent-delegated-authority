/**
 * LangGraph node with ADAP in front.
 * A tool step is gated. A handoff to another agent needs a signed delegation chain.
 */
import { adapNode, WEEKEND_AGENT } from '../langgraph.mjs'

async function act(state) {
  return { ...state, didRun: true }
}

export const guarded = adapNode(act, { agentRole: WEEKEND_AGENT })
