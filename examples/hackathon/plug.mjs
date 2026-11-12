/**
 * Plug-and-play gate. Build the console once (`pnpm hackathon:start` does this),
 * then import this file from any Node agent.
 */
export {
  WEEKEND_AGENT,
  WEEKEND_POLICY,
  gateTool,
  normalizeToolCall,
} from '../../apps/hackathon-console/dist/weekend-gate.js'
