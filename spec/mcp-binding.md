# MCP binding (open questions)

**Status:** Not normative. Opened in review.

The README and the threat model name "an MCP server gateway" as one place to enforce ADAP. No document maps MCP onto ADAP's terms yet. A binding has to answer these before an MCP gateway can claim conformance.

## Tool identity

MCP tool names are chosen by each server and collide across servers. A server can change a tool's description or input schema after a grant was issued. `action` should identify the server, the tool name, and a hash of the tool definition (description and input schema). The delegation and the receipt bind that hash, and a changed definition is `BLOCK` until a new grant names it.

## Arguments and constraints

ADAP constraints name fixed parameters (`amount`, `currency`, `route`). MCP tools declare their own JSON Schema (`price_cents`, `items[].qty`, `to`). A binding needs a signed, pinned per-tool profile that maps schema paths to constraint dimensions, plus a closed-world option that rejects any argument the profile does not name.

## Targets

`target` is a string the agent supplies. For MCP, the gateway should derive it from the server identity and the arguments, so an agent cannot label a call with a target it was granted while the arguments point elsewhere.

## Results

Tool results return to the model's context, which is where indirect prompt injection enters. ADAP is silent on results. Open questions: does the receipt bind a hash of the result, and can policy label results as untrusted so that later calls in the same session are evaluated differently?

## Server-initiated requests

MCP servers can ask the client for sampling or elicitation. The binding should say whether those requests are intents, and under whose delegation they run.

## Session state

ADAP decisions are per call. Two calls that are each allowed (read a customer table, then send an external email) can still be the attack. A binding should state whether the gateway keeps session state (cumulative spend, call counts, data-flow labels) that policy can read, and if not, say that this class of attack is out of scope.
