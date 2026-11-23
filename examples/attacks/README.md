# Attacks

`pnpm attacks` runs these six cases through the reference path. Each file is that output. A test fails if a file diverges.

| File | Refused |
| --- | --- |
| `01-over-delegation` | A child grant raises the parent's `max_amount`. |
| `02-privilege-escalation` | A capability marked `delegable: false` is passed on. |
| `03-prompt-injection` | Instruction text asks for more than the delegated maximum. The text is not a constraint. |
| `04-replay` | The same signed intent is presented again after the nonce was consumed. |
| `05-expired-delegation` | The grant is presented after `expires_at`. |
| `06-post-approval-mutation` | The intent changes after a person approved a different intent hash. |

Each refusal is `BLOCK`. The executor is not called for that attempt. The receipt verifies when the issuer public key is held.

## Known gaps

`pnpm attacks` then prints the cases below under `KNOWN GAPS`. They run the same path and are not refused today. Each file records the current result, so the suite does not claim a block it does not have. A test fails if a file diverges, and it also fails if a future change starts refusing the call, so the fixture and this table move together.

| File | Current result |
| --- | --- |
| `07-in-grant-injection` | `ALLOW`, executor called, receipt verifies. Text in a page the agent reads redirects `search` to `airline/partner-deals`, which is inside the `airline/*` grant. ADAP checks the action, the target, the amount, and the policy. It does not check why the model chose the call, and the receipt does not record which input caused the intent. Tracked in #48. |

Until that is addressed, name exact targets instead of wildcards for consequential actions, and keep them behind `REQUIRE_HUMAN`.

The model is allowed to change its mind. The authority boundary is not.
