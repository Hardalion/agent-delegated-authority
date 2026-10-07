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

The model is allowed to change its mind. The authority boundary is not.
