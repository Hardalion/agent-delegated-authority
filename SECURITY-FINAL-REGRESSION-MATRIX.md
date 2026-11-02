# SECURITY-FINAL-REGRESSION-MATRIX

| Finding | Pre-pass status | Post-pass status | Primary regression |
| --- | --- | --- | --- |
| ADAP-001 policy substitution | Fixed | Fixed | `security-adversarial`, RT-05, reproduce |
| ADAP-002 object nonce | Fixed | Fixed | RT-07, reproduce |
| ADAP-003 non-finite compare | Fixed | Fixed | reproduce, RT-04 |
| ADAP-004 dangerous keys | Fixed | Fixed | reproduce |
| ADAP-005 prototype constraints | Fixed | Fixed | reproduce |
| ADAP-006 empty agentRole | Fixed | Fixed / strengthened | fail-closed, RT-08 |
| ADAP-007 schema before execute | Held | Held | authority path + RT-04 |
| ADAP-008 clock trust | Conditional (caller `now`) | Remediated | final-hardening RT-06, probe RT-06 |
| ADAP-009 amount domain | Fixed | Fixed | amount tests |
| ADAP-010 ambiguous targets | Partial (`resource/.` open) | Remediated | final-hardening RT-10, probe RT-10 |
| ADAP-011 receipt contradiction | Fixed | Fixed | RT-09, reproduce |
| RT-01 nested mutation | Remediated | Remediated | rt-remediation, probe, adversarial-final |
| RT-02 getter flip | Not repro | Not repro | probe |
| RT-03 unauth nonce consume | Remediated | Remediated | rt-remediation, probe |
| RT-04 uncaught canonicalize | Remediated | Remediated | rt-remediation, probe |
| RT-06 caller `now` | Open | Remediated | final-hardening, probe |
| RT-08 omitted role | Open | Remediated | fail-closed, probe |
| Policy URI first-register | Conditional | Hardened (required resolver; conflict fails) | final-hardening policy registration |
| Missing `defaultAction` = ALLOW | Open | Remediated | fail-closed, schema |
| Process-local nonce | Deployment limit | Interface + async double; still not distributed | adversarial-final shared backend |
| Attack 06 binding reason | Test gap (`nonce already used`) | Fixed (`approval is not bound to this intent`) | attacks.test + golden |
| CI audit `\|\| true` | Open | Closed (audit fails on high/critical) | `.github/workflows/ci.yml` |
| Executor throw then retry | Fixed | Fixed + seal honesty | final-hardening, adversarial-final |
| Approval dedup on forged signature | Gap | Fixed (record after verify) | final-hardening approval binding |
