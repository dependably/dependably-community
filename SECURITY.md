# Security Policy

To report a security vulnerability, please use [GitHub's private vulnerability reporting](https://github.com/dependably/dependably-community/security/advisories/new).

Do not open a public issue for security vulnerabilities.

## Disclosure SLA

| Stage | Target |
| --- | --- |
| Acknowledge receipt | within **3 business days** |
| Initial severity assessment | within **7 business days** |
| Fix or documented mitigation for High/Critical | within **30 days** of confirmation |
| Coordinated public disclosure | after a fix ships, by mutual agreement (embargo honoured) |

These are targets for the maintainer team, not contractual guarantees. Please allow the
above windows before any public disclosure so a fix and, where relevant, an operator advisory
can land first.

## Supported versions

Security fixes land on the latest released minor and are shipped in a new patch release; there
are no long-term back-support branches for a pre-1.0 project. Operators should track the
latest release.

| Version | Supported |
| --- | --- |
| Latest `0.4.x` | Yes — fixes released as new `0.4.x` patches |
| Older `0.x` | No — upgrade to the latest `0.4.x` |

The threat model these fixes defend is documented in [`docs/threat-model.md`](docs/threat-model.md).

## Leaked credentials

If the secret-scan CI job fails, or a credential is otherwise found in this repository's source or history, treat it as compromised regardless of where it was committed from. Run the response below in order — do not stop at "remove from repo".

1. **Revoke at the provider.** Disable or delete the credential in the issuing system (cloud console, package registry, identity provider, etc.) before doing anything else. A scrubbed git history does not invalidate a leaked token.
2. **Remove from the repo.** Delete the secret from the working tree. If it landed on a long-lived branch or in history, rewrite with [`git filter-repo`](https://github.com/newren/git-filter-repo) and force-push, then have collaborators re-clone.
3. **Rotate and redeploy.** Issue a replacement, update every consumer (deployments, CI variables, local `.env` files), and roll any dependent services that cached the old value.
4. **Notify affected systems and people.** Anything that authenticated with the old credential, plus the maintainer team and — for production credentials — downstream operators.
5. **Owner.** The repo maintainer drives steps 1–4. Page them via the channel listed at the top of this document.

## Personal-data breach

A leaked credential (above) is one incident class; unauthorized access to or loss of
**personal data** is another and has its own notification obligations (e.g. GDPR Art. 33/34).
Personal data an operator's instance may hold includes account emails, display names, audit
`source_ip` values, and SAML NameIDs/attributes.
[`docs/privacy.md`](docs/privacy.md) is the authoritative inventory — what is stored, where, for
how long, and which of it a data subject can retrieve or have erased.

### Classification

A personal-data breach is any confirmed unauthorized access, disclosure, alteration, or loss of
personal data. Classify severity by scope and sensitivity:

| Level | Criteria | Example |
| --- | --- | --- |
| **P1 — high** | Personal data of many subjects exposed, or any credential/session material enabling account takeover | Cross-tenant read leaking another org's user emails; audit log with `source_ip` exfiltrated |
| **P2 — moderate** | Personal data of a bounded set exposed, low re-identification/harm risk | A single misdirected notification email |
| **P3 — low / near-miss** | Contained internally, no confirmed external exposure | An over-broad log line caught before egress |

### Detection sources

The raw material for detection already exists — start here when triaging a suspected breach:

- `dependably.audit.*` events and the `audit_log` table (who did what, from which `source_ip`).
- `AlertService` and the `SiemForwarderQueue` (forwarded security events).
- `dependably.audit.emit_failures` (a spike can indicate tampering or an overwhelmed pipeline).

### Notification decision tree

1. **Confirm and contain.** Establish whether personal data was actually accessed/lost (not just
   theoretically reachable). Stop ongoing exposure (revoke sessions/tokens, close the path).
2. **Assess risk to individuals.** Volume, sensitivity, re-identification and harm potential →
   assign P1/P2/P3 using the table above.
3. **Decide notification.**
   - **Regulator:** for a breach likely to result in a risk to individuals (typically P1, some
     P2), notify the competent authority **without undue delay and within 72 hours** of becoming
     aware, where such an obligation applies to the operator.
   - **Affected individuals:** where the breach is likely to result in a **high** risk (P1),
     notify them without undue delay, in clear language, with the likely consequences and the
     mitigations taken.
   - **No external notification** is required for a contained P3 near-miss — but still record it.
4. **Record.** Log every breach (including P3s and the reasoning for any decision not to notify)
   so the required breach register is complete.
5. **Remediate and follow up.** Ship the fix through the normal MR flow, add a regression test,
   and issue an operator advisory if instances beyond the reporter's are affected.

**Owner.** The repo maintainer drives classification and the notification decision. Self-hosted
operators are the data controllers for their own instances and hold the ultimate notification
obligation for data they process; this runbook is the upstream project's guidance, not a
substitute for the operator's own legal assessment.

