# Personal-data inventory

What a Dependably instance holds about identifiable people, where it lives, how long it stays, and
which of it a data subject can get back or have erased.

This page is written for the **operator** of a self-hosted instance. Dependably is software you
run; the operator is the controller for whatever their instance stores, and this inventory is the
raw material for their Art. 30 record of processing, their privacy notice, and their answer to a
subject access request. It is not legal advice, and it does not decide anything for you — it tells
you what the software puts in the database.

## How this page stays true

Two build gates keep the inventory from rotting:

- `PersonalDataTableClassificationComplianceTests` fails the build when a schema table declares a
  personal-data-shaped column (`user_id`, `actor_id`, `created_by`, `decided_by`, `email`,
  `email_hash`, `email_snapshot`, `nameid`, `source_ip`, `user_agent`) and is not classified in
  `PersonalDataTables` as either exported to the subject or deliberately excluded with a reason.
- The same gate requires each classified table to carry a `-- personal-data: included|excluded — …`
  annotation above its `CREATE TABLE` in **both** `Schema.sql` and `Schema.pg.sql`, and fails when
  an annotation disagrees with the C# classification.

So a new table carrying user-identifying data cannot ship without a conscious decision, and the DDL
cannot quietly stop matching the code. `PersonalDataTables` remains the single source of truth —
the annotations are how the schema tells you the same thing.

## What is stored

### Identity and credentials

| Table | Personal data | Notes |
| --- | --- | --- |
| `users` | Email, role, account status, last login | Email is the login identifier and is stored in plaintext — it has to be, since login resolves an account by it. Passwords are BCrypt hashes, never recoverable. |
| `system_admins` | Email, credentials | Operator-plane accounts. Not tenant data subjects; see the exclusions below. |
| `external_identities` | SAML NameID, email snapshot | NameID is very commonly an email address. The snapshot records what the IdP asserted at link time. |
| `user_tokens` | Token description, timestamps, owner | The token itself is stored only as a SHA-256 hash. |
| `mfa_trusted_devices` | `user_agent`, first/last seen | A remembered-device record is a browser fingerprint plus a timeline of when it was used. |
| `password_reset_tokens`, `email_change_tokens` | Owner, timestamps, destination address | The reset/confirmation token is stored only as a hash. `email_change_tokens` carries the address the account is moving to. |
| `invites` | Invited email, inviter | Both the recipient's address and the `created_by` of whoever sent it. |

### Security telemetry

| Table | Personal data | Notes |
| --- | --- | --- |
| `audit_log` | `actor_id`, `source_ip`, `detail` | The highest-fidelity personal-data table. `detail` can carry email hashes and SAML NameID hashes. |
| `audit_event` | `actor_id`, `source_ip`, `user_agent`, payload | Structured counterpart to `audit_log`, and what the SIEM forwarder emits. |
| `activity` | `actor_id`, `source_ip` | Per-artifact events (publish, download) attributed to whoever caused them. |
| `login_attempts` | Pseudonymized account key, failure count, lock state | Keyed by a SHA-256 over (realm, tenant, email). Pseudonymized, **not** anonymous: someone holding a candidate address can confirm it by recomputing the hash. |
| `account_send_throttle` | Same pseudonymized account key, send count, window | Bounds account-targeted transactional mail per target account. Same pseudonymity caveat. |

An operator reads these rows back through the audit and activity surfaces, including a CSV export.
A search term there runs as a leading-wildcard match, which no index can serve, so the export
bounds how far back it scans rather than walking the whole history. When that bound is reached the
response carries **`X-Export-Truncated: true`** and the CSV holds only the rows found within it. An
export with **no** search term is deliberately left unbounded, so a complete extract is always
available through the indexed `action` and `since` filters — a compliance export must not be
quietly short, and a client that ignores the header would not know that it was.

### Outbound mail waiting to be sent

| Table | Personal data | Notes |
| --- | --- | --- |
| `email_outbox` | Recipient addresses, rendered subject and body | The durable queue behind alert email. A row holds the org's configured alert recipients, snapshotted when the alert was raised, plus the message text, and it exists until delivery succeeds or a ceiling retires it. |

Two properties bound what this table can hold. It carries **alert mail only** — password-reset links
and email-change verification links stay on an in-memory path and are never persisted, because those
bodies are live credentials and an outbox would put them at rest in the database. And it is bounded
in three directions at once: a message stops being retried after `EMAIL_OUTBOX_MAX_RETRY_HOURS`, a
row stops existing in a non-terminal state after `EMAIL_OUTBOX_RETENTION_HOURS`, and the queue as a
whole refuses new messages past `EMAIL_OUTBOX_MAX_DEPTH` rather than growing without limit.

A row is excluded from the subject export deliberately: one message is addressed to several
recipients at once, so returning it to one of them would disclose the others, and its content is the
org's alert rather than the recipient's own data. Storage limitation is discharged by the retention
sweep below and by the tenant cascade instead.

Emails never reach the log stream in plaintext: `LoginService.HashEmail` hashes them before any
audit or log call, and SAML NameIDs go through `HashNameId` for the same reason.

### Governance rows that name a person

`reserved_namespace`, `quarantine`, `signature_trust_anchor`, `saml_test_runs`, `claim`,
`claim_history`, `package_name_grant`, `install_script_allowlist`, and `banners` each carry a
`created_by` / `decided_by` / `actor_id` pointer. The row's content is org data; the pointer is an
authorship-provenance stamp saying who made a governance decision. These are excluded from the
subject export for that reason — exporting them into a personal package would hand the subject the
org's governance state rather than their own data.

## Retention

Nothing personal is kept forever by default. The GC pass (`RetentionService`, `GC_SCHEDULE`,
default 03:00 daily) enforces these horizons; every one is an environment variable, documented in
[CONTRIBUTING.md → Environment variables](../CONTRIBUTING.md#environment-variables).

| Data | Default horizon | Variable |
| --- | --- | --- |
| `audit_log` identifiers (`source_ip`, `detail`) | Cleared at 90 days, keeping the forensic skeleton | `AUDIT_LOG_PII_DAYS` |
| `audit_log` rows | Deleted at 365 days | `AUDIT_LOG_RETENTION_DAYS` |
| `audit_event` identifiers (`source_ip`, `user_agent`) | Cleared at 90 days, keeping the forensic skeleton | `AUDIT_EVENT_PII_DAYS` |
| `audit_event` rows | Deleted at 365 days | `AUDIT_EVENT_RETENTION_DAYS` |
| `activity` rows | Deleted at 90 days | `ACTIVITY_RETENTION_DAYS` (per-org override available) |
| `login_attempts` idle rows | Deleted at 30 days | `LOGIN_ATTEMPTS_RETENTION_DAYS` |
| `account_send_throttle` rolled-over rows | Deleted at 7 days | `ACCOUNT_SEND_THROTTLE_RETENTION_DAYS` |
| `mfa_trusted_devices` | Deleted at expiry | Device TTL |
| `email_outbox` non-terminal rows | Retired to `expired` at 72 hours (or at 6 hours of retrying) | `EMAIL_OUTBOX_RETENTION_HOURS`, `EMAIL_OUTBOX_MAX_RETRY_HOURS` |
| `email_outbox` terminal rows | Deleted at 30 days | `EMAIL_OUTBOX_TERMINAL_RETENTION_DAYS` |
| Invites, SAML one-shots, JWT revocations | Deleted at expiry | — |

Two knobs reduce what is written in the first place, which is stronger than deleting it later:

- `AUDIT_TRUNCATE_IP=true` records the source network (`/24` for IPv4, `/48` for IPv6) instead of
  the host address.
- `AUDIT_DISABLE_USER_AGENT=true` records no `user_agent` at all.

## Subject rights

**Access and portability (Art. 15 / 20).** `GET /api/v1/users/me/export` returns the authenticated
subject's own rows from every included table as structured JSON. Every query is scoped on both the
subject's user id (taken from the authenticated principal, never from a request parameter) and
their tenant id, so the surface can only ever return the caller's own data. Secret material —
password and MFA secrets, token hashes, the security stamp — is excluded from the projections: the
export is a copy of personal data, not a credential dump.

**Rectification (Art. 16).** `PATCH /api/v1/users/{userId}/email` moves an account to a new
address. The change is confirmed by a link mailed to the new mailbox, because email is the login
identifier and the destination for password resets — a change authorized by a session alone would
let a hijacked session repoint account recovery. SAML accounts are refused: the IdP is
authoritative there, and a local edit would be overwritten on the next login.

**Erasure (Art. 17).** Deleting a user removes their account row and cascading personal rows, drops
their remembered devices, and pseudonymizes the forensic rows that are retained (`activity` and
`audit_log` keep `actor_id` and lose `source_ip`/`detail`; `audit_event` keeps `actor_id` and
`payload` and loses `source_ip`/`user_agent`). Deleting a tenant marks it for deletion and
hard-deletes after `TENANT_HARD_DELETE_GRACE_DAYS` (default 30): the tenant's `audit_log` rows are
deleted outright, since no foreign key cascade covers them, while its `audit_event` rows are
pseudonymized rather than deleted — `audit_event.org_id` carries an `ON DELETE SET NULL` foreign
key, so the schema already intends those rows to outlive the tenant. The tenant's entire
`email_outbox` backlog goes with it, cascaded by the `org_id` foreign key whether the mail was ever
delivered or not.

The whole per-tenant erasure commits as one transaction. This is what makes the guarantee hold
under failure: the sweep finds its work by selecting tenants out of `orgs`, so a partial pass that
removed the `orgs` row and then failed would strand the remaining personal rows where no later pass
could ever find them again. Wrapping the sequence means a failure anywhere rolls the `orgs` row
back with everything else, the tenant is still listed on the next pass, and every step is
idempotent so the retry runs cleanly over whatever the previous attempt left. Only the operator
notification is sent after the commit, so a failure there leaves a completed, audited deletion
unannounced rather than an incomplete one.

Removing one member does not clear that member's address from an org's queued alert mail, and that is
correct rather than an omission: the recipient list is the org's alert-delivery configuration, edited
by an admin on Settings → Integrations, not a per-account subscription. Clearing the setting stops
future mail; the rows already queued retire on the horizons above.

Retained-for-security rows are a deliberate limit on erasure, not an oversight: an audit trail that
any subject could erase on request would not be an audit trail. The horizons above are what bounds
it.

## Data leaving the instance

A default instance sends nothing about people anywhere. Every egress path is opt-in and operator-
configured:

- **Transactional and alert email** — addresses go to whatever SMTP relay the operator configures.
  Configuring `security=none` with a username and password sends the SMTP AUTH exchange in the
  clear; the settings UI warns when that combination is saved.
- **SIEM forwarding** — `audit_event` payloads, including `source_ip` and `user_agent`, go to the
  configured collector.
- **Webhooks** — per-org subscriptions receive package-event payloads.
- **Upstream registries** — proxy fetches reach the configured upstreams. These carry no user
  identity; what they reveal is which artifacts an instance requested.
- **Vulnerability lookups** — by default these query `api.osv.dev` with package coordinates. Again
  no user identity, but the coordinates tell the endpoint what the instance holds. An air-gapped
  deployment can sideload an OSV corpus and resolve entirely offline instead.

## Breach response

See [SECURITY.md → Personal-data breach](../SECURITY.md) for classification, detection sources, and
the notification decision tree.
