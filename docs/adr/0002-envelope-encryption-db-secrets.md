# ADR 0002 — Envelope encryption of DB-resident secrets

## Context

Three secrets are persisted in the metadata database (SQLite in the community
build, Postgres in the bridge/enterprise build):

- **`jwt_secret`** (`instance_settings.value`) — the HS256 signing key for every
  session JWT. Anyone who can read this value can forge a valid session token for
  any user in any tenant. This is the highest-severity item.
- **`mfa_encryption_key`** (`instance_settings.value`) — the AES-256-GCM key that
  `MfaSecretProtector` uses to encrypt user TOTP secrets and recovery codes stored
  in `users` / `system_admins`. Because the key lived in the *same database* as the
  ciphertext it protects, that encryption gave near-zero protection against a stolen
  database file or backup — an attacker with the DB has both halves.
- **`data_protection_keys.xml`** — the ASP.NET Core DataProtection key ring,
  persisted as plaintext XML by `DbXmlRepository` (standalone) or in Redis (HA).

ADR 0001 deferred this as a single cross-cutting initiative: "encrypt all
DB-resident secrets together, keyed from outside the DB." All three share one
root weakness — a secret that protects data is stored next to that data, so the
database is a single point of compromise. The fix has to introduce a key that
lives *outside* the database.

## Decision

Envelope-encrypt all three secrets with an operator-supplied **master key (KEK)**
that the application reads from configuration, never from the database.

### Key provider seam

`IMasterKeyProvider` abstracts the KEK source. The community build ships one
implementation, `EnvFileMasterKeyProvider`, which reads `DEPENDABLY_MASTER_KEY`
from configuration. The value is either an inline base64 string **or** a path to a
file containing one — mirroring the established `Rpm:GpgKey` operator-key-material
pattern. The decoded key must be **exactly 32 bytes** (AES-256). The provider is
registered with `TryAddSingleton`, so the enterprise build can supply a
`KmsMasterKeyProvider` (AWS KMS / Azure Key Vault) without modifying community
code — the cloud-KMS *provider semantics* are an enterprise concern; the
mechanism, the schema, and the env-var/file provider are community.

**Format is base64-32-byte-only; no passphrase/KDF in v1.** A passphrase would
require persisting KDF parameters (salt, iteration count) somewhere, and the only
natural home is the database we are explicitly refusing to trust. Operators who
want a memorable secret can derive 32 bytes out-of-band and supply the result.

### Envelope format

`EnvelopeProtector` wraps the existing `MfaSecretProtector` AES-256-GCM primitive
(32-byte key, 12-byte random nonce, 16-byte tag, `base64(nonce‖tag‖ciphertext)`).
Encrypted values carry an **`enc:v1:` prefix**. The prefix is both the
discriminator between an encrypted value and a legacy-plaintext value, and the
version anchor for any future re-key. Reads are prefix-gated (decrypt only
`enc:v1:` values; pass everything else through unchanged), so non-secret instance
settings — quotas, schedules — are unaffected. Writes are key-allowlisted
(`OrgRepository.SecretKeys` = `jwt_secret`, `mfa_encryption_key`), so only the two
secrets are ever encrypted, never a quota integer.

The DataProtection ring uses the framework's own at-rest seam:
`KeyManagementOptions.XmlEncryptor` with a custom `EnvelopeXmlEncryptor` /
`EnvelopeXmlDecryptor` pair over the same KEK. `DbXmlRepository` is unchanged —
only the *contents* of the `xml` column become an `<encryptedKey>` envelope. The
encryptor is applied in both the standalone and the Redis/HA wiring branches.

### Opt-in, with a fail-closed safety catch

Encryption is **opt-in**. With no `DEPENDABLY_MASTER_KEY` set, the server behaves
exactly as before (plaintext secrets) and logs a single startup warning pointing
operators at either the master key or an OS-encrypted volume. This keeps every
existing zero-config install working across the upgrade — no flag-day.

| Master key | Stored value | Behavior |
|---|---|---|
| set | plaintext | migrate in place at startup + log |
| set | `enc:v1:` | normal transparent decrypt |
| **absent** | **`enc:v1:` present** | **fail closed — refuse to start** |
| absent | plaintext | unchanged behavior + one startup warning |

The fail-closed row is the critical one: if encrypted secrets exist but the key is
gone, the server must refuse to start rather than silently mint new secrets (which
would invalidate every session and orphan every enrolled MFA device without
explanation). `StartupService` probes for this state explicitly and throws a clear,
`DEPENDABLY_MASTER_KEY`-naming error at boot.

### Migration

On startup, when a key is configured, `StartupService.MigrateSecretsToEnvelopeAsync`
re-encrypts any still-plaintext secret in place (idempotent — `enc:v1:` values are
skipped; wrapped in `BEGIN IMMEDIATE`). Fresh installs are born encrypted:
`FirstBootService` writes the two secrets pre-wrapped when a key is present, so a
KEK-configured install never writes a plaintext secret to disk. Existing
DataProtection key elements stay plaintext and keep loading (the ring natively
mixes encrypted and plaintext keys); only newly generated/rotated keys are
encrypted.

### Key rotation is a manual procedure

Automated KEK rotation is **out of scope for v1**. Rotation needs both the old and
new keys available simultaneously plus a maintenance window; an online rotation
endpoint would add attack surface for marginal benefit. The supported procedure is
operational: bring the instance down, decrypt-with-old / re-encrypt-with-new across
the three secrets and the DataProtection ring, restart with the new key. The
`enc:v1:` prefix reserves room for a versioned online rotation later.

## Consequences

- **The database alone is no longer sufficient to forge tokens or decrypt MFA
  secrets** when a master key is configured. The KEK must be compromised
  *separately* (from the host environment, a secrets manager, or KMS).
- **The master key is an operator responsibility.** It is a shared secret that must
  be injected identically into every replica and must not be lost. Losing it is, by
  design, unrecoverable for the encrypted data: `jwt_secret` and the DataProtection
  ring can be regenerated (at the cost of invalidating all sessions / forcing
  re-login), but losing `mfa_encryption_key` means every user must re-enroll MFA.
- **No schema change.** Both `instance_settings.value` and `data_protection_keys.xml`
  are `TEXT`; the `enc:v1:` marker and the `<encryptedKey>` envelope reuse the
  existing columns.
- **Without a master key, the supported posture is an OS-encrypted volume.**
  Operators who do not want to manage a KEK should place the SQLite file (or the
  Postgres data directory) on an OS-level encrypted volume — LUKS/dm-crypt, an
  encrypted EBS volume, or equivalent. The startup warning states this.
- **Crypto is reused, not invented.** All three secrets ride the same vetted
  AES-256-GCM primitive (`MfaSecretProtector`); the new code is key management and
  wiring, not novel cryptography.

## Status

Delivered. Supersedes the "Encrypting DB-resident secrets at rest" deferral in
ADR 0001.
