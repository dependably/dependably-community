# ADR 0001 — Auth stack: Identity Core hybrid

## Context

Dependably needs password hashing, TOTP MFA, one-time recovery codes, and a security_stamp for concurrent-mutation detection. ASP.NET Core Identity provides all of these primitives, but its higher layers (SignInManager, cookie authentication, SecurityStampValidator, lockout via UserManager) make assumptions that conflict with Dependably's security requirements:

- **Email enumeration defense.** The first-factor login path (forms and SAML) must respond in constant time for both valid and invalid emails, using a timing sentinel to prevent enumeration. Identity's `UserManager.CheckPasswordAsync` path does not guarantee this.
- **Lockout scope.** Lockout must be keyed on `(realm, tenantId, email)` so unknown accounts can be locked without a row in the `users` table. Identity's built-in `ILockoutStore` is keyed on user identity, which presupposes the user exists.
- **JWT session shape.** Sessions are HS256 JWT-in-cookie with `scope`, `tid`, and `tver` claims that `RouteScopeFilter` and the `ApiToken` scheme depend on. Identity's Application cookie scheme produces opaque tickets, not JWTs, and adding a parallel JWT layer would require custom claim mapping and re-validation.
- **Per-request session invalidation.** A password change must invalidate all outstanding sessions immediately by incrementing `token_version` (stored as the `tver` claim) and checking it on every authenticated request in `OnJwtTokenValidatedAsync`. Identity's `SecurityStampValidator` polls on a configurable interval (default 30 minutes), which would leave an ~30-minute window where a compromised session is still valid after a password change.

## Decision

The auth stack is an intentional hybrid:

- **Identity Core layer (AddIdentityCore only, no SignInManager/cookie scheme):** `UserManager<DependablyUser>` and `UserManager<SystemAdminUser>` supply TOTP token generation/validation, recovery code generation/validation, and BCrypt password hashing via the registered `IPasswordHasher`. `DependablyUserStore` and `SystemAdminUserStore` are custom Dapper implementations of `IUserStore`. `security_stamp` is rotated alongside `token_version` at every credential/session-invalidation event to keep the Identity model internally consistent.

- **Bespoke first-factor layer (LoginService, LoginServiceSaml, SqliteLockoutStore):** Constant-time BCrypt verification + timing sentinel for email-enumeration defense. Lockout keyed on `(realm, tenantId, email)` so unknown accounts can be locked. SAML JIT-provisioning with configurable attribute mapping.

- **Bespoke session layer (JWT-in-cookie, RouteScopeFilter, OnJwtTokenValidatedAsync):** HS256 JWT issued by `LoginService`; validated in `OnJwtTokenValidatedAsync` against the revocation store and the `tver` claim. `RouteScopeFilter` pins each scope claim (`tenant`/`system`) to its realm and rejects mismatches. The `ApiToken` scheme (service tokens + user PATs) resolves via `TokenAuthExtensions.ResolveTokenAsync` by SHA-256 hash lookup.

- **DataProtection key ring:** The standalone (no-Redis) path always configures a durable DB-backed key ring via `DbXmlRepository` → `data_protection_keys` table. The HA (Redis) path uses `PersistKeysToStackExchangeRedis` for multi-replica key sharing. The key material — like `jwt_secret` and `mfa_encryption_key` in `instance_settings` — is envelope-encrypted at rest when an operator master key is configured (`DEPENDABLY_MASTER_KEY`); see ADR 0002. With no master key set it is stored unencrypted (opt-in), and the supported posture is an OS-encrypted volume.

- **security_stamp rotation:** `token_version` is the canonical per-request session-invalidation signal, checked on every request in `OnJwtTokenValidatedAsync`. `security_stamp` is kept consistent by rotating it alongside `token_version` at all four credential/session-invalidation sites: `UserService.ChangePasswordAsync`, `UserService.BumpTokenVersionAndRevokeTokensAsync`, `SystemAdminRepository.RotatePasswordAsync`, `SystemAdminRepository.BumpTokenVersionAsync`. Per-request stamp validation via `SecurityStampValidator` is deliberately rejected — it would require JWT re-issuance on MFA enroll/recovery-regen and introduces an up-to-30-minute validation lag that `tver` already eliminates. `SystemAdminRepository.ResetPasswordAsync` does not rotate the stamp because it sets `must_change_password=1` and the admin's next successful credential rotation (via `RotatePasswordAsync`) will rotate both; forcing rotation here would be redundant and could race the first-login flow.

## Consequences

**Retained bespoke layers (deliberately not migrated):**
- First-factor login → `LoginService` / `LoginServiceSaml` (constant-time + timing sentinel for email enumeration defense; lockout on unknown accounts)
- Lockout → `SqliteLockoutStore` / `RedisLockoutStore` keyed on `(realm, tenantId, email)` (bounds unknown accounts, not just known users)
- JWT session issuance → `LoginService.IssueTenantJwt` / `IssueSystemJwt` (HS256, scope/tid/tver claims that RouteScopeFilter depends on)
- Per-request session invalidation → `OnJwtTokenValidatedAsync` + `tver` claim (immediate invalidation on password change vs SecurityStampValidator's poll interval)

**Deferred items:**
- Migrating `ResetPasswordAsync` stamp rotation: not worth the surface area today; the forced-rotation path handles it on next login.
- `SignInManager` adoption: blocked by the email-enumeration and lockout constraints above.
- Identity Application cookie scheme: blocked by the JWT session shape and RouteScopeFilter dependency on specific claims.
- `SecurityStampValidator` per-request check: deliberately rejected (redundant given tver, harmful to MFA enroll UX, 30-minute lag).
- Encrypting DB-resident secrets at rest: **delivered** — see ADR 0002, which envelope-encrypts `jwt_secret`, `mfa_encryption_key`, and `data_protection_keys.xml` together under an operator master key (`DEPENDABLY_MASTER_KEY`) held outside the DB.
