using Dapper;

namespace Dependably.Infrastructure;

public sealed class SamlConfigRepository
{
    private readonly IMetadataStore _db;

    public SamlConfigRepository(IMetadataStore db) => _db = db;

    public async Task<TenantSamlConfig?> GetAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<TenantSamlConfig>(
            """
            SELECT org_id              AS OrgId,
                   enabled             AS Enabled,
                   forms_login_enabled AS FormsLoginEnabled,
                   idp_entity_id       AS IdpEntityId,
                   idp_sso_url         AS IdpSsoUrl,
                   idp_signing_cert    AS IdpSigningCert,
                   idp_signing_cert_override AS IdpSigningCertOverride,
                   metadata_xml        AS MetadataXml,
                   sp_entity_id        AS SpEntityId,
                   name_id_format      AS NameIdFormat,
                   email_attribute     AS EmailAttribute,
                   button_label        AS ButtonLabel,
                   last_test_at        AS LastTestAt,
                   last_test_email     AS LastTestEmail,
                   last_test_claims    AS LastTestClaims,
                   role_attribute      AS RoleAttribute,
                   role_mapping        AS RoleMapping,
                   default_role        AS DefaultRole,
                   idp_can_assign_admin AS IdpCanAssignAdmin,
                   cert_expiry_alert_stage AS CertExpiryAlertStage,
                   updated_at          AS UpdatedAt
            FROM tenant_saml_config
            WHERE org_id = @orgId
            """,
            new { orgId });
    }

    /// <summary>
    /// Returns a lightweight projection of all orgs that have SAML enabled and an IdP signing
    /// cert configured. Used by the daily cert-expiry sweep, which reads every tenant's cert
    /// fields in a single cross-tenant pass.
    /// </summary>
    public async Task<IReadOnlyList<TenantSamlCertRow>> GetAllCertRowsAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: daily cert-expiry sweep reads all orgs for operator-level monitoring
        var rows = await conn.QueryAsync<TenantSamlCertRow>(
            """
            SELECT tsc.org_id              AS OrgId,
                   tsc.idp_signing_cert    AS IdpSigningCert,
                   tsc.idp_signing_cert_override AS IdpSigningCertOverride,
                   tsc.cert_expiry_alert_stage   AS CertExpiryAlertStage
            FROM tenant_saml_config tsc
            JOIN orgs o ON o.id = tsc.org_id
            WHERE (tsc.idp_signing_cert IS NOT NULL OR tsc.idp_signing_cert_override IS NOT NULL)
              AND o.deleted_at IS NULL
            """);
        return rows.ToList();
    }

    /// <summary>
    /// Records the cert-expiry alert stage after the daily sweep emits an audit event.
    /// The stage is one of "30", "14", "7", "1", or "expired".
    /// </summary>
    public async Task SetCertExpiryAlertStageAsync(string orgId, string stage, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            UPDATE tenant_saml_config
            SET cert_expiry_alert_stage = @stage
            WHERE org_id = @orgId
            """,
            new { orgId, stage });
    }

    /// <summary>
    /// Resets the cert-expiry alert stage to NULL so the sweep re-evaluates against the new cert.
    /// Called whenever the metadata cert or signing-cert override is replaced or cleared.
    /// </summary>
    public async Task ResetCertExpiryAlertStageAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            UPDATE tenant_saml_config
            SET cert_expiry_alert_stage = NULL
            WHERE org_id = @orgId
            """,
            new { orgId });
    }

    /// <summary>
    /// Updates connection-shape fields (toggles + display + format hints). Does NOT touch the
    /// IdP metadata — those columns are written exclusively by <see cref="UpsertMetadataAsync"/>
    /// after the uploaded XML has been parsed and verified.
    /// </summary>
    public async Task UpsertSettingsAsync(SamlSettingsUpdate update, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO tenant_saml_config (org_id, enabled, forms_login_enabled,
                sp_entity_id, name_id_format, email_attribute, button_label,
                role_attribute, role_mapping, default_role, idp_can_assign_admin, updated_at)
            VALUES (@orgId, @enabled, @formsEnabled,
                @spEntityId, @nameIdFormat, @emailAttribute, @buttonLabel,
                @roleAttribute, @roleMapping, @defaultRole, @idpCanAssignAdmin, @now)
            ON CONFLICT(org_id) DO UPDATE SET
                enabled             = @enabled,
                forms_login_enabled = @formsEnabled,
                sp_entity_id        = @spEntityId,
                name_id_format      = @nameIdFormat,
                email_attribute     = @emailAttribute,
                button_label        = @buttonLabel,
                role_attribute      = @roleAttribute,
                role_mapping        = @roleMapping,
                default_role        = @defaultRole,
                idp_can_assign_admin = @idpCanAssignAdmin,
                updated_at          = @now
            """,
            new
            {
                orgId = update.OrgId,
                enabled = update.Enabled ? 1 : 0,
                formsEnabled = update.FormsLoginEnabled ? 1 : 0,
                spEntityId = update.SpEntityId,
                nameIdFormat = update.NameIdFormat,
                emailAttribute = update.EmailAttribute,
                buttonLabel = update.ButtonLabel,
                roleAttribute = update.RoleAttribute,
                roleMapping = update.RoleMapping,
                defaultRole = update.DefaultRole,
                idpCanAssignAdmin = update.IdpCanAssignAdmin ? 1 : 0,
                now = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            });
    }

    /// <summary>
    /// Persists the parsed IdP metadata (entity id, SSO URL, signing cert) plus the original
    /// XML for later re-parsing. Leaves the toggles untouched so uploading metadata never
    /// silently flips SAML on.
    /// </summary>
    public async Task UpsertMetadataAsync(
        string orgId,
        string idpEntityId,
        string idpSsoUrl,
        string? idpSigningCertBase64,
        string metadataXml,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO tenant_saml_config (org_id, idp_entity_id, idp_sso_url,
                idp_signing_cert, metadata_xml, updated_at)
            VALUES (@orgId, @entityId, @ssoUrl, @cert, @xml, @now)
            ON CONFLICT(org_id) DO UPDATE SET
                idp_entity_id    = @entityId,
                idp_sso_url      = @ssoUrl,
                idp_signing_cert = @cert,
                metadata_xml     = @xml,
                updated_at       = @now
            """,
            new
            {
                orgId,
                entityId = idpEntityId,
                ssoUrl = idpSsoUrl,
                cert = idpSigningCertBase64,
                xml = metadataXml,
                now = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            });
    }

    /// <summary>Records a successful SAML test. Used by the forms-disable lockout guard.</summary>
    public async Task RecordTestSuccessAsync(string orgId, string email, string? claimsJson, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            UPDATE tenant_saml_config
            SET last_test_at = @now, last_test_email = @email, last_test_claims = @claimsJson, updated_at = @now
            WHERE org_id = @orgId
            """,
            new
            {
                orgId,
                email,
                claimsJson,
                now = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            });
    }

    /// <summary>Sets or replaces the admin-pinned IdP signing certificate override.</summary>
    public async Task SetSigningCertOverrideAsync(string orgId, string certBase64, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO tenant_saml_config (org_id, idp_signing_cert_override, updated_at)
            VALUES (@orgId, @cert, @now)
            ON CONFLICT(org_id) DO UPDATE SET
                idp_signing_cert_override = @cert,
                updated_at = @now
            """,
            new
            {
                orgId,
                cert = certBase64,
                now = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            });
    }

    /// <summary>Clears the admin-pinned signing cert override, reverting to the metadata-derived cert.</summary>
    public async Task ClearSigningCertOverrideAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            UPDATE tenant_saml_config
            SET idp_signing_cert_override = NULL, updated_at = @now
            WHERE org_id = @orgId
            """,
            new
            {
                orgId,
                now = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            });
    }

    public async Task DeleteAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "DELETE FROM tenant_saml_config WHERE org_id = @orgId",
            new { orgId });
    }

    /// <summary>
    /// Records a pending SAML admin-test run keyed by <paramref name="cid"/>. The cid is
    /// embedded in the signed test cookie; <see cref="TryConsumeTestRunAsync"/> later atomically
    /// stamps consumed_at so the cookie cannot drive a second round-trip.
    /// </summary>
    public async Task IssueTestRunAsync(
        string cid, string tenantId, string? actorId, DateTimeOffset expiresAt, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO saml_test_runs (cid, tenant_id, actor_id, issued_at, expires_at)
            VALUES (@cid, @tenantId, @actorId, @issuedAt, @expiresAt)
            """,
            new
            {
                cid,
                tenantId,
                actorId,
                issuedAt = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                expiresAt = expiresAt.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            });
    }

    /// <summary>
    /// Atomically consumes a pending test run. Returns true exactly once for a given
    /// <paramref name="cid"/> + <paramref name="tenantId"/> pair that hasn't expired and hasn't
    /// already been consumed; subsequent calls return false (replay protection).
    /// </summary>
    public async Task<bool> TryConsumeTestRunAsync(
        string cid, string tenantId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        int rows = await conn.ExecuteAsync(
            """
            UPDATE saml_test_runs
            SET consumed_at = @now
            WHERE cid = @cid
              AND tenant_id = @tenantId
              AND consumed_at IS NULL
              AND expires_at > @now
            """,
            new
            {
                cid,
                tenantId,
                now = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            });
        return rows == 1;
    }

    /// <summary>
    /// Garbage-collects expired rows across all three SAML one-shot tables. Each table also prunes
    /// itself on write, so this scheduled sweep only matters for a tenant that goes idle after
    /// generating rows — it bounds the table even when no further SAML traffic fires the on-write
    /// prune. Test runs keep a 1-hour grace (recent runs stay visible for debugging); pending
    /// requests and consumed assertions are reclaimed as soon as they expire.
    /// </summary>
    public async Task PurgeExpiredSamlAsync(CancellationToken ct = default)
    {
        string now = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        string testCutoff = DateTimeOffset.UtcNow.AddHours(-1).ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: global retention sweep of expired one-shot rows; deletes by expiry across all tenants
        await conn.ExecuteAsync("DELETE FROM saml_pending_requests WHERE expires_at < @now", new { now });
        // xtenant: global retention sweep of expired one-shot rows; deletes by expiry across all tenants
        await conn.ExecuteAsync("DELETE FROM saml_consumed_assertions WHERE expires_at < @now", new { now });
        // xtenant: global retention sweep of expired one-shot rows; deletes by expiry across all tenants
        await conn.ExecuteAsync("DELETE FROM saml_test_runs WHERE expires_at < @testCutoff", new { testCutoff });
    }

    // ── SP-initiated request binding (InResponseTo) ───────────────────────────

    /// <summary>
    /// Records a pending SP-initiated AuthnRequest keyed by <paramref name="requestId"/> so the
    /// ACS handler can bind the response's InResponseTo back to a request this SP actually issued.
    /// Expired rows are pruned opportunistically.
    /// </summary>
    public async Task IssuePendingRequestAsync(
        string requestId, string tenantId, DateTimeOffset expiresAt, CancellationToken ct = default)
    {
        string now = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: prune-on-write of expired one-shot rows; deletes by expiry across all tenants
        await conn.ExecuteAsync("DELETE FROM saml_pending_requests WHERE expires_at < @now", new { now });
        await conn.ExecuteAsync(
            """
            INSERT INTO saml_pending_requests (request_id, tenant_id, issued_at, expires_at)
            VALUES (@requestId, @tenantId, @issuedAt, @expiresAt)
            """,
            new
            {
                requestId,
                tenantId,
                issuedAt = now,
                expiresAt = expiresAt.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            });
    }

    /// <summary>
    /// Atomically consumes a pending AuthnRequest. Returns true exactly once for a given
    /// <paramref name="requestId"/> + <paramref name="tenantId"/> pair that hasn't expired and
    /// hasn't already been consumed; subsequent calls (and unknown/unsolicited ids) return false.
    /// </summary>
    public async Task<bool> TryConsumePendingRequestAsync(
        string requestId, string tenantId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        int rows = await conn.ExecuteAsync(
            """
            UPDATE saml_pending_requests
            SET consumed_at = @now
            WHERE request_id = @requestId
              AND tenant_id = @tenantId
              AND consumed_at IS NULL
              AND expires_at > @now
            """,
            new
            {
                requestId,
                tenantId,
                now = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            });
        return rows == 1;
    }

    // ── Assertion replay guard ────────────────────────────────────────────────

    /// <summary>
    /// Records an accepted assertion's signed ID as consumed for <paramref name="tenantId"/>.
    /// Returns true the first time the (tenant, assertion) pair is seen and false on any repeat —
    /// the insert's primary-key conflict is the atomic replay guard. <paramref name="expiresAt"/>
    /// is the assertion's NotOnOrAfter so the row outlives the window in which it could be replayed.
    /// Expired rows are pruned opportunistically.
    /// </summary>
    public async Task<bool> TryConsumeAssertionAsync(
        string tenantId, string? idpEntityId, string assertionId, DateTimeOffset expiresAt,
        CancellationToken ct = default)
    {
        string now = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: prune-on-write of expired one-shot rows; deletes by expiry across all tenants
        await conn.ExecuteAsync("DELETE FROM saml_consumed_assertions WHERE expires_at < @now", new { now });
        int rows = await conn.ExecuteAsync(
            """
            INSERT INTO saml_consumed_assertions (tenant_id, assertion_id, idp_entity_id, consumed_at, expires_at)
            VALUES (@tenantId, @assertionId, @idpEntityId, @now, @expiresAt)
            ON CONFLICT DO NOTHING
            """,
            new
            {
                tenantId,
                assertionId,
                idpEntityId,
                now,
                expiresAt = expiresAt.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            });
        return rows == 1;
    }
}

public sealed record SamlSettingsUpdate(
    string OrgId,
    bool Enabled,
    bool FormsLoginEnabled,
    string? SpEntityId,
    string NameIdFormat,
    string? EmailAttribute,
    string? ButtonLabel,
    string? RoleAttribute,
    string? RoleMapping,
    string DefaultRole,
    bool IdpCanAssignAdmin = false);

/// <summary>
/// Lightweight projection of the columns the cert-expiry sweep needs from
/// <c>tenant_saml_config</c>. Avoids loading the full metadata XML for every tenant
/// in the daily cross-tenant pass.
/// </summary>
public sealed class TenantSamlCertRow
{
    public string OrgId { get; set; } = "";
    /// <summary>Base64-encoded X.509 cert parsed from IdP metadata. NULL when absent.</summary>
    public string? IdpSigningCert { get; set; }
    /// <summary>Admin-pinned signing cert override. NULL when absent. Takes precedence over IdpSigningCert.</summary>
    public string? IdpSigningCertOverride { get; set; }
    /// <summary>Most-recently emitted alert stage: "30","14","7","1","expired". NULL = never alerted or cert changed.</summary>
    public string? CertExpiryAlertStage { get; set; }
}
