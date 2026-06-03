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
                   updated_at          AS UpdatedAt
            FROM tenant_saml_config
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
                role_attribute, role_mapping, default_role, updated_at)
            VALUES (@orgId, @enabled, @formsEnabled,
                @spEntityId, @nameIdFormat, @emailAttribute, @buttonLabel,
                @roleAttribute, @roleMapping, @defaultRole, @now)
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
                updated_at          = @now
            """,
            new
            {
                orgId          = update.OrgId,
                enabled        = update.Enabled ? 1 : 0,
                formsEnabled   = update.FormsLoginEnabled ? 1 : 0,
                spEntityId     = update.SpEntityId,
                nameIdFormat   = update.NameIdFormat,
                emailAttribute = update.EmailAttribute,
                buttonLabel    = update.ButtonLabel,
                roleAttribute  = update.RoleAttribute,
                roleMapping    = update.RoleMapping,
                defaultRole    = update.DefaultRole,
                now            = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
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
        var rows = await conn.ExecuteAsync(
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

    /// <summary>Garbage-collects expired or consumed test runs older than 1 hour.</summary>
    public async Task PurgeExpiredTestRunsAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "DELETE FROM saml_test_runs WHERE expires_at < @cutoff",
            new { cutoff = DateTimeOffset.UtcNow.AddHours(-1).ToString("yyyy-MM-ddTHH:mm:ssZ") });
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
    string DefaultRole);
