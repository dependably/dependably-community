namespace Dependably.Infrastructure.Privacy;

/// <summary>
/// Single source of truth classifying every schema table that carries a personal-data-shaped
/// column — <c>user_id</c>, <c>actor_id</c>, <c>created_by</c>, <c>decided_by</c>, <c>email</c>,
/// <c>email_hash</c>, <c>email_snapshot</c>, <c>nameid</c>, <c>source_ip</c>, <c>user_agent</c> —
/// as either <see cref="Included"/> in a data-subject export (GDPR Art. 15 right of access /
/// Art. 20 portability) or deliberately <see cref="ExcludedWithReason"/> with a documented reason.
///
/// <para>
/// Backed by <c>PersonalDataTableClassificationComplianceTests</c>: a new schema table that
/// declares one of <see cref="PersonalDataColumns"/> fails the build until it is classified here.
/// That converts the personal-data inventory from a document that drifts into a build gate — the
/// same shape every other architectural invariant in this codebase uses.
/// </para>
///
/// <para>
/// This constant is the shared input to <see cref="PersonalDataExportRepository"/> and is the
/// intended input to the erasure routine and the Art. 30 processing inventory, so it is built once.
/// </para>
/// </summary>
public static class PersonalDataTables
{
    /// <summary>
    /// Exact column names that mark a table as carrying information about an identifiable natural
    /// person. Exact-name matching (not substring) is deliberate: config/delivery columns such as
    /// <c>email_status</c>, <c>email_smtp_username</c>, <c>email_attribute</c>, and
    /// <c>name_id_format</c> describe a channel or a setting, not a data subject, and must not
    /// drag their tables into the classification.
    /// </summary>
    public static readonly IReadOnlySet<string> PersonalDataColumns =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "user_id",
            "actor_id",
            "created_by",
            "decided_by",
            "email",
            "email_hash",
            "email_snapshot",
            "nameid",
            "source_ip",
            "user_agent",
        };

    /// <summary>
    /// Tables whose rows are returned to the data subject in the export, each strictly keyed to the
    /// subject (by <c>user_id</c>/<c>actor_id</c> = the subject's id, by <c>email</c> = the
    /// subject's address, or by the subject's pseudonymized login-attempt key). Every one is also
    /// filtered by the subject's <c>org_id</c>/<c>tenant_id</c> where the table carries one.
    /// </summary>
    public static readonly IReadOnlySet<string> Included =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "users",                 // the subject's own account row
            "user_tokens",           // the subject's personal access tokens
            "password_reset_tokens", // the subject's self-serve reset links
            "email_change_tokens",   // the subject's pending email rectifications (carries the new address)
            "external_identities",   // the subject's linked SAML identities
            "mfa_trusted_devices",   // the subject's remembered MFA devices (user_agent history)
            "banner_dismissals",     // banners the subject dismissed
            "invites",               // invites the subject created (created_by) and invites to their email
            "audit_log",             // security/config audit rows attributed to the subject (source_ip history)
            "activity",              // activity-feed rows attributed to the subject (source_ip history)
            "audit_event",           // structured audit events attributed to the subject (source_ip/user_agent)
            "login_attempts",        // the subject's failed-login / lockout throttle row (pseudonymized key)
            "account_send_throttle", // the subject's per-account transactional-mail send budget (same pseudonymized key)
        };

    /// <summary>
    /// Tables that declare a personal-data-shaped column but are deliberately NOT part of a subject
    /// export, each with the reason. The recurring rationale: a <c>created_by</c>/<c>decided_by</c>/
    /// <c>actor_id</c> pointer on an org-owned governance/config row is an authorship-provenance
    /// stamp — the row's content is org data, and exporting it into a personal package would leak
    /// org governance state rather than serve the subject's own data.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> ExcludedWithReason =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["system_admins"] =
                "Operator-plane identity with its own lifecycle and no tenant_id — not a tenant `users` " +
                "row. The tenant self-service export serves tenant data subjects only.",
            ["reserved_namespace"] =
                "Org namespace-governance config; created_by is an authorship-provenance stamp on an " +
                "org-owned row, not the subject's personal data.",
            ["quarantine"] =
                "Org supply-chain quarantine decision; decided_by is a provenance stamp on an org-owned row.",
            ["signature_trust_anchor"] =
                "Org signature trust-anchor config; created_by is a provenance stamp on an org-owned row.",
            ["saml_test_runs"] =
                "Org SAML IdP-configuration diagnostics; actor_id is a provenance stamp on config testing, " +
                "not the subject's personal data.",
            ["claim"] =
                "Org package-name claim governance; created_by is a provenance stamp on an org-owned row.",
            ["package_name_grant"] =
                "Org package-name publish-grant governance; created_by is a provenance stamp on an " +
                "org-owned authorization row, not the subject's personal data.",
            ["claim_history"] =
                "Org package-name claim history; actor_id is a provenance stamp on an org-owned row.",
            ["install_script_allowlist"] =
                "Org install-script allowlist config; created_by is a provenance stamp on an org-owned row.",
            ["banners"] =
                "Operator/admin-authored org or instance announcement; created_by is authorship provenance, " +
                "not the subject's personal data. (The subject's own dismissals ARE exported, via banner_dismissals.)",
        };
}
