namespace Dependably.Infrastructure.Siem;

/// <summary>
/// Shared CEF (Common Event Format) helpers used by both the pull-API formatter
/// (<c>SiemController</c>) and the push forwarder (<c>SyslogSiemForwarder</c>).
/// All values are defined by the ArcSight CEF specification and must not be
/// changed without verifying downstream SIEM parser compatibility.
///
/// <para>
/// Every action named below is a member of <c>AuditActions.All</c>, checked by
/// <c>AuditActionVocabularyComplianceTests</c>. A mapping for a name no writer emits is not
/// harmlessly unused: it reads as coverage, and the real event — written under the name the
/// mapping missed — falls through to the raw action string and <see cref="SeverityLow"/>, so it
/// arrives unnamed and under-ranked in whatever the collector alerts on. The table is deliberately
/// partial, not exhaustive: an action with no entry falls through by design.
/// </para>
/// </summary>
internal static class CefFormat
{
    // CEF severity values per the ArcSight specification (0=Unknown, 1-3=Low,
    // 4-6=Medium, 7-8=High, 9-10=Very-High). Each auth event maps to the most
    // appropriate level.
    internal const int SeverityHigh = 7;
    internal const int SeverityMediumHigh = 6;
    internal const int SeverityMedium = 5;
    internal const int SeverityMediumLow = 4;
    internal const int SeverityLow = 3;

    /// <summary>
    /// Escapes a value for use in a CEF field per the CEF specification:
    /// backslash, pipe, equals, CR, and LF are all backslash-escaped.
    /// </summary>
    internal static string Escape(string s) =>
        s.Replace("\\", "\\\\").Replace("|", "\\|").Replace("=", "\\=").Replace("\n", "\\n").Replace("\r", "\\r");

    /// <summary>
    /// Maps a Dependably audit action string to a human-readable CEF event name.
    /// Unmapped actions fall through to the raw action string.
    /// </summary>
    internal static string FriendlyName(string action) => action switch
    {
        // Authentication and session.
        "login.success" => "Login Success",
        "login.failure" => "Login Failure",
        "auth.login.failure" => "Login Failure",
        "lockout.triggered" => "Account Lockout",
        "auth.saml.login.success" => "SAML Login Success",
        "auth.saml.login.failure" => "SAML Login Failure",
        "mfa.enrolled" => "MFA Enrolled",
        "mfa.disabled" => "MFA Disabled",
        "mfa.recovery_code_used" => "MFA Recovery Code Used",
        "mfa.trusted_device_added" => "MFA Trusted Device Added",

        // Refusals.
        "auth.token.rejected" => "Credential Rejected",
        "auth.capability.denied" => "Capability Denied",
        "ratelimit.rejected" => "Rate Limit Rejected",
        "oci.scope_denied" => "OCI Scope Denied",
        "metrics.scrape_denied" => "Metrics Scrape Denied",
        "allowlist_blocked" => "Allowlist Blocked",
        "invite_accept_blocked" => "Invite Acceptance Blocked",

        // Credential lifecycle.
        "token_created" => "Token Created",
        "token_revoked" => "Token Revoked",
        "service_token_created" => "Service Token Created",
        "service_token_revoked" => "Service Token Revoked",
        "system_admin.jwt_secret_rotated" => "JWT Secret Rotated",
        "user.password_changed" => "Password Changed",
        "user.password_reset" => "Password Reset",

        // Privilege and membership.
        "member_role_changed" => "Role Changed",
        "member_removed" => "Member Removed",
        "system_admin.admin_created" => "Operator Created",
        "system_admin.admin_deleted" => "Operator Deleted",

        // Identity-provider trust.
        "saml.config_updated" => "SAML Config Updated",
        "saml.signing_cert_set" => "SAML Signing Cert Set",
        "saml.signing_cert_expired" => "SAML Signing Cert Expired",

        // Supply-chain integrity.
        "checksum_failure" => "Checksum Verification Failed",
        "ssrf_blocked" => "SSRF Blocked",
        "provenance_verification_failed" => "Provenance Verification Failed",
        "upstream_source_pin_violation" => "Upstream Source Pin Violation",
        "conflict_resolved" => "Dependency Confusion Conflict",
        "quarantine_decision" => "Quarantine Decision",
        "package.override.set" => "Policy Override Set",
        "package_version_blocked" => "Version Blocked",
        "package_version_unblocked" => "Version Unblocked",
        "trust_anchor_added" => "Trust Anchor Added",
        "trust_anchor_removed" => "Trust Anchor Removed",

        _ => action,
    };

    /// <summary>
    /// Maps a Dependably audit action string to a CEF severity integer.
    /// Unmapped actions default to <see cref="SeverityLow"/>.
    /// </summary>
    internal static int Severity(string action) => action switch
    {
        // An integrity or provenance failure is the highest-ranked thing this feed carries: it
        // says an artefact did not verify, which no amount of correct authentication excuses.
        "checksum_failure" => SeverityHigh,
        "ssrf_blocked" => SeverityHigh,
        "provenance_verification_failed" => SeverityHigh,
        "upstream_source_pin_violation" => SeverityHigh,
        "lockout.triggered" => SeverityHigh,
        "system_admin.jwt_secret_rotated" => SeverityHigh,

        "auth.capability.denied" => SeverityMediumHigh,
        "oci.scope_denied" => SeverityMediumHigh,
        "member_role_changed" => SeverityMediumHigh,
        "mfa.disabled" => SeverityMediumHigh,
        "package.override.set" => SeverityMediumHigh,
        "package_version_unblocked" => SeverityMediumHigh,
        "trust_anchor_added" => SeverityMediumHigh,
        "trust_anchor_removed" => SeverityMediumHigh,
        "saml.config_updated" => SeverityMediumHigh,
        "saml.signing_cert_set" => SeverityMediumHigh,
        "system_admin.admin_created" => SeverityMediumHigh,
        "system_admin.admin_deleted" => SeverityMediumHigh,

        "login.failure" => SeverityMedium,
        "auth.login.failure" => SeverityMedium,
        "auth.saml.login.failure" => SeverityMedium,
        "auth.token.rejected" => SeverityMedium,
        "member_removed" => SeverityMedium,
        "mfa.recovery_code_used" => SeverityMedium,
        "user.password_changed" => SeverityMedium,
        "user.password_reset" => SeverityMedium,
        "quarantine_decision" => SeverityMedium,
        "conflict_resolved" => SeverityMedium,
        "invite_accept_blocked" => SeverityMedium,
        "saml.signing_cert_expired" => SeverityMedium,

        "token_created" => SeverityMediumLow,
        "token_revoked" => SeverityMediumLow,
        "service_token_created" => SeverityMediumLow,
        "service_token_revoked" => SeverityMediumLow,
        "ratelimit.rejected" => SeverityMediumLow,
        "metrics.scrape_denied" => SeverityMediumLow,
        "allowlist_blocked" => SeverityMediumLow,
        "package_version_blocked" => SeverityMediumLow,
        "mfa.trusted_device_added" => SeverityMediumLow,

        _ => SeverityLow,
    };
}
