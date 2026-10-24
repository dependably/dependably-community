using Dependably.Infrastructure.Siem;

namespace Dependably.Tests.Unit;

/// <summary>
/// Verifies the shared <see cref="CefFormat"/> helper that both
/// <c>SiemController</c> and <c>SyslogSiemForwarder</c> now use.
/// Tests cover: escape rules, friendly-name mapping, severity mapping, and the
/// boundary between named actions (mapped) and unknown actions (fallback).
/// </summary>
[Trait("Category", "Unit")]
public sealed class CefFormatTests
{
    // ── Escape ────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("plain", "plain")]
    [InlineData("back\\slash", "back\\\\slash")]
    [InlineData("pipe|char", "pipe\\|char")]
    [InlineData("equals=sign", "equals\\=sign")]
    [InlineData("new\nline", "new\\nline")]
    [InlineData("carriage\rreturn", "carriage\\rreturn")]
    public void Escape_AppliesCefEscapingRules(string input, string expected)
    {
        Assert.Equal(expected, CefFormat.Escape(input));
    }

    [Fact]
    public void Escape_CombinedSpecialChars_AllEscaped()
    {
        // Pipe, equals, backslash, and newline all in one string.
        string result = CefFormat.Escape("a|b=c\\d\ne");
        Assert.Equal("a\\|b\\=c\\\\d\\ne", result);
    }

    // ── FriendlyName ─────────────────────────────────────────────────────────

    /// <summary>
    /// The names are the ones writers emit. The credential and RBAC rows are flat
    /// (<c>token_created</c>, <c>member_role_changed</c>) — the dotted <c>token.created</c> /
    /// <c>rbac.role_changed</c> spellings this table carried for releases were never written by
    /// anything, so the real events fell through to the raw action name and the lowest severity.
    /// </summary>
    [Theory]
    [InlineData("login.success", "Login Success")]
    [InlineData("login.failure", "Login Failure")]
    [InlineData("auth.login.failure", "Login Failure")]
    [InlineData("lockout.triggered", "Account Lockout")]
    [InlineData("token_created", "Token Created")]
    [InlineData("token_revoked", "Token Revoked")]
    [InlineData("service_token_created", "Service Token Created")]
    [InlineData("member_role_changed", "Role Changed")]
    [InlineData("member_removed", "Member Removed")]
    [InlineData("checksum_failure", "Checksum Verification Failed")]
    [InlineData("auth.token.rejected", "Credential Rejected")]
    public void FriendlyName_MappedActions_ReturnHumanReadableName(string action, string expected)
    {
        Assert.Equal(expected, CefFormat.FriendlyName(action));
    }

    /// <summary>
    /// The adversarial twin of the table above: the names that were mapped but never written must
    /// now fall through, so a table re-acquiring one fails here rather than reading as coverage.
    /// </summary>
    [Theory]
    [InlineData("token.created")]
    [InlineData("token.revoked")]
    [InlineData("rbac.role_changed")]
    [InlineData("rbac.member_added")]
    [InlineData("rbac.member_removed")]
    public void FriendlyName_PhantomActionsNothingEverWrote_FallThrough(string action)
    {
        Assert.Equal(action, CefFormat.FriendlyName(action));
        Assert.Equal(CefFormat.SeverityLow, CefFormat.Severity(action));
    }

    [Fact]
    public void FriendlyName_UnknownAction_ReturnActionAsIs()
    {
        Assert.Equal("custom.event", CefFormat.FriendlyName("custom.event"));
    }

    // ── Severity ─────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("lockout.triggered", CefFormat.SeverityHigh)]
    [InlineData("checksum_failure", CefFormat.SeverityHigh)]
    [InlineData("login.failure", CefFormat.SeverityMedium)]
    [InlineData("login.success", CefFormat.SeverityLow)]
    [InlineData("token_revoked", CefFormat.SeverityMediumLow)]
    [InlineData("member_role_changed", CefFormat.SeverityMediumHigh)]
    public void Severity_MappedActions_ReturnExpectedLevel(string action, int expected)
    {
        Assert.Equal(expected, CefFormat.Severity(action));
    }

    [Fact]
    public void Severity_UnknownAction_ReturnsLow()
    {
        Assert.Equal(CefFormat.SeverityLow, CefFormat.Severity("any.unknown"));
    }

    /// <summary>
    /// Every action the table names, with its exact display name. Each row is one switch arm, so a
    /// renamed or dropped arm fails here instead of arriving unnamed in a collector.
    /// </summary>
    [Theory]
    [InlineData("auth.saml.login.success", "SAML Login Success")]
    [InlineData("auth.saml.login.failure", "SAML Login Failure")]
    [InlineData("mfa.enrolled", "MFA Enrolled")]
    [InlineData("mfa.disabled", "MFA Disabled")]
    [InlineData("mfa.recovery_code_used", "MFA Recovery Code Used")]
    [InlineData("mfa.trusted_device_added", "MFA Trusted Device Added")]
    [InlineData("auth.capability.denied", "Capability Denied")]
    [InlineData("ratelimit.rejected", "Rate Limit Rejected")]
    [InlineData("oci.scope_denied", "OCI Scope Denied")]
    [InlineData("metrics.scrape_denied", "Metrics Scrape Denied")]
    [InlineData("allowlist_blocked", "Allowlist Blocked")]
    [InlineData("invite_accept_blocked", "Invite Acceptance Blocked")]
    [InlineData("service_token_revoked", "Service Token Revoked")]
    [InlineData("system_admin.jwt_secret_rotated", "JWT Secret Rotated")]
    [InlineData("user.password_changed", "Password Changed")]
    [InlineData("user.password_reset", "Password Reset")]
    [InlineData("system_admin.admin_created", "Operator Created")]
    [InlineData("system_admin.admin_deleted", "Operator Deleted")]
    [InlineData("saml.config_updated", "SAML Config Updated")]
    [InlineData("saml.signing_cert_set", "SAML Signing Cert Set")]
    [InlineData("saml.signing_cert_expired", "SAML Signing Cert Expired")]
    [InlineData("ssrf_blocked", "SSRF Blocked")]
    [InlineData("provenance_verification_failed", "Provenance Verification Failed")]
    [InlineData("upstream_source_pin_violation", "Upstream Source Pin Violation")]
    [InlineData("conflict_resolved", "Dependency Confusion Conflict")]
    [InlineData("quarantine_decision", "Quarantine Decision")]
    [InlineData("package.override.set", "Policy Override Set")]
    [InlineData("package_version_blocked", "Version Blocked")]
    [InlineData("package_version_unblocked", "Version Unblocked")]
    [InlineData("trust_anchor_added", "Trust Anchor Added")]
    [InlineData("trust_anchor_removed", "Trust Anchor Removed")]
    public void FriendlyName_EveryRemainingMappedAction_ReturnsItsDisplayName(string action, string expected)
    {
        Assert.Equal(expected, CefFormat.FriendlyName(action));
        Assert.NotEqual(action, CefFormat.FriendlyName(action));
    }

    [Theory]
    [InlineData("checksum_failure")]
    [InlineData("ssrf_blocked")]
    [InlineData("provenance_verification_failed")]
    [InlineData("upstream_source_pin_violation")]
    [InlineData("lockout.triggered")]
    [InlineData("system_admin.jwt_secret_rotated")]
    public void Severity_IntegrityAndLockoutActions_AreHigh(string action)
    {
        Assert.Equal(7, CefFormat.Severity(action));
    }

    [Theory]
    [InlineData("auth.capability.denied")]
    [InlineData("oci.scope_denied")]
    [InlineData("member_role_changed")]
    [InlineData("mfa.disabled")]
    [InlineData("package.override.set")]
    [InlineData("package_version_unblocked")]
    [InlineData("trust_anchor_added")]
    [InlineData("trust_anchor_removed")]
    [InlineData("saml.config_updated")]
    [InlineData("saml.signing_cert_set")]
    [InlineData("system_admin.admin_created")]
    [InlineData("system_admin.admin_deleted")]
    public void Severity_PrivilegeAndTrustChanges_AreMediumHigh(string action)
    {
        Assert.Equal(6, CefFormat.Severity(action));
    }

    [Theory]
    [InlineData("login.failure")]
    [InlineData("auth.login.failure")]
    [InlineData("auth.saml.login.failure")]
    [InlineData("auth.token.rejected")]
    [InlineData("member_removed")]
    [InlineData("mfa.recovery_code_used")]
    [InlineData("user.password_changed")]
    [InlineData("user.password_reset")]
    [InlineData("quarantine_decision")]
    [InlineData("conflict_resolved")]
    [InlineData("invite_accept_blocked")]
    [InlineData("saml.signing_cert_expired")]
    public void Severity_FailedAuthAndCredentialChanges_AreMedium(string action)
    {
        Assert.Equal(5, CefFormat.Severity(action));
    }

    [Theory]
    [InlineData("token_created")]
    [InlineData("token_revoked")]
    [InlineData("service_token_created")]
    [InlineData("service_token_revoked")]
    [InlineData("ratelimit.rejected")]
    [InlineData("metrics.scrape_denied")]
    [InlineData("allowlist_blocked")]
    [InlineData("package_version_blocked")]
    [InlineData("mfa.trusted_device_added")]
    public void Severity_RoutineCredentialAndRefusalEvents_AreMediumLow(string action)
    {
        Assert.Equal(4, CefFormat.Severity(action));
    }

    [Theory]
    [InlineData("login.success")]
    [InlineData("mfa.enrolled")]
    [InlineData("auth.saml.login.success")]
    [InlineData("")]
    public void Severity_UnrankedActions_AreLow(string action)
    {
        Assert.Equal(3, CefFormat.Severity(action));
    }

    [Fact]
    public void Escape_EmptyString_StaysEmpty()
    {
        Assert.Equal("", CefFormat.Escape(""));
    }

    [Fact]
    public void Escape_LiteralBackslashThenN_IsNotConfusedWithANewline()
    {
        // Two characters, backslash and n: the backslash is doubled and the n stays literal.
        Assert.Equal(@"a\\nb", CefFormat.Escape(@"a\nb"));
        // A real newline becomes the two-character escape instead.
        Assert.Equal(@"a\nb", CefFormat.Escape("a\nb"));
    }

    [Fact]
    public void Escape_CrLfPair_BecomesTwoEscapedCharacters()
    {
        Assert.Equal(@"line1\r\nline2", CefFormat.Escape("line1\r\nline2"));
    }

    // ── Constant values per ArcSight CEF spec ────────────────────────────────

    [Fact]
    public void Constants_MatchArcSightCefSpec()
    {
        Assert.Equal(7, CefFormat.SeverityHigh);
        Assert.Equal(6, CefFormat.SeverityMediumHigh);
        Assert.Equal(5, CefFormat.SeverityMedium);
        Assert.Equal(4, CefFormat.SeverityMediumLow);
        Assert.Equal(3, CefFormat.SeverityLow);
    }

    // ── Cross-caller parity: SyslogSiemForwarder.FormatCef uses CefFormat ────

    [Fact]
    public void SyslogFormatCef_LockoutSeverity_MatchesCefFormatConstant()
    {
        // Regression: SyslogSiemForwarder.FormatCef must use the same severity as CefFormat.
        var ev = new SiemEvent("e1", "lockout.triggered", "tenant", "org-1",
            "u-1", null, null, null,
            new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        string line = SyslogSiemForwarder.FormatCef(ev);
        // SeverityHigh = 7; the header pipe count is fixed.
        Assert.Contains("|Account Lockout|7|", line);
    }

    [Fact]
    public void SyslogFormatCef_UnknownAction_FallsBackToSeverityLow()
    {
        var ev = new SiemEvent("e2", "custom.new_event", "tenant", "org-1",
            null, null, null, null,
            new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        string line = SyslogSiemForwarder.FormatCef(ev);
        // Severity low = 3; friendly name falls back to raw action.
        Assert.Contains("|custom.new_event|custom.new_event|3|", line);
    }
}
