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

    [Theory]
    [InlineData("login.success", "Login Success")]
    [InlineData("login.failure", "Login Failure")]
    [InlineData("lockout.triggered", "Account Lockout")]
    [InlineData("token.created", "Token Created")]
    [InlineData("token.revoked", "Token Revoked")]
    [InlineData("rbac.role_changed", "Role Changed")]
    [InlineData("rbac.member_added", "Member Added")]
    [InlineData("rbac.member_removed", "Member Removed")]
    public void FriendlyName_MappedActions_ReturnHumanReadableName(string action, string expected)
    {
        Assert.Equal(expected, CefFormat.FriendlyName(action));
    }

    [Fact]
    public void FriendlyName_UnknownAction_ReturnActionAsIs()
    {
        Assert.Equal("custom.event", CefFormat.FriendlyName("custom.event"));
    }

    // ── Severity ─────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("lockout.triggered", CefFormat.SeverityHigh)]
    [InlineData("login.failure", CefFormat.SeverityMedium)]
    [InlineData("login.success", CefFormat.SeverityLow)]
    [InlineData("token.revoked", CefFormat.SeverityMediumLow)]
    [InlineData("rbac.role_changed", CefFormat.SeverityMediumHigh)]
    public void Severity_MappedActions_ReturnExpectedLevel(string action, int expected)
    {
        Assert.Equal(expected, CefFormat.Severity(action));
    }

    [Fact]
    public void Severity_UnknownAction_ReturnsLow()
    {
        Assert.Equal(CefFormat.SeverityLow, CefFormat.Severity("any.unknown"));
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
