using Dependably.Security;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class PasswordPolicyTests
{
    private readonly PasswordPolicy _policy = new();

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Evaluate_NullOrEmpty_ReturnsTooShort(string? pwd)
    {
        var r = _policy.Evaluate(pwd, default);
        Assert.Equal(PasswordPolicyVerdict.TooShort, r.Verdict);
        Assert.Equal(PasswordPolicy.MinLength, r.DiagnosticValue);
        Assert.Null(r.Detail);
        Assert.False(r.IsOk);
    }

    [Theory]
    [InlineData("a")]
    [InlineData("Short1!")]
    [InlineData("abcdefghijk")]   // 11 chars
    public void Evaluate_BelowMinLength_ReturnsTooShort(string pwd)
    {
        var r = _policy.Evaluate(pwd, default);
        Assert.Equal(PasswordPolicyVerdict.TooShort, r.Verdict);
        Assert.Equal(PasswordPolicy.MinLength, r.DiagnosticValue);
    }

    [Fact]
    public void Evaluate_AboveMaxUtf8Bytes_ReturnsTooLong()
    {
        // Each "猫" is 3 UTF-8 bytes; 25 * 3 = 75 bytes > 72.
        string pwd = new('猫', 25);
        Assert.True(pwd.Length >= PasswordPolicy.MinLength);

        var r = _policy.Evaluate(pwd, default);
        Assert.Equal(PasswordPolicyVerdict.TooLong, r.Verdict);
        Assert.Equal(PasswordPolicy.MaxBytesUtf8, r.DiagnosticValue);
        Assert.Null(r.Detail);
    }

    [Theory]
    [InlineData("DependablyRocks2026")]
    [InlineData("MyDEPENDABLYpassword")]
    [InlineData("de-pen-dab-ly-secret-9!")] // non-alphanumerics stripped by Normalize
    public void Evaluate_ContainsBlockedSubstring_ReturnsContainsContext(string pwd)
    {
        var r = _policy.Evaluate(pwd, default);
        Assert.Equal(PasswordPolicyVerdict.ContainsContext, r.Verdict);
        Assert.Equal("dependably", r.Detail);
        Assert.Equal(0, r.DiagnosticValue);
    }

    [Fact]
    public void Evaluate_ContainsEmailLocalPart_ReturnsContainsContext()
    {
        var ctx = new PasswordContext(Email: "alice.dev@example.com");
        var r = _policy.Evaluate("AliceDevPassphrase!", ctx);
        Assert.Equal(PasswordPolicyVerdict.ContainsContext, r.Verdict);
        Assert.Equal("alice.dev", r.Detail);
    }

    [Fact]
    public void Evaluate_ShortEmailLocalPart_DoesNotTriggerContextMatch()
    {
        // Local part "ab" is 2 chars (< 3) — should be ignored by FindContextMatch.
        var ctx = new PasswordContext(Email: "ab@example.com");
        var r = _policy.Evaluate("correct horse battery staple xyz", ctx);
        Assert.NotEqual(PasswordPolicyVerdict.ContainsContext, r.Verdict);
    }

    [Fact]
    public void Evaluate_EmailWithoutAtSign_SkipsLocalPartCheck()
    {
        // No '@' means ExtractEmailLocalPart returns null; the email block is skipped.
        var ctx = new PasswordContext(Email: "not-an-email");
        var r = _policy.Evaluate("correct horse battery staple xyz", ctx);
        Assert.NotEqual(PasswordPolicyVerdict.ContainsContext, r.Verdict);
    }

    [Fact]
    public void Evaluate_EmailStartingWithAt_SkipsLocalPart()
    {
        // '@' at index 0 → ExtractEmailLocalPart returns null (at <= 0 branch).
        var ctx = new PasswordContext(Email: "@nolocal.com");
        var r = _policy.Evaluate("correct horse battery staple xyz", ctx);
        Assert.NotEqual(PasswordPolicyVerdict.ContainsContext, r.Verdict);
    }

    [Fact]
    public void Evaluate_WhitespaceEmail_SkipsEmailCheck()
    {
        var ctx = new PasswordContext(Email: "   ");
        var r = _policy.Evaluate("correct horse battery staple xyz", ctx);
        Assert.NotEqual(PasswordPolicyVerdict.ContainsContext, r.Verdict);
    }

    [Fact]
    public void Evaluate_ContainsTenantSlug_ReturnsContainsContext()
    {
        var ctx = new PasswordContext(TenantSlug: "acme-corp");
        var r = _policy.Evaluate("AcmeCorpForever!!", ctx);
        Assert.Equal(PasswordPolicyVerdict.ContainsContext, r.Verdict);
        Assert.Equal("acme-corp", r.Detail);
    }

    [Fact]
    public void Evaluate_ShortTenantSlug_DoesNotTriggerContextMatch()
    {
        var ctx = new PasswordContext(TenantSlug: "ab");
        var r = _policy.Evaluate("correct horse battery staple xyz", ctx);
        Assert.NotEqual(PasswordPolicyVerdict.ContainsContext, r.Verdict);
    }

    [Fact]
    public void Evaluate_WhitespaceTenantSlug_SkipsCheck()
    {
        var ctx = new PasswordContext(TenantSlug: "   ");
        var r = _policy.Evaluate("correct horse battery staple xyz", ctx);
        Assert.NotEqual(PasswordPolicyVerdict.ContainsContext, r.Verdict);
    }

    [Theory]
    [InlineData("password1234")] // common weak password, 12 chars
    [InlineData("aaaaaaaaaaaa")]
    [InlineData("123456789012")]
    public void Evaluate_LowEntropy_ReturnsLowEntropy(string pwd)
    {
        var r = _policy.Evaluate(pwd, default);
        Assert.Equal(PasswordPolicyVerdict.LowEntropy, r.Verdict);
        Assert.True(r.DiagnosticValue < PasswordPolicy.MinZxcvbnScore);
    }

    [Fact]
    public void Evaluate_StrongPassphrase_ReturnsOk()
    {
        var r = _policy.Evaluate("correct horse battery staple xyz", default);
        Assert.Equal(PasswordPolicyVerdict.Ok, r.Verdict);
        Assert.True(r.IsOk);
        Assert.Equal(PasswordPolicyResult.Ok, r);
    }

    [Fact]
    public void Evaluate_UnicodeNormalization_MatchesContext()
    {
        // "café" written with combining acute (U+0301) normalizes to NFC "café".
        var ctx = new PasswordContext(TenantSlug: "café");
        var r = _policy.Evaluate("CaféRoastersClub!", ctx);
        Assert.Equal(PasswordPolicyVerdict.ContainsContext, r.Verdict);
        Assert.Equal("café", r.Detail);
    }

    [Fact]
    public void ToReason_Ok()
    {
        Assert.Equal("ok", PasswordPolicyResult.Ok.ToReason());
    }

    [Fact]
    public void ToReason_TooShort_IncludesMinLength()
    {
        var r = new PasswordPolicyResult(PasswordPolicyVerdict.TooShort, PasswordPolicy.MinLength, null);
        Assert.Contains($"at least {PasswordPolicy.MinLength}", r.ToReason());
    }

    [Fact]
    public void ToReason_TooLong_IncludesMaxBytes()
    {
        var r = new PasswordPolicyResult(PasswordPolicyVerdict.TooLong, PasswordPolicy.MaxBytesUtf8, null);
        Assert.Contains($"at most {PasswordPolicy.MaxBytesUtf8}", r.ToReason());
    }

    [Fact]
    public void ToReason_LowEntropy_WithoutDetail_UsesScoreTemplate()
    {
        var r = new PasswordPolicyResult(PasswordPolicyVerdict.LowEntropy, 1, null);
        string msg = r.ToReason();
        Assert.Contains("too easy to guess", msg);
        Assert.Contains("score 1/", msg);
    }

    [Fact]
    public void ToReason_LowEntropy_WithDetail_UsesDetailTemplate()
    {
        var r = new PasswordPolicyResult(PasswordPolicyVerdict.LowEntropy, 1, "common password");
        string msg = r.ToReason();
        Assert.Contains("too easy to guess: common password", msg);
    }

    [Fact]
    public void ToReason_ContainsContext_QuotesDetail()
    {
        var r = new PasswordPolicyResult(PasswordPolicyVerdict.ContainsContext, 0, "acme");
        Assert.Equal("Password must not contain \"acme\".", r.ToReason());
    }

    [Fact]
    public void ToReason_UnknownVerdict_FallsThroughToDefault()
    {
        var r = new PasswordPolicyResult((PasswordPolicyVerdict)999, 0, null);
        Assert.Equal("Password rejected.", r.ToReason());
    }
}
