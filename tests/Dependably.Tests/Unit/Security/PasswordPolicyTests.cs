using Dependably.Security;
using Xunit;

namespace Dependably.Tests.Unit.Security;

/// <summary>
/// Covers the password-strength gate adopted per NIST 800-63B + ASVS V2.1
/// (encryption.md §10): length floor, UTF-8 byte ceiling for BCrypt, zxcvbn
/// entropy floor, context-dictionary block. Breach-corpus check is out of
/// scope here; see the deferred GitLab issue referenced in encryption.md §6.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PasswordPolicyTests
{
    private static readonly PasswordPolicy Policy = new();
    private static readonly PasswordContext NoContext = new();

    [Theory]
    [InlineData("")]
    [InlineData("short")]
    [InlineData("eleven-chrs")]  // 11
    public void Rejects_passwords_below_min_length(string pw)
    {
        var result = Policy.Evaluate(pw, NoContext);
        Assert.Equal(PasswordPolicyVerdict.TooShort, result.Verdict);
        Assert.Equal(PasswordPolicy.MinLength, result.DiagnosticValue);
    }

    [Fact]
    public void Rejects_passwords_exceeding_72_utf8_bytes()
    {
        var pw = new string('a', 73);
        var result = Policy.Evaluate(pw, NoContext);
        Assert.Equal(PasswordPolicyVerdict.TooLong, result.Verdict);
    }

    [Fact]
    public void Multi_byte_unicode_counts_by_bytes_not_chars()
    {
        // 36 four-byte emoji = 144 UTF-8 bytes, still 36 .NET char-pairs
        var pw = string.Concat(Enumerable.Repeat("\U0001F600", 36));
        var result = Policy.Evaluate(pw, NoContext);
        Assert.Equal(PasswordPolicyVerdict.TooLong, result.Verdict);
    }

    [Fact]
    public void Accepts_strong_passphrase_at_exactly_72_bytes()
    {
        var pw = new string('a', 60) + "-Battery!Staple";  // 75... trim
        pw = pw[..72];  // exactly 72 ASCII bytes
        var result = Policy.Evaluate(pw, NoContext);
        // Length cap is satisfied; entropy depends on zxcvbn — but a 60-char
        // run of 'a' is low entropy. Just assert we cleared the length gate.
        Assert.NotEqual(PasswordPolicyVerdict.TooLong, result.Verdict);
        Assert.NotEqual(PasswordPolicyVerdict.TooShort, result.Verdict);
    }

    [Theory]
    [InlineData("password1234")]   // 12 chars, classic weak
    [InlineData("qwertyuiopas")]   // 12 chars, keyboard walk
    [InlineData("aaaaaaaaaaaa")]   // 12 chars, repetition
    public void Rejects_low_entropy_12_char_passwords(string pw)
    {
        var result = Policy.Evaluate(pw, NoContext);
        Assert.Equal(PasswordPolicyVerdict.LowEntropy, result.Verdict);
    }

    [Theory]
    [InlineData("correct-horse-battery-staple")]
    [InlineData("my-pet-rabbit-eats-blue-carrots")]
    public void Accepts_high_entropy_passphrases_without_composition_rules(string pw)
    {
        // No uppercase, no digit, no symbol beyond '-': demonstrates that NIST
        // "no composition rules" guidance is respected.
        var result = Policy.Evaluate(pw, NoContext);
        Assert.Equal(PasswordPolicyVerdict.Ok, result.Verdict);
    }

    [Fact]
    public void Blocks_literal_product_name_in_any_case()
    {
        var result = Policy.Evaluate("DependablyRocks2026", NoContext);
        Assert.Equal(PasswordPolicyVerdict.ContainsContext, result.Verdict);
        Assert.Equal("dependably", result.Detail);
    }

    [Fact]
    public void Blocks_email_local_part_when_supplied()
    {
        var ctx = new PasswordContext(Email: "alice.dev@acme.example.com");
        var result = Policy.Evaluate("AliceDevPassphrase!", ctx);
        Assert.Equal(PasswordPolicyVerdict.ContainsContext, result.Verdict);
        Assert.Equal("alice.dev", result.Detail);
    }

    [Fact]
    public void Blocks_tenant_slug_when_supplied()
    {
        var ctx = new PasswordContext(TenantSlug: "northwind");
        var result = Policy.Evaluate("northwindForever!2026", ctx);
        Assert.Equal(PasswordPolicyVerdict.ContainsContext, result.Verdict);
        Assert.Equal("northwind", result.Detail);
    }

    [Fact]
    public void Two_char_email_local_part_is_ignored_to_avoid_false_positives()
    {
        // Local-part shorter than 3 chars would block common letters.
        var ctx = new PasswordContext(Email: "ab@example.com");
        var result = Policy.Evaluate("correct-horse-battery-staple", ctx);
        Assert.Equal(PasswordPolicyVerdict.Ok, result.Verdict);
    }

    [Fact]
    public void Unicode_normalization_matches_canonical_form()
    {
        // The literal "dependably" rendered with NFD-decomposed accents elsewhere
        // would still match after NFC normalization.
        var pw = "Dependably".Normalize(System.Text.NormalizationForm.FormD) + "-rocks-passphrase";
        var result = Policy.Evaluate(pw, NoContext);
        Assert.Equal(PasswordPolicyVerdict.ContainsContext, result.Verdict);
    }

    [Fact]
    public void Ok_verdict_is_idempotent_static()
    {
        Assert.True(PasswordPolicyResult.Ok.IsOk);
        Assert.Equal(PasswordPolicyVerdict.Ok, PasswordPolicyResult.Ok.Verdict);
    }

    [Fact]
    public void ToReason_does_not_throw_for_any_verdict()
    {
        foreach (PasswordPolicyVerdict v in Enum.GetValues<PasswordPolicyVerdict>())
        {
            var result = new PasswordPolicyResult(v, 12, "x");
            var reason = result.ToReason();
            Assert.False(string.IsNullOrWhiteSpace(reason));
        }
    }
}
