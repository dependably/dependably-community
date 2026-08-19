using System.Text.RegularExpressions;
using Dependably.Security;

namespace Dependably.Tests.Unit.Security;

/// <summary>
/// Enforces the API/CI-CD token-generator invariants: at least 256 bits of
/// CSPRNG entropy, and an alphabet that GitLab masked CI/CD variables accept
/// (alphanumeric only — masking rejects the base64url '-' and '_'
/// substitutions, and a rejected save silently keeps a variable's old value,
/// which strands token rotations).
/// </summary>
[Trait("Category", "Unit")]
public sealed partial class TokenGeneratorTests
{
    [Fact]
    public void Token_carries_at_least_256_bits_of_entropy()
    {
        string token = TokenGenerator.Generate();
        double entropyBits = token.Length * Math.Log2(62);
        Assert.True(
            entropyBits >= 256,
            $"{token.Length} alphanumeric chars carry only {entropyBits:F0} bits of entropy");
    }

    [Fact]
    public void Token_uses_only_the_gitlab_maskable_alphanumeric_alphabet()
    {
        string token = TokenGenerator.Generate();
        Assert.Matches(AlphanumericRegex(), token);
        Assert.DoesNotContain('-', token);
        Assert.DoesNotContain('_', token);
        Assert.DoesNotContain('=', token);
    }

    [Fact]
    public void Ten_thousand_tokens_are_all_distinct()
    {
        // Smoke check: a future refactor that swapped the CSPRNG for a counter
        // would still produce well-formed output but lose this property fast.
        var tokens = new HashSet<string>();
        for (int i = 0; i < 10_000; i++)
        {
            Assert.True(tokens.Add(TokenGenerator.Generate()), "Duplicate token generated");
        }

        Assert.Equal(10_000, tokens.Count);
    }

    [GeneratedRegex(@"^[A-Za-z0-9]+$")]
    private static partial Regex AlphanumericRegex();
}
