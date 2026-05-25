using System.Text.RegularExpressions;
using Dependably.Security;
using Xunit;

namespace Dependably.Tests.Unit.Security;

/// <summary>
/// Enforces the API/CI-CD token-generator invariants declared in encryption.md §3:
/// 32 bytes of CSPRNG entropy, URL-safe base64 encoding (no `+`, `/`, or `=`).
/// </summary>
[Trait("Category", "Unit")]
public sealed partial class TokenGeneratorTests
{
    [Fact]
    public void Decoded_token_is_exactly_32_bytes()
    {
        var token = TokenGenerator.Generate();
        // Reverse the URL-safe transform, restore padding, decode.
        var padded = token.Replace('-', '+').Replace('_', '/');
        padded = padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '=');
        var decoded = Convert.FromBase64String(padded);
        Assert.Equal(32, decoded.Length);
    }

    [Fact]
    public void Token_uses_only_url_safe_base64_alphabet()
    {
        var token = TokenGenerator.Generate();
        Assert.Matches(UrlSafeAlphabetRegex(), token);
        Assert.DoesNotContain('+', token);
        Assert.DoesNotContain('/', token);
        Assert.DoesNotContain('=', token);
    }

    [Fact]
    public void Ten_thousand_tokens_are_all_distinct()
    {
        // Smoke check: a future refactor that swapped the CSPRNG for a counter
        // would still produce 32-byte output but lose this property fast.
        var tokens = new HashSet<string>();
        for (int i = 0; i < 10_000; i++)
            Assert.True(tokens.Add(TokenGenerator.Generate()), "Duplicate token generated");
        Assert.Equal(10_000, tokens.Count);
    }

    [GeneratedRegex(@"^[A-Za-z0-9_-]+$")]
    private static partial Regex UrlSafeAlphabetRegex();
}
