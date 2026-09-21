using System.Text;
using Dependably.Infrastructure.Canonicalization;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Pins <see cref="CanonicalJson"/>'s output against RFC 8785's own published test vectors
/// (vendored, byte-for-byte, under <c>Fixtures/rfc8785-vectors/</c> — see that directory's
/// provenance note). This is the precondition ADR-sbom-author-signature calls out explicitly:
/// a wrong canonicalizer fails in the direction nothing notices, because a signature computed
/// over the wrong bytes still verifies against itself. Comparing against the RFC's OWN vectors
/// — not against anything this codebase generated — is what makes this a real check rather than
/// a tautology.
/// </summary>
[Trait("Category", "Unit")]
public sealed class CanonicalJsonVectorTests
{
    [Theory]
    [InlineData("arrays")]
    [InlineData("french")]
    [InlineData("structures")]
    [InlineData("values")]
    [InlineData("weird")]
    public async Task Canonicalize_MatchesTheRfc8785PublishedVector(string name)
    {
        string input = await File.ReadAllTextAsync(
            Path.Combine(FixtureManifest.Rfc8785VectorsRoot, "input", $"{name}.json"));
        string expected = (await File.ReadAllTextAsync(
            Path.Combine(FixtureManifest.Rfc8785VectorsRoot, "output", $"{name}.json"))).TrimEnd('\n', '\r');

        byte[] canonical = CanonicalJson.Canonicalize(input);

        Assert.Equal(expected, Encoding.UTF8.GetString(canonical));
    }

    // Adversarial twin: a canonicalizer that sorted keys by ORDINAL-IGNORE-CASE, or by CULTURE-
    // AWARE comparison, would still pass every hand-written unit test elsewhere in this suite —
    // none of them mix upper- and lower-case sibling keys — but would silently disagree with
    // RFC 8785 (and with every other JSF implementation) the first time a real document did.
    // "structures" is the vector that actually exercises mixed-case key ordering.
    [Fact]
    public async Task Canonicalize_SortsObjectKeysByOrdinalUtf16CodeUnit_NotCultureOrCase()
    {
        const string mixedCase = """{"B":1,"a":2,"A":3,"b":4}""";
        // Ordinal: 'A' (0x41) < 'B' (0x42) < 'a' (0x61) < 'b' (0x62).
        const string expected = """{"A":3,"B":1,"a":2,"b":4}""";

        byte[] canonical = CanonicalJson.Canonicalize(mixedCase);

        Assert.Equal(expected, Encoding.UTF8.GetString(canonical));
        await Task.CompletedTask;
    }

    [Theory]
    [InlineData("100", "100")]
    [InlineData("100.0", "100")]
    [InlineData("-0.0", "0")]
    [InlineData("1.5", "1.5")]
    [InlineData("1E21", "1e+21")]
    [InlineData("1E-7", "1e-7")]
    public void Canonicalize_SerializesNumbersPerEs6_NotDotNetDefaultFormatting(string input, string expected)
    {
        byte[] canonical = CanonicalJson.Canonicalize($$"""{"v":{{input}}}""");

        Assert.Equal($$$"""{"v":{{{expected}}}}""", Encoding.UTF8.GetString(canonical));
    }
}
