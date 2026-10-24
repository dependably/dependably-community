using System.Text;
using Dependably.Infrastructure.Canonicalization;
using Dependably.Tests.Infrastructure;
using WebpkiJsonCanonicalizer = Org.Webpki.JsonCanonicalizer.JsonCanonicalizer;

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

    private static string Canon(string json) => Encoding.UTF8.GetString(CanonicalJson.Canonicalize(json));

    [Fact]
    public void Canonicalize_StringEscapes_UseTheShortFormsAndLowerCaseHexForOtherControlCharacters()
    {
        const string input = """{"s":"a\nb\tc\rd\be\ff\"g\\h\/i \u0001 \u001F é"}""";

        // \/ decodes to a bare slash; U+0001 and U+001F have no short form so they re-escape as
        // lower-case \u00xx; U+00E9 is emitted as the literal character, not an escape.
        const string expected = """{"s":"a\nb\tc\rd\be\ff\"g\\h/i \u0001 \u001f é"}""";

        Assert.Equal(expected, Canon(input));
    }

    [Fact]
    public void Canonicalize_TopLevelArray_KeepsElementOrderAndSortsNestedObjects()
    {
        const string input = """ [ 3 , "a" , true , false , null , { "b" : 1 , "a" : [ ] } , { } ] """;

        Assert.Equal("""[3,"a",true,false,null,{"a":[],"b":1},{}]""", Canon(input));
    }

    [Fact]
    public void Canonicalize_StripsInsignificantWhitespaceAroundTokens()
    {
        const string input = "\t{ \"b\" :\r\n [ 1 ,\n 2 ] ,\n \"a\" : \"x y\" }\n";

        Assert.Equal("""{"a":"x y","b":[1,2]}""", Canon(input));
    }

    [Fact]
    public void Canonicalize_SurrogatePairs_PassThroughUnescaped()
    {
        Assert.Equal("{\"s\":\"😀\"}", Canon("{\"s\":\"\\uD83D\\uDE00\"}"));
    }

    [Theory]
    [InlineData("""{"a":1} x""", "Improperly terminated JSON object")]
    [InlineData("""{"a":}""", "Missing argument")]
    [InlineData("""{"a":xfalse}""", "Unrecognized or malformed JSON token: xfalse")]
    [InlineData("""{"a":nul}""", "Unrecognized or malformed JSON token: nul")]
    [InlineData("""{"a":1.}""", "Unrecognized or malformed JSON token: 1.")]
    [InlineData("""{"a":+1}""", "Unrecognized or malformed JSON token: +1")]
    [InlineData("""{"a":True}""", "Unrecognized or malformed JSON token: True")]
    [InlineData("""{"a":"unterminated""", "Unexpected EOF reached")]
    [InlineData("", "Unexpected EOF reached")]
    [InlineData("{\"a\":\"line\nbreak\"}", "Unterminated string literal")]
    [InlineData("{\"a\":\"tab\there\"}", "Unescaped control character: 0x09")]
    [InlineData("""{"a":"\x"}""", "Unsupported escape:x")]
    [InlineData("""{"a":"\u00zz"}""", "Bad hex in \\u escape: z")]
    [InlineData("""{"a":1 "b":2}""", "Expected ',' but got '\"'")]
    [InlineData("""{"a" 1}""", "Expected ':' but got '1'")]
    [InlineData("""{1:2}""", "Expected '\"' but got '1'")]
    [InlineData("\"just a string\"", "Expected '{' but got '\"'")]
    [InlineData("[1 2]", "Expected ',' but got '2'")]
    public void Canonicalize_MalformedDocument_RaisesIOExceptionNamingTheDefect(string input, string expectedMessage)
    {
        var ex = Assert.Throws<IOException>(() => CanonicalJson.Canonicalize(input));

        Assert.Equal(expectedMessage, ex.Message);
    }

    [Fact]
    public void Canonicalize_DuplicateObjectKey_IsRefusedRatherThanSilentlyMerged()
    {
        Assert.Throws<ArgumentException>(() => CanonicalJson.Canonicalize("""{"a":1,"a":2}"""));
    }

    [Fact]
    public void ByteConstructor_DecodesUtf8_AndExposesBothEncodedForms()
    {
        byte[] input = Encoding.UTF8.GetBytes("""{"name":"café","k":[2,1]}""");

        var canonicalizer = new WebpkiJsonCanonicalizer(input);

        Assert.Equal("""{"k":[2,1],"name":"café"}""", canonicalizer.GetEncodedString());
        Assert.Equal(Encoding.UTF8.GetBytes("""{"k":[2,1],"name":"café"}"""), canonicalizer.GetEncodedUTF8());
    }

    [Fact]
    public void ByteConstructor_InvalidUtf8_IsRefusedRatherThanReplaced()
    {
        byte[] invalid = { (byte)'{', (byte)'"', (byte)'a', (byte)'"', (byte)':', (byte)'"', 0xFF, (byte)'"', (byte)'}' };

        Assert.ThrowsAny<ArgumentException>(() => new WebpkiJsonCanonicalizer(invalid));
    }
}
