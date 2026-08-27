using Dependably.Security;

namespace Dependably.Tests.Unit;

/// <summary>
/// <see cref="PathSafeValidator.ValidateUpstreamSegment"/> guards route values that are
/// embedded as single path segments of upstream proxy URLs: everything the base validator
/// rejects, plus percent-encoded sequences (ASP.NET leaves <c>%2F</c> undecoded in route
/// values, so an encoded slash would survive into the composed upstream URL).
/// </summary>
[Trait("Category", "Unit")]
public class PathSafeUpstreamSegmentTests
{
    [Theory]
    [InlineData("lodash")]
    [InlineData("mypy_extensions-1.0.0-py3-none-any.whl")]
    [InlineData("newtonsoft.json")]
    [InlineData("13.0.3")]
    [InlineData("@scope")]
    [InlineData("is-odd-3.0.1.tgz")]
    // RPM: NEVRA package filenames and repodata names. Dots, dashes, plus signs, tildes,
    // carets and 64-char hex prefixes are all ordinary content and must keep passing.
    [InlineData("tree-2.1.1-1.fc40.x86_64.rpm")]
    [InlineData("libstdc++-13.2.1-3.fc40.x86_64.rpm")]
    [InlineData("golang-1.22.0~rc1-1.fc40.aarch64.rpm")]
    [InlineData("repomd.xml")]
    [InlineData("repomd.xml.asc")]
    [InlineData("0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0-primary.xml.gz")]
    public void LegitimatePackageSegments_Pass(string value)
        => Assert.True(PathSafeValidator.ValidateUpstreamSegment(value, "segment").IsValid);

    [Theory]
    [InlineData("..")]
    [InlineData("..%2Fetc%2Fpasswd")]
    [InlineData("a%2Fb")]
    [InlineData("a%2fb")]
    [InlineData("a%5Cb")]
    [InlineData("a/b")]
    [InlineData(@"a\b")]
    [InlineData("file\tname")]
    [InlineData("")]
    // RPM hash-prefixed repodata names only constrain their leading 64 hex characters, so the
    // traversal rides in the tail: "{sha256}-%2e%2e%2f%2e%2e%2fx".
    [InlineData("0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0-%2e%2e%2f%2e%2e%2fx")]
    [InlineData("%2e%2e%2f%2e%2e%2fetc%2fpasswd.rpm")]
    public void TraversalAndEncodedSegments_AreRejected(string value)
        => Assert.False(PathSafeValidator.ValidateUpstreamSegment(value, "segment").IsValid);

    /// <summary>
    /// `?` and `#` terminate the path when the composed string is parsed as a URI, so a segment
    /// carrying one truncates the upstream request to a shorter path than the caller's coordinate
    /// names. Rejected before any fetch.
    /// </summary>
    [Theory]
    [InlineData("pkg?a")]
    [InlineData("?leading")]
    [InlineData("trailing?")]
    [InlineData("pkg#f")]
    [InlineData("#leading")]
    [InlineData("trailing#")]
    [InlineData("pkg?a#f")]
    [InlineData("newtonsoft.json?ignored")]
    [InlineData("tree-2.1.1-1.fc40.x86_64.rpm#x")]
    public void UrlDelimitersThatTruncateTheUpstreamPath_AreRejected(string value)
        => Assert.False(PathSafeValidator.ValidateUpstreamSegment(value, "segment").IsValid);

    /// <summary>
    /// The adversarial twin of the case above: characters that are URL-reserved but which
    /// <see cref="Uri"/> percent-encodes INTO the same single segment keep passing. They cannot
    /// restructure the request, and rejecting them would narrow what a legitimate client may ask
    /// for — the guard is about URL structure, not about looking dangerous.
    /// </summary>
    [Theory]
    [InlineData("pkg&b")]
    [InlineData("pkg;x")]
    [InlineData("pkg:8080")]
    [InlineData("pkg@1.0.0")]
    [InlineData("with space")]
    [InlineData("golang-1.22.0~rc1-1.fc40.aarch64.rpm")]
    [InlineData("libstdc++-13.2.1-3.fc40.x86_64.rpm")]
    public void UrlReservedCharactersThatStayInsideTheSegment_StillPass(string value)
        => Assert.True(PathSafeValidator.ValidateUpstreamSegment(value, "segment").IsValid);

    /// <summary>
    /// The `%` message must not change for inputs that already got it — `%` is checked before the
    /// delimiter rule, so a value carrying both still reports the encoding failure.
    /// </summary>
    [Fact]
    public void PercentKeepsItsOwnMessageAheadOfTheDelimiterRule()
    {
        var both = PathSafeValidator.ValidateUpstreamSegment("a%2fb?c", "segment");

        Assert.False(both.IsValid);
        Assert.Equal("must not contain percent-encoded sequences", both.Message);

        var delimiterOnly = PathSafeValidator.ValidateUpstreamSegment("a?c", "segment");
        Assert.Equal("must not contain URL delimiters", delimiterOnly.Message);
    }

    /// <summary>
    /// The plain <see cref="PathSafeValidator.Validate"/> path (blob keys, not URLs) is
    /// deliberately unchanged: `?` and `#` are ordinary characters in a key and banning them there
    /// would reject stored content for no reason.
    /// </summary>
    [Theory]
    [InlineData("pkg?a")]
    [InlineData("pkg#f")]
    public void TheBaseValidatorIsUnaffected(string value)
        => Assert.True(PathSafeValidator.Validate(value, "segment").IsValid);
}
