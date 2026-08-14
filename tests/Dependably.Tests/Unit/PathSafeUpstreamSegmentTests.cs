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
}
