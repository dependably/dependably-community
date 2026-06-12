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
    public void TraversalAndEncodedSegments_AreRejected(string value)
        => Assert.False(PathSafeValidator.ValidateUpstreamSegment(value, "segment").IsValid);
}
