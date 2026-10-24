using Dependably.Security;
using Microsoft.AspNetCore.Http;

namespace Dependably.Tests.Unit.Security;

/// <summary>
/// The artifact serve paths' <c>If-None-Match</c> check (<see cref="ConditionalRequestHelper"/>):
/// an exact strong ETag match answers 304, anything else (absent, different or weak) does not.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ConditionalRequestHelperTests
{
    private const string ETag = "\"sha256:0a1b2c\"";

    [Fact]
    public void Exact_etag_hits()
    {
        var headers = new HeaderDictionary { ["If-None-Match"] = ETag };

        Assert.True(ConditionalRequestHelper.IfNoneMatchHits(headers, ETag));
    }

    [Theory]
    [InlineData("\"sha256:ffffff\"")]
    [InlineData("W/\"sha256:0a1b2c\"")]
    [InlineData("sha256:0a1b2c")]
    [InlineData("\"SHA256:0A1B2C\"")]
    public void Different_or_weak_etag_misses(string ifNoneMatch)
    {
        var headers = new HeaderDictionary { ["If-None-Match"] = ifNoneMatch };

        Assert.False(ConditionalRequestHelper.IfNoneMatchHits(headers, ETag));
    }

    [Fact]
    public void Absent_header_misses() =>
        Assert.False(ConditionalRequestHelper.IfNoneMatchHits(new HeaderDictionary(), ETag));
}
