using Dependably.Protocol;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// The checksum-database path allowlist (<see cref="GoSumDbPath"/>). The tile grammar mirrors
/// <c>golang.org/x/mod/sumdb/tlog.ParseTilePath</c>, which accepts only a path that round-trips
/// through <c>Tile.Path()</c>; the lookup grammar mirrors <c>modVerRE</c> in
/// <c>golang.org/x/mod/sumdb/server.go</c>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class GoSumDbPathTests
{
    [Theory]
    [InlineData("latest", GoSumDbPathKind.Latest)]
    [InlineData("lookup/golang.org/x/text@v0.3.0", GoSumDbPathKind.Lookup)]
    [InlineData("lookup/github.com/!burnt!sushi/toml@v1.3.2", GoSumDbPathKind.Lookup)]
    [InlineData("lookup/example.com/m@v2.0.0+incompatible", GoSumDbPathKind.Lookup)]
    [InlineData("lookup/example.com/m@v0.0.0-20191109021931-daa7c04131f5", GoSumDbPathKind.Lookup)]
    [InlineData("tile/8/0/x001/234", GoSumDbPathKind.Tile)]
    // The worked example in the tlog package documentation: H=3, L=4, N=1234067.
    [InlineData("tile/3/4/x001/x234/067", GoSumDbPathKind.Tile)]
    [InlineData("tile/3/4/x001/x234/067.p/1", GoSumDbPathKind.Tile)]
    [InlineData("tile/8/data/x001/234", GoSumDbPathKind.Tile)]
    [InlineData("tile/8/data/000.p/1", GoSumDbPathKind.Tile)]
    [InlineData("tile/1/0/000", GoSumDbPathKind.Tile)]
    [InlineData("tile/30/63/x001/x000/x000/x000/x000/x000/000", GoSumDbPathKind.Tile)]
    // supported is answered by the controller before classification, never forwarded.
    [InlineData("supported", GoSumDbPathKind.Unknown)]
    [InlineData("", GoSumDbPathKind.Unknown)]
    [InlineData("latest/", GoSumDbPathKind.Unknown)]
    [InlineData("Latest", GoSumDbPathKind.Unknown)]
    [InlineData("latestx", GoSumDbPathKind.Unknown)]
    [InlineData("lookup", GoSumDbPathKind.Unknown)]
    [InlineData("lookup/", GoSumDbPathKind.Unknown)]
    [InlineData("Lookup/example.com/m@v1.0.0", GoSumDbPathKind.Unknown)]
    [InlineData("lookupx/example.com/m@v1.0.0", GoSumDbPathKind.Unknown)]
    [InlineData("lookup/example.com/m", GoSumDbPathKind.Unknown)]
    [InlineData("lookup/example.com/m@latest", GoSumDbPathKind.Unknown)]
    [InlineData("lookup/example.com/m@v1.0", GoSumDbPathKind.Unknown)]
    [InlineData("lookup/@v1.0.0", GoSumDbPathKind.Unknown)]
    [InlineData("lookup/a@b@v1.0.0", GoSumDbPathKind.Unknown)]
    [InlineData("lookup/example.com/m@v1.0.0\n", GoSumDbPathKind.Unknown)]
    [InlineData("Tile/8/0/000", GoSumDbPathKind.Unknown)]
    [InlineData("foo/example.com/m@v1.0.0", GoSumDbPathKind.Unknown)]
    [InlineData("example.com/m@v1.0.0", GoSumDbPathKind.Unknown)]
    public void Classify(string path, GoSumDbPathKind expected) =>
        Assert.Equal(expected, GoSumDbPath.Classify(path));

    [Theory]
    [InlineData("tile/8/0")]
    [InlineData("tile/8/0/")]
    [InlineData("tile//0/000")]
    [InlineData("tile/8//000")]
    [InlineData("tile/0/0/000")]
    [InlineData("tile/31/0/000")]
    [InlineData("tile/+8/0/000")]
    [InlineData("tile/-1/0/000")]
    [InlineData("tile/08/0/000")]
    [InlineData("tile/8/00/000")]
    [InlineData("tile/8/-1/000")]
    [InlineData("tile/8/64/000")]
    [InlineData("tile/8/9999999999/000")]
    [InlineData("tile/8/Data/000")]
    [InlineData("tile/8/0/00")]
    [InlineData("tile/8/0/0000")]
    [InlineData("tile/8/0/abc")]
    [InlineData("tile/8/0/x000/234")]
    [InlineData("tile/8/0/x01/234")]
    [InlineData("tile/8/0/001/234")]
    [InlineData("tile/8/0/x001/x234")]
    [InlineData("tile/8/0/X001/234")]
    [InlineData("tile/8/0/x001/234/")]
    [InlineData("tile/8/0/000.p/0")]
    [InlineData("tile/8/0/000.p/256")]
    [InlineData("tile/8/0/000.p/07")]
    [InlineData("tile/8/0/000.p/")]
    [InlineData("tile/8/0/000.p")]
    [InlineData("tile/1/0/000.p/2")]
    [InlineData("tile/8/0/000.p/1/2")]
    [InlineData("tile/8/0/x001/x002/x003/x004/x005/x006/x007/008")]
    [InlineData("tile/8/0/example.com/internal/tool")]
    public void IsCanonicalTilePath_RejectsNonCanonicalForms(string path) =>
        Assert.False(GoSumDbPath.IsCanonicalTilePath(path));
}
