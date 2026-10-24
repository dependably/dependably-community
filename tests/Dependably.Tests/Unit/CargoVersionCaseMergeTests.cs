using Dependably.Api;
using Dependably.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// The sparse-index merges decide whether an upstream line is shadowed by a local one by version
/// string. Cargo versions are exact strings, so a case-only difference is a different version.
/// </summary>
[Trait("Category", "Unit")]
public sealed class CargoVersionCaseMergeTests
{
    private static string Line(string vers) => $$"""{"name":"c","vers":"{{vers}}","cksum":"00"}""";

    [Fact]
    public void MergeIndexLines_GlobalVersionDifferingOnlyInCase_IsKept()
    {
        var merged = CargoMetadataRepository.MergeIndexLines(
            [Line("1.0.0-RC1")], [Line("1.0.0-rc1"), Line("1.0.0-RC1")]);

        Assert.Equal([Line("1.0.0-RC1"), Line("1.0.0-rc1")], merged);
    }

    [Fact]
    public void ParseLocalVersions_DoesNotShadowACaseDistinctUpstreamVersion()
    {
        var local = CargoController.ParseLocalVersions([Line("1.0.0-RC1")]);

        Assert.Contains("1.0.0-RC1", local);
        Assert.DoesNotContain("1.0.0-rc1", local);
    }
}
