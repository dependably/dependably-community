using Dapper;
using Dependably.Api;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Tests.Unit.Api;

// Maven versions are repository path segments on a case-sensitive path, so a hosted `1.0-RC1` and an
// upstream `1.0-rc1` are two versions of the coordinate.
public sealed partial class MavenControllerProxyTests
{
    [Fact]
    public async Task Metadata_UpstreamVersionDifferingOnlyInCase_IsKeptBesideTheHostedVersion()
    {
        const string artifactPath = "com/example/casemerge";
        await PublishLocalVersionAsync("com.example", "casemerge", "1.0-RC1");
        StubUpstreamMetadata(artifactPath, "1.0-RC1", "1.0-rc1");

        var ctl = BuildController(CleanOsv());
        var doc = Assert.IsType<ContentResult>(
            await ctl.Download(artifactPath + "/maven-metadata.xml", CancellationToken.None));

        Assert.Contains("<version>1.0-RC1</version>", doc.Content);
        Assert.Contains("<version>1.0-rc1</version>", doc.Content);
    }

    [Fact]
    public async Task Metadata_BlockedHostedVersion_DoesNotWithholdTheCaseDistinctUpstreamVersion()
    {
        const string artifactPath = "com/example/caseblock";
        await PublishLocalVersionAsync("com.example", "caseblock", "1.0-RC1");
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE package_versions SET manual_block_state = 'blocked' WHERE version = '1.0-RC1'");
        }
        StubUpstreamMetadata(artifactPath, "1.0-rc1");

        var ctl = BuildController(CleanOsv());
        var doc = Assert.IsType<ContentResult>(
            await ctl.Download(artifactPath + "/maven-metadata.xml", CancellationToken.None));

        Assert.DoesNotContain("<version>1.0-RC1</version>", doc.Content);
        Assert.Contains("<version>1.0-rc1</version>", doc.Content);
    }
}
