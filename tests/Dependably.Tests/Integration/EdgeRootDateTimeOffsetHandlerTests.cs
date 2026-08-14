using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Confirms the global Dapper <c>DateTimeOffsetHandler</c> registration
/// (<c>SchemaInitializer.RegisterDateTimeOffsetHandler</c>, <c>[ModuleInitializer]</c>) is in
/// effect on the <c>Dependably.Edge</c> composition root specifically — the edge root never
/// references <c>Dependably.Management</c> and has its own <c>Program</c>/DI graph
/// (<see cref="EdgeFactory"/>), so a registration mechanism that happened to depend on something
/// only the full root touches would silently not apply here. A module initializer fires on
/// module load regardless of which composition root references the assembly, but this is the
/// concrete proof for the assembly the <c>edge-closure-guard</c> CI gate actually ships.
/// </summary>
[Trait("Category", "Integration")]
public sealed class EdgeRootDateTimeOffsetHandlerTests
{
    [Fact]
    public async Task EdgeRoot_RawDateTimeOffsetWrite_IsCanonicalUtcText()
    {
        await using var f = new EdgeFactory { EdgeAccessToken = "inbound-tok" };
        using var client = f.CreateClient();

        var db = f.Services.GetRequiredService<IMetadataStore>();
        var orgs = f.Services.GetRequiredService<OrgRepository>();
        var orgRecord = await orgs.GetBySlugAsync("default")
            ?? throw new InvalidOperationException("edge default org not seeded");

        var recorder = f.Services.GetRequiredService<CacheAccessRecorder>();
        string? caId = await recorder.RecordAccessAsync(new CacheAccess(
            orgRecord.Id, "npm", "lodash", "1.0.0", "lodash-1.0.0.tgz",
            Sha256: "abc123", SizeBytes: 4,
            BlobKey: "proxy/abc123/lodash-1.0.0.tgz",
            UpstreamUrl: "https://upstream.example/lodash-1.0.0.tgz", Origin: CacheAccessOrigin.FirstFetch));
        Assert.NotNull(caId);

        await using var conn = await db.OpenAsync();
        string firstCachedAt = await conn.QuerySingleAsync<string>(
            "SELECT first_cached_at FROM cache_artifact WHERE id = @id", new { id = caId });

        // Canonical "...Z" text, not the ADO.NET provider's own DateTimeOffset serialization
        // ("yyyy-MM-dd HH:mm:ss+00:00") that CacheArtifactRepository.InsertAsync would produce
        // if the global type-handler registration hadn't run before this write.
        Assert.Matches(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", firstCachedAt);
    }
}
