using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Usage;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// The stored-byte reconciliation through the real container and schema: the metadata reads run
/// on whichever database <c>TEST_INTEGRATION_DB</c> selects, including Postgres under enforced
/// row-level security, where a tenant-bound read would see none of the rows.
/// </summary>
[Trait("Category", "Integration")]
public sealed class StoredByteReconciliationIntegrationTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public StoredByteReconciliationIntegrationTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private static PlaneByteTally Plane(StoredByteReport report, string plane)
        => report.Planes.Single(p => p.Plane == plane);

    [Fact]
    public async Task Published_and_proxied_bytes_reconcile_against_the_real_schema()
    {
        var reconciler = _factory.Services.GetRequiredService<StoredByteReconciler>();
        var before = await reconciler.MeasureAsync(CancellationToken.None);

        // Hosted: a real publish writes the blob and the row that records its size.
        string name = $"sbr-{Guid.NewGuid():N}"[..20];
        await _factory.PushNpmPackage(name, "1.0.0");
        var org = (await _factory.Services.GetRequiredService<OrgRepository>().GetBySlugAsync("default"))!;
        var packages = _factory.Services.GetRequiredService<PackageRepository>();
        var pkg = (await packages.GetByPurlNameAsync(org.Id, "npm", name))!;
        var version = (await packages.GetVersionAsync(pkg.Id, "1.0.0"))!;

        // Proxy: three coordinates sharing one object. The Go coordinate's shared row names another
        // tenant's bytes; this tenant's own binding names its own key and records no size.
        string sha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Guid.NewGuid().ToByteArray())).ToLowerInvariant();
        await _factory.BlobStore.PutAsync(BlobKeys.Proxy(sha), new MemoryStream(new byte[64]));
        string goKey = BlobKeys.Go(org.Id, $"example.com/{name}", "v1.0.0", "zip");
        await _factory.BlobStore.PutAsync(goKey, new MemoryStream(new byte[32]));
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes)
                VALUES (@a, 'npm', @nameA, '1.0.0', 'a.tgz', @keyA, @sha, 64),
                       (@b, 'npm', @nameB, '1.0.0', 'b.tgz', @keyB, @sha, 64)
                """,
                new
                {
                    a = Guid.NewGuid().ToString("N"),
                    nameA = name + "-a",
                    keyA = BlobKeys.Proxy(sha) + "/a.tgz",
                    b = Guid.NewGuid().ToString("N"),
                    nameB = name + "-b",
                    keyB = BlobKeys.Proxy(sha) + "/b.tgz",
                    sha,
                });
            string goArtifact = Guid.NewGuid().ToString("N");
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes)
                VALUES (@goArtifact, 'golang', @module, 'v1.0.0', 'v1.0.0.zip', @sharedKey, @sha, 64)
                """,
                new { goArtifact, module = $"example.com/{name}", sharedKey = BlobKeys.Proxy(sha) + "/v1.0.0.zip", sha });
            await conn.ExecuteAsync(
                """
                INSERT INTO tenant_artifact_access (org_id, cache_artifact_id, blob_key, size_bytes)
                VALUES (@orgId, @goArtifact, @goKey, NULL)
                """,
                new { orgId = org.Id, goArtifact, goKey });
        }

        var after = await reconciler.MeasureAsync(CancellationToken.None);

        var (hostedBefore, hostedAfter) = (Plane(before, "hosted/"), Plane(after, "hosted/"));
        Assert.Equal(version.SizeBytes, hostedAfter.StoreBytes - hostedBefore.StoreBytes);
        Assert.Equal(version.SizeBytes, hostedAfter.MetadataBytes - hostedBefore.MetadataBytes);

        var (proxyBefore, proxyAfter) = (Plane(before, "proxy/"), Plane(after, "proxy/"));
        Assert.Equal(64, proxyAfter.StoreBytes - proxyBefore.StoreBytes);
        Assert.Equal(64, proxyAfter.MetadataBytes - proxyBefore.MetadataBytes);

        var (goBefore, goAfter) = (Plane(before, "go/"), Plane(after, "go/"));
        Assert.Equal(32, goAfter.StoreBytes - goBefore.StoreBytes);
        Assert.Equal(0, goAfter.MetadataBytes - goBefore.MetadataBytes);
        Assert.Equal(1, goAfter.MetadataKeys - goBefore.MetadataKeys);
        Assert.Equal(1, goAfter.NullSizeKeys - goBefore.NullSizeKeys);
    }
}
