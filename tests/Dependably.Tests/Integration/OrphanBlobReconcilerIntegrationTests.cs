using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end exercise of the SIGKILL-recovery path: a hosted blob exists with no
/// <c>package_versions</c> row referencing it (the orphan condition that would otherwise
/// only arise from a process killed between blob put and metadata commit). The unit tests
/// in <see cref="Unit.Infrastructure.OrphanBlobReconcilerServiceTests"/> exercise the same
/// logic against synthetic blobs; this fixture runs through the real DI container with
/// real seeded packages alongside, proving the reconciler also leaves the legitimately
/// referenced ones alone.
/// </summary>
[Trait("Category", "Integration")]
public sealed class OrphanBlobReconcilerIntegrationTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public OrphanBlobReconcilerIntegrationTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task RunOnce_DeletesOrphans_KeepsReferenced_KeepsInGrace()
    {
        // Step 1: seed a legitimately referenced hosted blob via the normal publish path.
        var legitName = $"sigkill-legit-{Guid.NewGuid():N}"[..24];
        await _factory.PushNpmPackage(legitName, "1.0.0");
        var legitKey = BlobKeys.Hosted("default", "npm", legitName, "1.0.0", $"{legitName}-1.0.0.tgz");
        // PushNpmPackage writes via the real PackagePublishService — but its blob key uses
        // the default org's id, not the slug. Resolve the actual id, then derive the key.
        var orgs = _factory.Services.GetRequiredService<OrgRepository>();
        var defaultOrg = (await orgs.GetBySlugAsync("default"))!;
        legitKey = BlobKeys.Hosted(defaultOrg.Id, "npm", legitName, "1.0.0", $"{legitName}-1.0.0.tgz");
        Assert.True(await _factory.BlobStore.ExistsAsync(legitKey),
            "Seeded legit blob must exist before the sweep.");

        // Step 2: plant a SIGKILL-style orphan — a hosted blob with no package_versions row.
        // Backdate the LastModified so it sits outside the grace window the reconciler uses.
        var oldOrphanKey = BlobKeys.Hosted(defaultOrg.Id, "npm",
            "sigkill-orphan", "1.0.0", "sigkill-orphan-1.0.0.tgz");
        _factory.BlobStore.SeedWithLastModified(oldOrphanKey, new byte[] { 9, 9, 9 },
            DateTimeOffset.UtcNow.AddHours(-2));

        // Step 3: plant a fresh orphan that's INSIDE the grace window — must survive the
        // sweep because it could be from a publish that's still committing.
        var freshOrphanKey = BlobKeys.Hosted(defaultOrg.Id, "npm",
            "inflight", "1.0.0", "inflight-1.0.0.tgz");
        _factory.BlobStore.SeedWithLastModified(freshOrphanKey, new byte[] { 1, 1, 1 },
            DateTimeOffset.UtcNow);

        // Step 4: build the reconciler with the same wiring Program.cs uses, but with a
        // tight grace window so the test doesn't have to wait minutes. We instantiate
        // directly rather than resolving the hosted service because AddHostedService<T>
        // doesn't make T itself resolvable from the DI container.
        var tiered = _factory.Services.GetRequiredService<TieredBlobStorage>();
        var packages = _factory.Services.GetRequiredService<PackageRepository>();
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ORPHAN_RECONCILE_GRACE_MINUTES"] = "5",
            })
            .Build();
        var sut = new OrphanBlobReconcilerService(tiered, packages, cfg,
            NullLogger<OrphanBlobReconcilerService>.Instance);

        var summary = await sut.RunOnceAsync();

        // Step 5: invariants.
        Assert.Equal(1, summary.OrphansDeleted);
        Assert.Equal(3, summary.BytesFreed);
        Assert.True(await _factory.BlobStore.ExistsAsync(legitKey),
            "Referenced blob must survive the sweep.");
        Assert.False(await _factory.BlobStore.ExistsAsync(oldOrphanKey),
            "Old orphan must be deleted.");
        Assert.True(await _factory.BlobStore.ExistsAsync(freshOrphanKey),
            "In-grace orphan must survive — could be a publish still committing.");
    }
}
