using System.Net.Http.Headers;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

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
        string legitName = $"sigkill-legit-{Guid.NewGuid():N}"[..24];
        await _factory.PushNpmPackage(legitName, "1.0.0");
        var orgs = _factory.Services.GetRequiredService<OrgRepository>();
        var defaultOrg = (await orgs.GetBySlugAsync("default"))!;
        // Hosted artefacts are content-addressed, so the key is not derivable from the publish
        // coordinate — take it from the committed row, which is also the set the reconciler
        // treats as referenced.
        var packageRepo = _factory.Services.GetRequiredService<PackageRepository>();
        var legitPkg = (await packageRepo.GetByPurlNameAsync(defaultOrg.Id, "npm", legitName))!;
        string legitKey = (await packageRepo.GetVersionAsync(legitPkg.Id, "1.0.0"))!.BlobKey;
        Assert.True(await _factory.BlobStore.ExistsAsync(legitKey),
            "Seeded legit blob must exist before the sweep.");

        // Step 2: plant a SIGKILL-style orphan — a hosted blob with no package_versions row.
        // Backdate the LastModified so it sits outside the grace window the reconciler uses.
        // Timestamps are fixed instants relative to TestTime.KnownNow; the reconciler below
        // runs on the same frozen clock, so the grace-window math is deterministic.
        string oldOrphanKey = BlobKeys.Hosted(defaultOrg.Id, "npm",
            "sigkill-orphan", "1.0.0", "sigkill-orphan-1.0.0.tgz");
        _factory.BlobStore.SeedWithLastModified(oldOrphanKey, new byte[] { 9, 9, 9 },
            TestTime.KnownNow.AddHours(-2));

        // Step 3: plant a fresh orphan that's INSIDE the grace window — must survive the
        // sweep because it could be from a publish that's still committing.
        string freshOrphanKey = BlobKeys.Hosted(defaultOrg.Id, "npm",
            "inflight", "1.0.0", "inflight-1.0.0.tgz");
        _factory.BlobStore.SeedWithLastModified(freshOrphanKey, new byte[] { 1, 1, 1 },
            TestTime.KnownNow);

        // Step 4: build the reconciler with the same wiring Program.cs uses, but with a
        // tight grace window so the test doesn't have to wait minutes. We instantiate
        // directly rather than resolving the hosted service because AddHostedService<T>
        // doesn't make T itself resolvable from the DI container. The clock is frozen at
        // TestTime.KnownNow so the seeded orphans land on fixed sides of the cutoff; the
        // legit blob's real-time LastModified doesn't matter — the reference check runs
        // before the grace check, so referenced blobs survive at any age.
        var tiered = _factory.Services.GetRequiredService<TieredBlobStorage>();
        var packages = _factory.Services.GetRequiredService<PackageRepository>();
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ORPHAN_RECONCILE_GRACE_MINUTES"] = "5",
            })
            .Build();
        var testClock = TestTime.Frozen();
        var sut = new OrphanBlobReconcilerService(tiered, packages, cfg,
            new AirGapMode(cfg),
            NullLogger<OrphanBlobReconcilerService>.Instance,
            testClock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(testClock));

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

    [Fact]
    public async Task RunOnce_MavenSidecarPublishedThroughTheRealController_Survives()
    {
        // Maven's publish path shares ONE package_versions row across every file of a version:
        // the JAR (published first) owns package_versions.blob_key, and the .pom lands only in
        // maven_version_files. This runs both PUTs through the real controller, then sweeps —
        // if the referenced set is package_versions alone, the .pom blob is reaped here and the
        // artefact becomes unresolvable to every Maven client.
        string artifactId = $"widget{Guid.NewGuid():N}"[..16];
        const string GroupId = "com.acme.recon";
        const string Version = "1.0.0";

        await _factory.PushMavenArtifact(GroupId, artifactId, Version);
        await PushMavenPomAsync(GroupId, artifactId, Version);

        // Hosted keys are content-addressed (the artefact's SHA-256 is a key segment), so the key
        // cannot be rebuilt from the coordinate alone — read the one the publish path actually
        // committed, exactly as every production reader does.
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        string jarKey = await conn.QuerySingleAsync<string>(
            "SELECT blob_key FROM maven_version_files WHERE filename = @filename",
            new { filename = $"{artifactId}-{Version}.jar" });
        string pomKey = await conn.QuerySingleAsync<string>(
            "SELECT blob_key FROM maven_version_files WHERE filename = @filename",
            new { filename = $"{artifactId}-{Version}.pom" });

        Assert.True(await _factory.BlobStore.ExistsAsync(jarKey), "JAR must exist before the sweep.");
        Assert.True(await _factory.BlobStore.ExistsAsync(pomKey), ".pom must exist before the sweep.");

        // Backdate both blobs well outside the grace window so only the referenced-set check can
        // save them. Without this the grace window alone would spare a freshly published .pom and
        // mask the bug entirely.
        await BackdateAsync(jarKey, TestTime.KnownNow.AddHours(-2));
        await BackdateAsync(pomKey, TestTime.KnownNow.AddHours(-2));

        var summary = await BuildReconciler().RunOnceAsync();

        Assert.True(await _factory.BlobStore.ExistsAsync(jarKey), "JAR must survive the sweep.");
        Assert.True(await _factory.BlobStore.ExistsAsync(pomKey),
            ".pom is referenced only from maven_version_files and must survive the sweep.");
        Assert.Equal(0, summary.DeletionFailures);
    }

    /// <summary>
    /// PUTs a minimal POM alongside an already-published JAR, via the real Maven controller.
    /// </summary>
    private async Task PushMavenPomAsync(string groupId, string artifactId, string version)
    {
        string token = await _factory.CreateToken("push");
        string pom =
            $"""
             <?xml version="1.0" encoding="UTF-8"?>
             <project xmlns="http://maven.apache.org/POM/4.0.0">
               <modelVersion>4.0.0</modelVersion>
               <groupId>{groupId}</groupId>
               <artifactId>{artifactId}</artifactId>
               <version>{version}</version>
             </project>
             """;

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"user:{token}")));

        using var content = new StringContent(pom, Encoding.UTF8);
        string path = $"/maven/{groupId.Replace('.', '/')}/{artifactId}/{version}/{artifactId}-{version}.pom";
        using var response = await client.PutAsync(path, content);
        response.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// Rewrites an already-stored blob's LastModified without changing its bytes. PutAsync stamps
    /// the store's own clock, which is the real one in this fixture; the reconciler runs on a
    /// frozen clock, so a published blob's age has to be pinned relative to that frozen instant
    /// for the grace-window comparison to be deterministic.
    /// </summary>
    private async Task BackdateAsync(string key, DateTimeOffset lastModified)
    {
        await using var stream = await _factory.BlobStore.GetAsync(key);
        Assert.NotNull(stream);
        using var buffer = new MemoryStream();
        await stream!.CopyToAsync(buffer);
        _factory.BlobStore.SeedWithLastModified(key, buffer.ToArray(), lastModified);
    }

    /// <summary>
    /// The reconciler with production wiring but a frozen clock and a tight grace window, so the
    /// seeded timestamps land on deterministic sides of the cutoff. Instantiated directly rather
    /// than resolved: AddHostedService&lt;T&gt; does not make T resolvable from the container.
    /// </summary>
    private OrphanBlobReconcilerService BuildReconciler()
    {
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ORPHAN_RECONCILE_GRACE_MINUTES"] = "5",
            })
            .Build();
        var testClock = TestTime.Frozen();
        return new OrphanBlobReconcilerService(
            _factory.Services.GetRequiredService<TieredBlobStorage>(),
            _factory.Services.GetRequiredService<PackageRepository>(),
            cfg,
            new AirGapMode(cfg),
            NullLogger<OrphanBlobReconcilerService>.Instance,
            testClock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(testClock));
    }
}
