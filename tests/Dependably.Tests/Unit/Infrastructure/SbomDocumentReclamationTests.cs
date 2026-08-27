using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Sbom;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Where an uploaded SBOM/VEX/SARIF's superseded bytes are reclaimed, and what that placement
/// buys.
///
/// <para><c>Schema.sql</c> promises of <c>project_documents</c> that a metadata row never points
/// at bytes that are already gone. Reclaiming a superseded blob from the upload path cannot keep
/// that promise, because the blob store and the database commit independently: an upload stages
/// bytes X, a concurrent upload carrying different bytes commits its own row, reads X as
/// superseded and deletes it, and only afterwards does the first upload commit a row naming X.
/// No database transaction closes that — the delete is in the other system.</para>
///
/// <para>The orphan reconciler can, and its grace window is the reason: a blob written more
/// recently than <c>ORPHAN_RECONCILE_GRACE_MINUTES</c> is skipped no matter when the referenced
/// set was read, so an in-flight upload's bytes are never candidates. Reclamation therefore lives
/// there and nowhere else, and these tests pin both halves — the interleave leaves the live
/// document intact, and the sweep still frees what the re-upload replaced.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomDocumentReclamationTests : IAsyncLifetime
{
    private const int GraceMinutes = 30;

    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private readonly List<string> _tempFiles = [];

    private InMemoryBlobStore _registry = null!;
    private OrphanBlobReconcilerService _reconciler = null!;
    private string _orgId = "";
    private string _projectId = "";
    private string _versionId = "";

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _orgId = await OrgSeeder.InsertAsync(_db, $"acme-{Guid.NewGuid():N}");
        _projectId = Guid.NewGuid().ToString("N");
        _versionId = Guid.NewGuid().ToString("N");

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO projects (id, org_id, name) VALUES (@projectId, @orgId, 'storefront')",
            new { projectId = _projectId, orgId = _orgId });
        await conn.ExecuteAsync(
            "INSERT INTO project_versions (id, org_id, project_id, version, is_latest) " +
            "VALUES (@versionId, @orgId, @projectId, '1.4.0', 1)",
            new { versionId = _versionId, orgId = _orgId, projectId = _projectId });

        _registry = new InMemoryBlobStore(_clock);
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ORPHAN_RECONCILE_GRACE_MINUTES"] = GraceMinutes.ToString(
                    System.Globalization.CultureInfo.InvariantCulture),
            })
            .Build();
        _reconciler = new OrphanBlobReconcilerService(
            new TieredBlobStorage(new InMemoryBlobStore(_clock), _registry),
            new PackageRepository(_db),
            cfg,
            new AirGapMode(cfg),
            NullLogger<OrphanBlobReconcilerService>.Instance,
            _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock));
    }

    public async Task DisposeAsync()
    {
        foreach (string path in _tempFiles)
        {
            File.Delete(path);
        }

        await _db.DisposeAsync();
    }

    /// <summary>
    /// The cross-system interleave, sequenced with no sleeps: the losing upload is parked inside
    /// its blob put — bytes already written — while a superseding upload of different bytes runs
    /// its whole commit, and only then does the loser commit the row naming those bytes.
    ///
    /// <para>Reclaiming inline, this is where the promise breaks. The superseding upload's
    /// transactional read is correct about what it replaced, and it is still wrong to act on:
    /// the key it read as superseded is the key another upload is about to re-commit, so the
    /// delete lands on a live document. The download path then 404s and the nightly re-apply
    /// skips its sweep over facts it can no longer read.</para>
    ///
    /// <para>The row naming a key at all is not the assertion — that holds either way. The
    /// assertion is that the bytes under it are still there.</para>
    /// </summary>
    [Fact]
    public async Task ASupersedingCommitDuringAnotherUploadsStageLeavesTheCommittedRowsBytesIntact()
    {
        byte[] bytesX = Payload(0x58);
        byte[] bytesY = Payload(0x59);
        var writeX = Write("sbom", bytesX);
        var writeY = Write("sbom", bytesY);

        // The version already holds X — the earlier build whose bytes the parked upload re-sends.
        var plain = StoreOver(_registry);
        await plain.CommitRowAsync(writeX, await plain.StageBlobAsync(writeX));

        // The loser parks with its bytes written but its row uncommitted.
        var gate = new GatedPutBlobStore(_registry, writeBeforePark: true);
        var parked = StoreOver(gate);
        var parkedStage = Task.Run(() => parked.StageBlobAsync(writeX));
        await gate.Reached;

        // The superseding upload runs to completion inside that window.
        await plain.CommitRowAsync(writeY, await plain.StageBlobAsync(writeY));

        gate.Release();
        string keyX = await parkedStage;
        await parked.CommitRowAsync(writeX, keyX);

        Assert.Equal(keyX, await LiveBlobKeyAsync("sbom"));
        Assert.True(
            await _registry.ExistsAsync(keyX),
            "the committed row's bytes must still be in the store");
    }

    /// <summary>
    /// One sweep, three document blobs, three different fates — the sweep has to get all of them
    /// right in the same pass, and each is decided by a different clause.
    ///
    /// <list type="bullet">
    ///   <item>The SBOM a re-upload replaced: unreferenced and outside the grace window, so it is
    ///     reclaimed. A sweep that reclaims nothing leaves the bytes stranded for good, because
    ///     no other code path deletes them.</item>
    ///   <item>The current SBOM and the version's VEX: outside the grace window too, kept only
    ///     because <c>project_documents</c> is in the referenced-key union. A sweep that skipped
    ///     that arm would delete live documents.</item>
    ///   <item>A SARIF staged but not yet committed: unreferenced, and kept only by the grace
    ///     window. This is the in-flight upload the inline delete could not protect, and the
    ///     reason reclamation belongs here.</item>
    /// </list>
    /// </summary>
    [Fact]
    public async Task OneSweepReclaimsTheSupersededDocumentAndKeepsTheLiveAndInFlightOnes()
    {
        var store = StoreOver(_registry);

        var firstSbom = Write("sbom", Payload(0x41));
        string supersededKey = await store.StageBlobAsync(firstSbom);
        await store.CommitRowAsync(firstSbom, supersededKey);

        var secondSbom = Write("sbom", Payload(0x42));
        string liveSbomKey = await store.StageBlobAsync(secondSbom);
        await store.CommitRowAsync(secondSbom, liveSbomKey);

        var vex = Write("vex", Payload(0x43));
        string liveVexKey = await store.StageBlobAsync(vex);
        await store.CommitRowAsync(vex, liveVexKey);

        // Everything above ages out of the grace window; the SARIF below does not.
        _clock.Advance(TimeSpan.FromMinutes(GraceMinutes + 1));
        string inFlightKey = await store.StageBlobAsync(Write("sarif", Payload(0x44)));

        var summary = await _reconciler.RunOnceAsync();

        Assert.False(
            await _registry.ExistsAsync(supersededKey),
            "the replaced document is unreferenced and old — the sweep is its only reclaimer");
        Assert.True(
            await _registry.ExistsAsync(liveSbomKey),
            "the current SBOM is referenced and must survive");
        Assert.True(
            await _registry.ExistsAsync(liveVexKey),
            "the version's VEX is referenced and must survive");
        Assert.True(
            await _registry.ExistsAsync(inFlightKey),
            "an upload that has staged but not committed is inside the grace window");
        Assert.Equal(1, summary.OrphansDeleted);
    }

    /// <summary>
    /// A re-upload of byte-identical content resolves to the same content-addressed key, so there
    /// is one blob and one row, and the sweep must not read the rewrite as a supersede. The
    /// aged-out clock is what makes this discriminating: the blob survives because it is
    /// referenced, not because it was written recently.
    /// </summary>
    [Fact]
    public async Task AnIdenticalBytesReuploadKeepsItsSingleBlobAcrossASweep()
    {
        var store = StoreOver(_registry);
        var write = Write("sbom", Payload(0x45));

        string firstKey = await store.StageBlobAsync(write);
        string firstId = await store.CommitRowAsync(write, firstKey);
        string secondKey = await store.StageBlobAsync(write);
        string secondId = await store.CommitRowAsync(write, secondKey);

        Assert.Equal(firstKey, secondKey);
        Assert.Equal(firstId, secondId);

        _clock.Advance(TimeSpan.FromMinutes(GraceMinutes + 1));
        var summary = await _reconciler.RunOnceAsync();

        Assert.Equal(0, summary.OrphansDeleted);
        Assert.True(await _registry.ExistsAsync(firstKey), "the one live document must survive");
        Assert.Equal(firstKey, await LiveBlobKeyAsync("sbom"));
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private SbomDocumentStore StoreOver(IBlobStore blobs) =>
        new(new SingleStoreResolver(blobs), new ProjectDocumentRepository(_db));

    private static byte[] Payload(byte fill)
    {
        byte[] bytes = new byte[64];
        Array.Fill(bytes, fill);
        return bytes;
    }

    private SbomDocumentWrite Write(string docType, byte[] bytes)
    {
        string path = Path.Combine(Path.GetTempPath(), $"sbom-reclaim-{Guid.NewGuid():N}.tmp");
        File.WriteAllBytes(path, bytes);
        _tempFiles.Add(path);

        return new SbomDocumentWrite(
            _orgId, _projectId, _versionId, docType,
            docType == "sarif" ? "sarif-json" : "cyclonedx-json",
            SpecVersion: "1.6", ToolName: "syft", ToolVersion: "1.0.0",
            Sha256: Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(),
            SizeBytes: bytes.LongLength,
            TempPath: path,
            UploadedBy: null,
            UploadedAt: _clock.GetUtcNow());
    }

    private async Task<string> LiveBlobKeyAsync(string docType)
    {
        await using var conn = await _db.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>(
            """
            SELECT blob_key FROM project_documents
            WHERE org_id = @orgId AND project_version_id = @versionId AND doc_type = @docType
            """,
            new { orgId = _orgId, versionId = _versionId, docType }))!;
    }

    /// <summary>Community's pool shape: one registry store for every tenant, chosen by the test.</summary>
    private sealed class SingleStoreResolver(IBlobStore store) : ITenantStorageResolver
    {
        public IBlobStore Cache => store;

        public Task<IBlobStore> GetRegistryAsync(string tenantId, CancellationToken ct = default)
            => Task.FromResult(store);
    }
}
