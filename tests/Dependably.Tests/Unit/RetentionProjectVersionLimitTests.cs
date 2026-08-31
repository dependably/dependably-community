using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// The projects plane's retention cap, <c>org_settings.keep_project_versions</c>.
///
/// <para>The uploaded and proxy catalogues each carry a bound; without this one the projects plane
/// carries none, so the one-SBOM-per-build CI pattern the plane exists to serve accretes a version
/// row plus its whole component set on every build, permanently, with an interactive delete as the
/// only reclaim. That contradicts the registry's own opt-in retention posture, where a configured
/// cap is honoured and an unset one genuinely means unlimited.</para>
///
/// <para>Three properties are load-bearing and each has its own test: the cap deletes the oldest
/// rows, it never deletes the <c>is_latest</c> row (a latest-less project 404s every <c>latest</c>
/// route and rolls up as "Not scanned"), and it releases the document blobs of what it deletes —
/// enumerated before the FK cascade destroys the only reference to their keys.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class RetentionProjectVersionLimitTests : IAsyncLifetime
{
    private const string OrgId = "o1";

    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@OrgId, 'acme')", new { OrgId });
        await conn.ExecuteAsync(
            "INSERT INTO org_settings (org_id) VALUES (@OrgId)", new { OrgId });
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task Cap_DeletesTheOldestVersionsAndKeepsTheNewest()
    {
        string projectId = await SeedProjectAsync("billing-api");
        string v1 = await SeedVersionAsync(projectId, "1.0.0", ageDays: 40);
        string v2 = await SeedVersionAsync(projectId, "2.0.0", ageDays: 30);
        string v3 = await SeedVersionAsync(projectId, "3.0.0", ageDays: 20);
        string v4 = await SeedVersionAsync(projectId, "4.0.0", ageDays: 10, isLatest: true);

        await RunSweepAsync(keepProjectVersions: 2);

        Assert.False(await VersionExistsAsync(v1));
        Assert.False(await VersionExistsAsync(v2));
        Assert.True(await VersionExistsAsync(v3));
        Assert.True(await VersionExistsAsync(v4));
    }

    /// <summary>
    /// The is_latest row survives even when its age puts it outside the keep-set. An operator who
    /// promoted an older release back to latest has said, explicitly, that it is the one the
    /// <c>latest</c> routes serve; a retention cap that could delete it would turn an age policy
    /// into a broken project.
    /// </summary>
    [Fact]
    public async Task Cap_NeverDeletesTheLatestVersion_EvenWhenItIsTheOldest()
    {
        string projectId = await SeedProjectAsync("legacy-service");
        string oldLatest = await SeedVersionAsync(projectId, "1.0.0", ageDays: 90, isLatest: true);
        string newer1 = await SeedVersionAsync(projectId, "2.0.0", ageDays: 20);
        string newer2 = await SeedVersionAsync(projectId, "3.0.0", ageDays: 10);

        await RunSweepAsync(keepProjectVersions: 1);

        Assert.True(await VersionExistsAsync(oldLatest));
        Assert.True(await VersionExistsAsync(newer2));
        Assert.False(await VersionExistsAsync(newer1));
    }

    [Fact]
    public async Task Cap_ReleasesTheDocumentBlobsOfEveryVersionItDeletes()
    {
        string projectId = await SeedProjectAsync("docs-heavy");
        string old = await SeedVersionAsync(projectId, "1.0.0", ageDays: 40);
        string kept = await SeedVersionAsync(projectId, "2.0.0", ageDays: 10, isLatest: true);

        string oldSbom = await SeedDocumentAsync(projectId, old, "sbom", "cyclonedx-json");
        string oldVex = await SeedDocumentAsync(projectId, old, "vex", "openvex-json");
        string keptSbom = await SeedDocumentAsync(projectId, kept, "sbom", "cyclonedx-json");

        await RunSweepAsync(keepProjectVersions: 1);

        Assert.False(await _blobs.ExistsAsync(BlobKeys.StoreKey(oldSbom)));
        Assert.False(await _blobs.ExistsAsync(BlobKeys.StoreKey(oldVex)));
        // Adversarial twin: the surviving version's bytes must still be there. A sweep that
        // deleted every project document would satisfy the two assertions above.
        Assert.True(await _blobs.ExistsAsync(BlobKeys.StoreKey(keptSbom)));
    }

    /// <summary>
    /// NULL is unlimited, matching keep_versions and keep_days. The pass must not invent a cap for
    /// an operator who never configured one — the same posture that keeps proxy-cache eviction
    /// opt-in.
    /// </summary>
    [Fact]
    public async Task NullCap_DeletesNothing()
    {
        string projectId = await SeedProjectAsync("untouched");
        string v1 = await SeedVersionAsync(projectId, "1.0.0", ageDays: 400);
        string v2 = await SeedVersionAsync(projectId, "2.0.0", ageDays: 300);
        string v3 = await SeedVersionAsync(projectId, "3.0.0", ageDays: 10, isLatest: true);
        string blobKey = await SeedDocumentAsync(projectId, v1, "sbom", "cyclonedx-json");

        // keep_project_versions stays NULL; the whole GC pass runs, not just the helper, so an
        // unconditional call from RunGcPassAsync would fail here.
        await Build().RunGcPassAsync(CancellationToken.None);

        Assert.True(await VersionExistsAsync(v1));
        Assert.True(await VersionExistsAsync(v2));
        Assert.True(await VersionExistsAsync(v3));
        Assert.True(await _blobs.ExistsAsync(BlobKeys.StoreKey(blobKey)));
    }

    /// <summary>
    /// One project over its cap must not drag another project's versions out with it: the keep-set
    /// is ranked per project, not per org.
    ///
    /// <para>Mutant this discriminates: dropping <c>pv2.project_id = pv.project_id</c> from the
    /// keep-set subquery so the ranking runs org-wide. The seeding is what makes that visible.
    /// <c>quietOld</c> is deliberately <b>not</b> latest and is the oldest row in the org, so a
    /// per-project keep of 2 retains it (quiet holds exactly two versions) while an org-wide keep of
    /// 2 — whose whole budget is spent on busy's two newest — evicts it. Protecting the sibling
    /// project with an is_latest row instead would make the mutant invisible, since the is_latest
    /// guard would spare that row under either ranking.</para>
    /// </summary>
    [Fact]
    public async Task Cap_RanksPerProject_NotPerOrg()
    {
        string busy = await SeedProjectAsync("busy");
        string busyOldest = await SeedVersionAsync(busy, "1.0.0", ageDays: 40);
        string busyMiddle = await SeedVersionAsync(busy, "2.0.0", ageDays: 30);
        string busyLatest = await SeedVersionAsync(busy, "3.0.0", ageDays: 10, isLatest: true);

        string quiet = await SeedProjectAsync("quiet");
        string quietOld = await SeedVersionAsync(quiet, "9.0.0", ageDays: 200);
        string quietLatest = await SeedVersionAsync(quiet, "9.1.0", ageDays: 150, isLatest: true);

        await RunSweepAsync(keepProjectVersions: 2);

        // busy is over its cap by one, and the one it loses is its own oldest.
        Assert.False(await VersionExistsAsync(busyOldest));
        Assert.True(await VersionExistsAsync(busyMiddle));
        Assert.True(await VersionExistsAsync(busyLatest));

        // quiet is within its cap, so nothing of its own goes — including the org's oldest row,
        // which an org-wide ranking would have evicted to make room for busy's.
        Assert.True(await VersionExistsAsync(quietOld));
        Assert.True(await VersionExistsAsync(quietLatest));
    }

    /// <summary>
    /// The sweep's SELECT and its per-row DELETE run on one connection with no transaction between
    /// them, so a promotion — the interactive endpoint, or the auto-latest a new upload takes — can
    /// land in that window and make a selected row the project's latest. Deleting it then
    /// manufactures the zero-latest state the cap exists not to manufacture: every <c>latest</c>
    /// route 404s and the rollup degrades to "Not scanned".
    ///
    /// <para>The interleave is <b>deterministically sequenced</b>, not raced.
    /// <see cref="AfterDbReadHookStore"/> fires a one-shot hook when the first reader on the
    /// connection closes — which is exactly the moment the candidate SELECT has materialized and
    /// the delete loop has not yet started. An unsequenced two-thread version of this test would
    /// pin nothing: it would pass on the broken code whenever the threads happened not to
    /// interleave.</para>
    /// </summary>
    [Fact]
    public async Task Cap_RowPromotedBetweenSelectAndDelete_IsNotDeleted()
    {
        string projectId = await SeedProjectAsync("raced-promotion");
        string oldest = await SeedVersionAsync(projectId, "1.0.0", ageDays: 40);
        string middle = await SeedVersionAsync(projectId, "2.0.0", ageDays: 30);
        string latest = await SeedVersionAsync(projectId, "3.0.0", ageDays: 10, isLatest: true);
        string oldestBlob = await SeedDocumentAsync(projectId, oldest, "sbom", "cyclonedx-json");

        // keep=1 selects both `oldest` and `middle` for deletion; `latest` is excluded by the
        // is_latest predicate on the SELECT.
        var hookStore = new AfterDbReadHookStore(_db)
        {
            AfterRead = async () =>
            {
                // The racing promotion, committed on its own connection in the window between the
                // sweep's SELECT and its first DELETE: `oldest` becomes the project's latest.
                await using var racer = await _db.OpenAsync();
                await racer.ExecuteAsync(
                    "UPDATE project_versions SET is_latest = 0 WHERE project_id = @projectId",
                    new { projectId });
                await racer.ExecuteAsync(
                    "UPDATE project_versions SET is_latest = 1 WHERE id = @id", new { id = oldest });
            },
        };

        await using (var conn = await hookStore.OpenAsync())
        {
            await Build().EnforceProjectVersionLimitAsync(conn, OrgId, 1, CancellationToken.None);
        }

        // The promoted row survives: the DELETE re-asserts is_latest = 0 rather than trusting the
        // id the SELECT chose.
        Assert.True(await VersionExistsAsync(oldest));
        // ...and its documents are still referenced by a live version, so its bytes stay put.
        Assert.True(await _blobs.ExistsAsync(BlobKeys.StoreKey(oldestBlob)));

        // The row that was NOT promoted is still swept — the guard must be a predicate, not a
        // blanket bail-out that quietly stops the sweep the moment anything moves.
        Assert.False(await VersionExistsAsync(middle));
        Assert.True(await VersionExistsAsync(latest));

        // The invariant the whole guard exists for: the project still has exactly one latest.
        Assert.Equal(1, await LatestCountAsync(projectId));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private async Task RunSweepAsync(int keepProjectVersions)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET keep_project_versions = @cap WHERE org_id = @OrgId",
            new { cap = keepProjectVersions, OrgId });
        await Build().EnforceProjectVersionLimitAsync(conn, OrgId, keepProjectVersions, CancellationToken.None);
    }

    private async Task<string> SeedProjectAsync(string name)
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO projects (id, org_id, name) VALUES (@id, @OrgId, @name)",
            new { id, OrgId, name });
        return id;
    }

    private async Task<string> SeedVersionAsync(
        string projectId, string version, int ageDays, bool isLatest = false)
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO project_versions (id, org_id, project_id, version, is_latest, created_at)
            VALUES (@id, @OrgId, @projectId, @version, @isLatest, @createdAt)
            """,
            new
            {
                id,
                OrgId,
                projectId,
                version,
                isLatest = isLatest ? 1 : 0,
                createdAt = TestTime.KnownNow.AddDays(-ageDays).ToUtcIso(),
            });
        return id;
    }

    // Returns the blob key, which is also written to the blob store so a released blob is
    // observable rather than merely asserted about.
    private async Task<string> SeedDocumentAsync(
        string projectId, string projectVersionId, string docType, string format)
    {
        string sha = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(projectVersionId + docType))).ToLowerInvariant();
        string blobKey = BlobKeys.ProjectDocument(OrgId, projectId, projectVersionId, docType, sha);
        await _blobs.PutAsync(BlobKeys.StoreKey(blobKey), new MemoryStream(new byte[16]));

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO project_documents
                (id, org_id, project_version_id, doc_type, format, sha256, size_bytes, blob_key)
            VALUES (@id, @OrgId, @projectVersionId, @docType, @format, @sha, 16, @blobKey)
            """,
            new { id = Guid.NewGuid().ToString("N"), OrgId, projectVersionId, docType, format, sha, blobKey });
        return blobKey;
    }

    private async Task<long> LatestCountAsync(string projectId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM project_versions WHERE project_id = @projectId AND is_latest = 1",
            new { projectId });
    }

    private async Task<bool> VersionExistsAsync(string versionId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM project_versions WHERE id = @id", new { id = versionId }) > 0;
    }

    private RetentionService Build()
    {
        var cfg = new ConfigurationBuilder().Build();
        return new RetentionService(new RetentionService.Dependencies(
            _db, _blobs, new JwtRevocationRepository(_db, time: _clock),
            new InviteRepository(_db, _clock), new SamlConfigRepository(_db, _clock),
            new TrustedDeviceService(_db, _clock, cfg),
            cfg, new AirGapMode(cfg), NullLogger<RetentionService>.Instance, _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock),
            new Dependably.Protocol.OciOrphanBlobDeleter(
                _db, new TieredBlobStorage(_blobs, _blobs),
                new Dependably.Protocol.OciBlobKeyLock()),
            new Dependably.Infrastructure.Mail.EmailOutboxRepository(_db, _clock),
            new Dependably.Infrastructure.Mail.EmailOutboxPolicy(cfg),
            new OrgStatsHistoryRepository(_db),
            new BackgroundJobRunRepository(_db)));
    }
}
