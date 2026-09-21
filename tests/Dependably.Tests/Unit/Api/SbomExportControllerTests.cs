using System.Security.Claims;
using System.Text;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Sbom;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// <see cref="SbomExportController.DownloadOriginal"/> resolves its blob read the same way every
/// other surface on the Projects plane resolves a write or a read: through
/// <see cref="ITenantStorageResolver.GetRegistryAsync"/>, never a bare <see cref="IBlobStore"/>
/// singleton. A resolver that hands back a store distinct from any other store in the process is
/// what makes that observable — the download can only ever see the bytes the resolver's store
/// holds.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomExportControllerTests : IAsyncLifetime
{
    private readonly InMemoryDbFixture _fixture = new();
    private readonly Microsoft.Extensions.Time.Testing.FakeTimeProvider _clock = TestTime.Frozen();

    private string _orgId = "";
    private string _foreignOrgId = "";
    private string _ownerId = "";

    public async Task InitializeAsync()
    {
        await _fixture.InitializeAsync();
        _orgId = await OrgSeeder.InsertAsync(_fixture.Store, "acme");
        _foreignOrgId = await OrgSeeder.InsertAsync(_fixture.Store, "globex");
        _ownerId = await UserSeeder.InsertAsync(_fixture.Store, _orgId, "owner@acme.test", "owner");
    }

    public async Task DisposeAsync() => await _fixture.DisposeAsync();

    [Fact]
    public async Task DownloadOriginal_ReadsThroughTheTenantStorageResolversStore()
    {
        string blobKey = BlobKeys.ProjectDocument(_orgId, "proj-1", "ver-1", "sbom", new string('a', 64));
        byte[] correctBytes = Encoding.UTF8.GetBytes("{\"bomFormat\":\"CycloneDX\"}");

        // The resolver's store is the only place the fixed controller can read from. A second,
        // unreachable store stands in for "some other IBlobStore singleton" — the shape the bug
        // read from — carrying different bytes at the identical key, so a regression that started
        // reading anything but the resolver's store would return this instead and fail the assert.
        var resolverStore = new InMemoryBlobStore();
        var unreachableStore = new InMemoryBlobStore();
        await using (var correct = new MemoryStream(correctBytes))
        {
            await resolverStore.PutAsync(blobKey, correct);
        }

        await using (var wrong = new MemoryStream(Encoding.UTF8.GetBytes("not the right bytes")))
        {
            await unreachableStore.PutAsync(blobKey, wrong);
        }

        string documentId = await SeedDocumentAsync(blobKey, new string('a', 64));

        var controller = Build(new SingleStoreTenantStorageResolver(resolverStore));
        var result = await controller.DownloadOriginal(documentId, CancellationToken.None);

        var file = Assert.IsType<FileStreamResult>(result);
        await using var ms = new MemoryStream();
        await file.FileStream.CopyToAsync(ms);
        Assert.Equal(correctBytes, ms.ToArray());
    }

    [Fact]
    public async Task DownloadOriginal_UnknownDocument_Returns404()
    {
        var controller = Build(new SingleStoreTenantStorageResolver(new InMemoryBlobStore()));
        var result = await controller.DownloadOriginal(Guid.NewGuid().ToString("N"), CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task DownloadOriginal_TokenFromOtherOrg_Returns404NotForbidden()
    {
        string blobKey = BlobKeys.ProjectDocument(_foreignOrgId, "proj-2", "ver-2", "sbom", new string('b', 64));
        var store = new InMemoryBlobStore();
        await using (var bytes = new MemoryStream(Encoding.UTF8.GetBytes("{}")))
        {
            await store.PutAsync(blobKey, bytes);
        }

        string documentId = await SeedDocumentAsync(_foreignOrgId, blobKey, new string('b', 64));

        var controller = Build(new SingleStoreTenantStorageResolver(store));
        var result = await controller.DownloadOriginal(documentId, CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    // ── Harness ──────────────────────────────────────────────────────────────────────────────

    private Task<string> SeedDocumentAsync(string blobKey, string sha) => SeedDocumentAsync(_orgId, blobKey, sha);

    private async Task<string> SeedDocumentAsync(string orgId, string blobKey, string sha)
    {
        string projectId = Guid.NewGuid().ToString("N");
        string versionId = Guid.NewGuid().ToString("N");
        string documentId = Guid.NewGuid().ToString("N");
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO projects (id, org_id, kind, name, classifier, created_at)
            VALUES (@projectId, @orgId, 'project', 'checkout', 'application', @now)
            """,
            new { projectId, orgId, now = _clock.GetUtcNow().ToUtcIso() });
        await conn.ExecuteAsync(
            """
            INSERT INTO project_versions (id, org_id, project_id, version, is_latest, created_at)
            VALUES (@versionId, @orgId, @projectId, '1.0.0', 1, @now)
            """,
            new { versionId, orgId, projectId, now = _clock.GetUtcNow().ToUtcIso() });
        await conn.ExecuteAsync(
            """
            INSERT INTO project_documents (id, org_id, project_version_id, doc_type, format, sha256,
                                           size_bytes, blob_key, uploaded_at)
            VALUES (@documentId, @orgId, @versionId, 'sbom', 'cyclonedx-json', @sha, 4, @blobKey, @now)
            """,
            new { documentId, orgId, versionId, sha, blobKey, now = _clock.GetUtcNow().ToUtcIso() });
        return documentId;
    }

    private SbomExportController Build(ITenantStorageResolver resolver)
    {
        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("acme.example.test");
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(_orgId, "acme");
        http.User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, _ownerId),
                new Claim("sub", _ownerId),
                new Claim("org_id", _orgId),
                new Claim("tid", _orgId),
                new Claim("role", "owner"),
                new Claim("scope", "tenant"),
            ],
            authenticationType: "test"));

        var documents = new SbomDocumentStore(resolver, new ProjectDocumentRepository(_fixture.Store));
        var tracker = new Dependably.Infrastructure.VulnTracker.InstanceVulnTrackerConfig(
            (_, _) => Task.FromResult<string?>(null), _clock);
        var controller = new SbomExportController(
            new SbomExportService(_fixture.Store, _clock, new ProjectRepository(_fixture.Store, _clock), tracker, Dependably.Tests.Infrastructure.TestSbomAuthorSigner.Unconfigured(_fixture.Store, _clock)),
            new OrgAccessGuard(_fixture.Store, TestProblems.Create()),
            new ProblemResults(new EchoLocalizer()),
            documents)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };

        return controller;
    }

    /// <summary>Community's pool shape: one registry store for every tenant, chosen by the test.</summary>
    private sealed class SingleStoreTenantStorageResolver : ITenantStorageResolver
    {
        public SingleStoreTenantStorageResolver(IBlobStore store) => Cache = store;
        public Task<IBlobStore> GetRegistryAsync(string tenantId, CancellationToken ct = default)
            => Task.FromResult(Cache);
        public IBlobStore Cache { get; }
    }

    private sealed class EchoLocalizer : IStringLocalizer<SharedResource>
    {
        public LocalizedString this[string name] => new(name, name, resourceNotFound: false);
        public LocalizedString this[string name, params object[] arguments]
            => new(name, string.Format(System.Globalization.CultureInfo.InvariantCulture, name, arguments), resourceNotFound: false);
        public IEnumerable<LocalizedString> GetAllStrings(bool includeParentCultures) => [];
    }
}
