using System.Globalization;
using System.Reflection;
using System.Security.Claims;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Endpoint-level coverage for <see cref="ProjectsController"/>: the response shapes the projects
/// UI binds to, the <c>latest</c> alias, the 404-not-403 BOLA posture on a cross-org id, and the
/// blob cleanup that runs after — never before — the rows are gone.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ProjectsControllerTests : IAsyncLifetime
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

    // ── Reads ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task List_ReturnsThePagedEnvelopeTheUiBindsTo()
    {
        var (controller, _) = Build();
        var repo = Repo();
        await repo.ResolveOrCreateAsync(
            _orgId, new ProjectVersionRequest("checkout", "1.0.0", true, IsLatest: true), _ownerId, CancellationToken.None);

        object payload = OkPayload(await controller.List());

        Assert.Equal(1, Field<int>(payload, "total"));
        Assert.Equal(50, Field<int>(payload, "limit"));
        Assert.Equal(0, Field<int>(payload, "offset"));

        object item = Assert.Single(Items(payload, "items"));
        Assert.Equal("checkout", Field<string>(item, "name"));
        Assert.Equal(ProjectKinds.Project, Field<string>(item, "kind"));
        Assert.Equal("1.0.0", Field<string>(item, "latestVersion"));
        Assert.Equal(0, Field<int>(item, "componentCount"));
        Assert.Null(Field<string?>(item, "policyStatus"));
        Assert.Null(Field<DateTimeOffset?>(item, "lastUploadAt"));

        object severity = Field<object>(item, "severityCounts")!;
        foreach (string bucket in new[] { "critical", "high", "medium", "low", "unscored" })
        {
            Assert.Equal(0, Field<int>(severity, bucket));
        }
    }

    [Fact]
    public async Task List_ClampsAnAbsurdPageSizeAndANegativeOffset()
    {
        var (controller, _) = Build();
        object payload = OkPayload(await controller.List(limit: 100_000, offset: -5));

        Assert.Equal(200, Field<int>(payload, "limit"));
        Assert.Equal(0, Field<int>(payload, "offset"));
    }

    [Fact]
    public async Task List_NeverShowsAnotherOrgsProjects()
    {
        var repo = Repo();
        await repo.CreateAsync(_foreignOrgId, new NewProject("theirs", ProjectKinds.Project), "u2");

        var (controller, _) = Build();
        object payload = OkPayload(await controller.List());

        Assert.Equal(0, Field<int>(payload, "total"));
        Assert.Empty(Items(payload, "items"));
    }

    [Fact]
    public async Task Get_ReturnsVersionsAndChildren()
    {
        var repo = Repo();
        var collection = await repo.CreateAsync(
            _orgId, new NewProject("monorepo", ProjectKinds.Collection, Description: "the mono-repo"), _ownerId);
        await repo.ResolveOrCreateAsync(
            _orgId, new ProjectVersionRequest("web", "1.0.0", true, ParentName: "monorepo", IsLatest: true), _ownerId, CancellationToken.None);

        var (controller, _) = Build();

        object collectionPayload = OkPayload(await controller.Get(collection.Id));
        Assert.Equal(ProjectKinds.Collection, Field<string>(collectionPayload, "kind"));
        Assert.Equal("the mono-repo", Field<string>(collectionPayload, "description"));
        Assert.Empty(Items(collectionPayload, "versions"));

        object child = Assert.Single(Items(collectionPayload, "children"));
        Assert.Equal("web", Field<string>(child, "name"));
        Assert.Equal("1.0.0", Field<string>(child, "latestVersion"));

        object childPayload = OkPayload(await controller.Get(Field<string>(child, "id")!));
        object version = Assert.Single(Items(childPayload, "versions"));
        Assert.Equal("1.0.0", Field<string>(version, "version"));
        Assert.True(Field<bool>(version, "isLatest"));
        Assert.Equal(0, Field<int>(version, "componentCount"));
    }

    [Fact]
    public async Task Get_ForAnotherOrgsProject_Is404NotForbidden()
    {
        var theirs = await Repo().CreateAsync(_foreignOrgId, new NewProject("theirs", ProjectKinds.Project), "u2");

        var (controller, _) = Build();
        Assert.IsType<NotFoundResult>(await controller.Get(theirs.Id));
    }

    // ── Create ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Create_ReturnsTheCreatedProjectAndAuditsIt()
    {
        var (controller, _) = Build();

        var created = Assert.IsType<CreatedResult>(
            await controller.Create(new CreateProjectRequest("checkout", Classifier: "library")));
        object payload = created.Value!;

        Assert.Equal("checkout", Field<string>(payload, "name"));
        Assert.Equal(ProjectKinds.Project, Field<string>(payload, "kind"));
        Assert.Equal("library", Field<string>(payload, "classifier"));
        Assert.Null(Field<string?>(payload, "parentId"));

        Assert.Equal(1, await AuditCountAsync("project.created"));
        Assert.Equal(_ownerId, await AuditActorAsync("project.created"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task Create_WithoutAName_Is422(string name)
    {
        var (controller, _) = Build();
        var result = Assert.IsType<ObjectResult>(await controller.Create(new CreateProjectRequest(name)));
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, result.StatusCode);
    }

    [Fact]
    public async Task Create_WithAnUnknownKindOrClassifier_Is422()
    {
        var (controller, _) = Build();

        var badKind = Assert.IsType<ObjectResult>(
            await controller.Create(new CreateProjectRequest("a", Kind: "folder")));
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, badKind.StatusCode);

        var badClassifier = Assert.IsType<ObjectResult>(
            await controller.Create(new CreateProjectRequest("b", Classifier: "spreadsheet")));
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, badClassifier.StatusCode);
    }

    [Fact]
    public async Task Create_DuplicateNameInTheSameScope_Is409()
    {
        var (controller, _) = Build();
        Assert.IsType<CreatedResult>(await controller.Create(new CreateProjectRequest("checkout")));

        var conflict = Assert.IsType<ObjectResult>(
            await controller.Create(new CreateProjectRequest("checkout")));
        Assert.Equal(StatusCodes.Status409Conflict, conflict.StatusCode);
    }

    [Fact]
    public async Task Create_UnderAnotherOrgsCollection_Is422AndCreatesNothing()
    {
        var foreign = await Repo().CreateAsync(_foreignOrgId, new NewProject("theirs", ProjectKinds.Collection), "u2");

        var (controller, _) = Build();
        var result = Assert.IsType<ObjectResult>(
            await controller.Create(new CreateProjectRequest("mine", ParentId: foreign.Id)));

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, result.StatusCode);
        Assert.Null(await Repo().GetByNameAsync(_orgId, null, "mine"));
    }

    // ── Promote ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task PromoteLatest_ReturnsTheVersionSummaryAndMovesTheFlag()
    {
        var repo = Repo();
        var v1 = await repo.ResolveOrCreateAsync(
            _orgId, new ProjectVersionRequest("checkout", "1.0.0", true, IsLatest: true), _ownerId, CancellationToken.None);
        var v2 = await repo.ResolveOrCreateAsync(
            _orgId, new ProjectVersionRequest("checkout", "2.0.0", true, IsLatest: false), _ownerId, CancellationToken.None);

        var (controller, _) = Build();
        object payload = OkPayload(await controller.PromoteLatest(v1.ProjectId, v2.ProjectVersionId));

        Assert.Equal(v2.ProjectVersionId, Field<string>(payload, "id"));
        Assert.Equal("2.0.0", Field<string>(payload, "version"));
        Assert.True(Field<bool>(payload, "isLatest"));
        Assert.Equal(1, await AuditCountAsync("project.version_promoted"));
    }

    [Fact]
    public async Task PromoteLatest_AcceptsTheLatestAliasAsANoOp()
    {
        var repo = Repo();
        var v1 = await repo.ResolveOrCreateAsync(
            _orgId, new ProjectVersionRequest("checkout", "1.0.0", true, IsLatest: true), _ownerId, CancellationToken.None);

        var (controller, _) = Build();
        object payload = OkPayload(await controller.PromoteLatest(v1.ProjectId, "latest"));

        Assert.Equal(v1.ProjectVersionId, Field<string>(payload, "id"));
        Assert.True(Field<bool>(payload, "isLatest"));
    }

    [Fact]
    public async Task PromoteLatest_ForAnotherOrgsVersion_Is404AndWritesNoAudit()
    {
        var repo = Repo();
        var theirs = await repo.ResolveOrCreateAsync(
            _foreignOrgId, new ProjectVersionRequest("checkout", "1.0.0", true, IsLatest: true), "u2", CancellationToken.None);

        var (controller, _) = Build();
        Assert.IsType<NotFoundResult>(
            await controller.PromoteLatest(theirs.ProjectId, theirs.ProjectVersionId));
        Assert.Equal(0, await AuditCountAsync("project.version_promoted"));
    }

    // ── Delete ───────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// The delete fans out over every document blob in the subtree. Mixed on purpose: one child
    /// carries two documents, another carries none, and one of the two blobs is missing from the
    /// store entirely — a partially-successful cleanup must still leave the delete a 204 with the
    /// present blob removed, because the rows are already gone by then and the surviving bytes are
    /// exactly what the orphan reconciler reclaims.
    /// </summary>
    [Fact]
    public async Task Delete_RemovesTheSubtreeAndTheDocumentBlobsItCanReach()
    {
        var repo = Repo();
        var collection = await repo.CreateAsync(_orgId, new NewProject("monorepo", ProjectKinds.Collection), _ownerId);
        var withDocs = await repo.ResolveOrCreateAsync(
            _orgId, new ProjectVersionRequest("web", "1.0.0", true, ParentName: "monorepo", IsLatest: true), _ownerId, CancellationToken.None);
        var withoutDocs = await repo.ResolveOrCreateAsync(
            _orgId, new ProjectVersionRequest("api", "1.0.0", true, ParentName: "monorepo", IsLatest: true), _ownerId, CancellationToken.None);

        string presentKey = BlobKeys.ProjectDocument(
            _orgId, withDocs.ProjectId, withDocs.ProjectVersionId, "sbom", new string('a', 64));
        string absentKey = BlobKeys.ProjectDocument(
            _orgId, withDocs.ProjectId, withDocs.ProjectVersionId, "sarif", new string('b', 64));

        await SeedDocumentAsync(withDocs.ProjectVersionId, "sbom", presentKey, new string('a', 64));
        await SeedDocumentAsync(withDocs.ProjectVersionId, "sarif", absentKey, new string('b', 64));

        var (controller, blobs) = Build();
        await blobs.PutAsync(presentKey, new MemoryStream("sbom"u8.ToArray()));
        // absentKey is deliberately never stored — the delete must survive the miss.

        Assert.IsType<NoContentResult>(await controller.Delete(collection.Id));

        Assert.False(await blobs.ExistsAsync(presentKey));
        Assert.False(await blobs.ExistsAsync(absentKey));

        Assert.Null(await repo.GetAsync(_orgId, collection.Id));
        Assert.Null(await repo.GetAsync(_orgId, withDocs.ProjectId));
        Assert.Null(await repo.GetAsync(_orgId, withoutDocs.ProjectId));
        Assert.Equal(0, await ProjectVersionCountAsync());
        Assert.Equal(0, await DocumentCountAsync());
        Assert.Equal(1, await AuditCountAsync("project.deleted"));
    }

    [Fact]
    public async Task Delete_ForAnotherOrgsProject_Is404AndLeavesItAlone()
    {
        var theirs = await Repo().CreateAsync(_foreignOrgId, new NewProject("theirs", ProjectKinds.Project), "u2");

        var (controller, _) = Build();
        Assert.IsType<NotFoundResult>(await controller.Delete(theirs.Id));

        Assert.NotNull(await Repo().GetAsync(_foreignOrgId, theirs.Id));
        Assert.Equal(0, await AuditCountAsync("project.deleted"));
    }

    [Fact]
    public async Task DeleteVersion_ViaTheLatestAlias_RemovesOnlyThatVersion()
    {
        var repo = Repo();
        var v1 = await repo.ResolveOrCreateAsync(
            _orgId, new ProjectVersionRequest("checkout", "1.0.0", true, IsLatest: false), _ownerId, CancellationToken.None);
        var v2 = await repo.ResolveOrCreateAsync(
            _orgId, new ProjectVersionRequest("checkout", "2.0.0", true, IsLatest: true), _ownerId, CancellationToken.None);

        var (controller, _) = Build();
        Assert.IsType<NoContentResult>(await controller.DeleteVersion(v1.ProjectId, "latest"));

        var remaining = await repo.ListVersionsAsync(_orgId, v1.ProjectId);
        Assert.Equal(v1.ProjectVersionId, Assert.Single(remaining).Id);
        Assert.NotEqual(v1.ProjectVersionId, v2.ProjectVersionId);
        Assert.Equal(1, await AuditCountAsync("project.version_deleted"));
    }

    [Fact]
    public async Task DeleteVersion_ForAnUnknownVersion_Is404()
    {
        var project = await Repo().CreateAsync(_orgId, new NewProject("checkout", ProjectKinds.Project), _ownerId);

        var (controller, _) = Build();
        Assert.IsType<NotFoundResult>(await controller.DeleteVersion(project.Id, "no-such-version"));
        Assert.IsType<NotFoundResult>(await controller.DeleteVersion(project.Id, "latest"));
    }

    // ── Audit attribution ────────────────────────────────────────────────────────────────────

    /// <summary>
    /// These routes authenticate on the API-token scheme as well as the session one, and a
    /// service token's subject is the token's own id. An audit row filed under the user
    /// discriminator against that id resolves through no join and reads as anonymous — the state
    /// an operator asking who deleted a project must never be shown.
    /// </summary>
    [Fact]
    public async Task Delete_DrivenByAServiceToken_WritesAResolvableServiceActor()
    {
        string tokenId = await SeedServiceTokenAsync("ci-pipeline");
        var project = await Repo().CreateAsync(_orgId, new NewProject("checkout", ProjectKinds.Project), _ownerId);

        var (controller, _) = Build(serviceTokenId: tokenId);
        Assert.IsType<NoContentResult>(await controller.Delete(project.Id));

        var row = await AuditAttributionAsync("project.deleted");
        Assert.Equal(tokenId, row.ActorId);
        Assert.Equal(ActorKinds.Service, row.ActorKind);
        Assert.Equal("ci-pipeline", row.ActorLabel);
    }

    [Fact]
    public async Task Delete_DrivenByAUser_IsUnchanged()
    {
        var project = await Repo().CreateAsync(_orgId, new NewProject("checkout", ProjectKinds.Project), _ownerId);

        var (controller, _) = Build();
        Assert.IsType<NoContentResult>(await controller.Delete(project.Id));

        var row = await AuditAttributionAsync("project.deleted");
        Assert.Equal(_ownerId, row.ActorId);
        Assert.Equal(ActorKinds.User, row.ActorKind);

        // A user's display name is an email, and the membership-removal and retention scrubs
        // clear a fixed column list — a denormalized one here would sit outside both.
        Assert.Null(row.ActorLabel);
    }

    [Fact]
    public async Task Create_DrivenByAServiceToken_WritesAResolvableServiceActor()
    {
        string tokenId = await SeedServiceTokenAsync("ci-pipeline");

        var (controller, _) = Build(serviceTokenId: tokenId);
        Assert.IsType<CreatedResult>(await controller.Create(new CreateProjectRequest("checkout")));

        var row = await AuditAttributionAsync("project.created");
        Assert.Equal(ActorKinds.Service, row.ActorKind);
        Assert.Equal("ci-pipeline", row.ActorLabel);
    }

    private async Task<string> SeedServiceTokenAsync(string name)
    {
        string tokenId = Guid.NewGuid().ToString("N");
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO service_tokens (id, org_id, name, token_hash)
            VALUES (@tokenId, @orgId, @name, @hash)
            """,
            new { tokenId, orgId = _orgId, name, hash = Guid.NewGuid().ToString("N") });
        return tokenId;
    }

    private async Task<AuditAttribution> AuditAttributionAsync(string action)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.QuerySingleAsync<AuditAttribution>(
            """
            SELECT actor_id AS ActorId, actor_kind AS ActorKind, actor_label AS ActorLabel
            FROM audit_log WHERE org_id = @orgId AND action = @action
            """,
            new { orgId = _orgId, action });
    }

    private sealed class AuditAttribution
    {
        public string? ActorId { get; set; }
        public string? ActorKind { get; set; }
        public string? ActorLabel { get; set; }
    }

    // ── Harness ──────────────────────────────────────────────────────────────────────────────

    private ProjectRepository Repo() => new(_fixture.Store, _clock);

    /// <summary>
    /// The controller under test, driven either by the seeded owner's session or — when
    /// <paramref name="serviceTokenId"/> is supplied — by a service token on the API-token
    /// scheme, which carries no users row and grants exactly its own <c>cap</c> claims.
    /// </summary>
    private (ProjectsController Controller, InMemoryBlobStore Blobs) Build(string? serviceTokenId = null)
    {
        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("acme.example.test");
        http.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("203.0.113.7");
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(_orgId, "acme");
        http.User = serviceTokenId is null
            ? new ClaimsPrincipal(new ClaimsIdentity(
                [
                    new Claim(ClaimTypes.NameIdentifier, _ownerId),
                    new Claim("sub", _ownerId),
                    new Claim("org_id", _orgId),
                    new Claim("tid", _orgId),
                    new Claim("role", "owner"),
                    new Claim("scope", "tenant"),
                ],
                authenticationType: "test"))
            : new ClaimsPrincipal(new ClaimsIdentity(
                [
                    new Claim(ClaimTypes.NameIdentifier, serviceTokenId),
                    new Claim("sub", serviceTokenId),
                    new Claim("org_id", _orgId),
                    new Claim("tid", _orgId),
                    new Claim("role", "ci"),
                    new Claim("scope", "tenant"),
                    new Claim("cap", Capabilities.TenantConfigure),
                ],
                authenticationType: TokenAuthenticationDefaults.Scheme));

        var blobs = new InMemoryBlobStore();
        var controller = new ProjectsController(
            Repo(),
            new OrgAccessGuard(_fixture.Store, TestProblems.Create()),
            new AuditRepository(_fixture.Store, null, _clock),
            new SbomIngestRepository(_fixture.Store),
            new ProblemResults(new EchoLocalizer()),
            new SingleStoreTenantStorageResolver(blobs),
            NullLogger<ProjectsController>.Instance)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };

        return (controller, blobs);
    }

    private async Task SeedDocumentAsync(string projectVersionId, string docType, string blobKey, string sha)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO project_documents (id, org_id, project_version_id, doc_type, format, sha256,
                                           size_bytes, blob_key, uploaded_at)
            VALUES (@id, @orgId, @projectVersionId, @docType, @format, @sha, 4, @blobKey, @uploadedAt)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                orgId = _orgId,
                projectVersionId,
                docType,
                format = docType == "sarif" ? "sarif-json" : "cyclonedx-json",
                sha,
                blobKey,
                uploadedAt = _clock.GetUtcNow().ToUtcIso(),
            });
    }

    private async Task<long> AuditCountAsync(string action)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE org_id = @orgId AND action = @action",
            new { orgId = _orgId, action });
    }

    private async Task<string?> AuditActorAsync(string action)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT actor_id FROM audit_log WHERE org_id = @orgId AND action = @action",
            new { orgId = _orgId, action });
    }

    private async Task<long> ProjectVersionCountAsync()
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM project_versions WHERE org_id = @orgId", new { orgId = _orgId });
    }

    private async Task<long> DocumentCountAsync()
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM project_documents WHERE org_id = @orgId", new { orgId = _orgId });
    }

    // The controller returns anonymous types, exactly as the JSON serializer sees them; reading
    // them reflectively is what keeps these assertions bound to the wire shape rather than to a
    // DTO that could drift from it.
    private static object OkPayload(IActionResult result) => Assert.IsType<OkObjectResult>(result).Value!;

    private static T? Field<T>(object payload, string name)
    {
        var prop = payload.GetType().GetProperty(name)
            ?? throw new Xunit.Sdk.XunitException(
                $"payload has no '{name}' field; it has: " +
                string.Join(", ", payload.GetType().GetProperties().Select(p => p.Name)));
        return (T?)prop.GetValue(payload);
    }

    private static List<object> Items(object payload, string name) =>
        ((System.Collections.IEnumerable)Field<object>(payload, name)!).Cast<object>().ToList();

    private sealed class EchoLocalizer : IStringLocalizer<SharedResource>
    {
        public LocalizedString this[string name] => new(name, name, resourceNotFound: false);
        public LocalizedString this[string name, params object[] arguments]
            => new(name, string.Format(CultureInfo.InvariantCulture, name, arguments), resourceNotFound: false);
        public IEnumerable<LocalizedString> GetAllStrings(bool includeParentCultures) => [];
    }

    // Community's pool shape: one registry store for every tenant. Mirrors the production
    // resolver's community arm without dragging in its lifecycle gate.
    private sealed class SingleStoreTenantStorageResolver : ITenantStorageResolver
    {
        public SingleStoreTenantStorageResolver(IBlobStore store) => Cache = store;
        public Task<IBlobStore> GetRegistryAsync(string tenantId, CancellationToken ct = default)
            => Task.FromResult(Cache);
        public IBlobStore Cache { get; }
    }
}
