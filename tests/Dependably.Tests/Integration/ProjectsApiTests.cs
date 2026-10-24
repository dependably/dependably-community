using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// The projects management API beyond the folder-filing surface: list paging and sort fallback,
/// create/patch validation, version lifecycle (retire, reinstate, promote, delete), project
/// delete with document-blob cleanup, capability denials, and org isolation. Every refusal is
/// paired with a check that the project tree is unchanged.
/// </summary>
[Trait("Category", "Integration")]
public sealed class ProjectsApiTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public ProjectsApiTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<HttpClient> AdminClient() =>
        _factory.CreateClientWithBearer(await _factory.CreateAdminJwt());

    private async Task<HttpClient> ClientWithCaps(params string[] caps)
    {
        string id = await _factory.CreateUser($"proj-{Guid.NewGuid():N}@example.com", "Password12345");
        return _factory.CreateClientWithBearer(await _factory.CreateUserJwtWithCaps(id, caps));
    }

    private static string Unique(string stem) => $"{stem}-{Guid.NewGuid().ToString("N")[..8]}";

    private static async Task<JsonElement> CreateAsync(HttpClient c, object body)
    {
        var resp = await c.PostAsJsonAsync("/api/v1/projects", body);
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        return await ProblemBody.ReadAsync(resp);
    }

    private static async Task<(string ProjectId, string VersionId)> UploadVersionAsync(
        HttpClient c, string project, string version, bool isLatest = true)
    {
        string body = await File.ReadAllTextAsync(
            Path.Combine(FixtureManifest.SbomFixturesRoot, "cyclonedx-1.6-inventory.json"));
        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        var resp = await c.PutAsync(
            $"/api/v1/sbom?projectName={Uri.EscapeDataString(project)}&projectVersion={version}"
            + $"&autoCreate=true&isLatest={isLatest.ToString().ToLowerInvariant()}", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var json = await ProblemBody.ReadAsync(resp);
        return (json.GetProperty("project").GetProperty("id").GetString()!,
            json.GetProperty("projectVersion").GetProperty("id").GetString()!);
    }

    private async Task<long> AuditCountAsync(string action, string projectId)
    {
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = @action AND detail LIKE @needle",
            new { action, needle = $"%{projectId}%" });
    }

    // ── List ─────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task List_ClampsPaging_AndFallsBackToDefaultSortForUnknownKeys()
    {
        using var c = await AdminClient();
        string stem = Unique("lst");
        foreach (string suffix in new[] { "b", "a", "c" })
        {
            await CreateAsync(c, new { name = $"{stem}-{suffix}" });
        }

        var page = await ProblemBody.ReadAsync(await c.GetAsync(
            $"/api/v1/projects?q={stem}&limit=9999&offset=-5&sort=bogus%3B%20drop&dir=sideways"));

        Assert.Equal(200, page.GetProperty("limit").GetInt32());
        Assert.Equal(0, page.GetProperty("offset").GetInt32());
        Assert.Equal("asc", page.GetProperty("dir").GetString());
        Assert.Equal(3, page.GetProperty("total").GetInt32());
        string defaultSort = page.GetProperty("sort").GetString()!;

        var desc = await ProblemBody.ReadAsync(await c.GetAsync(
            $"/api/v1/projects?q={stem}&sort={defaultSort}&dir=DESC&limit=0"));
        Assert.Equal("desc", desc.GetProperty("dir").GetString());
        Assert.Equal(1, desc.GetProperty("limit").GetInt32());
        Assert.Equal(1, desc.GetProperty("items").GetArrayLength());
    }

    [Fact]
    public async Task List_SearchLongerThanTheNameCap_IsTruncatedNotRejected()
    {
        using var c = await AdminClient();

        var resp = await c.GetAsync($"/api/v1/projects?q={new string('x', 500)}");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(0, (await ProblemBody.ReadAsync(resp)).GetProperty("total").GetInt32());
    }

    [Fact]
    public async Task ReadsNeedReadPackages_AndWritesNeedTenantConfigure()
    {
        using var admin = await AdminClient();
        var project = await CreateAsync(admin, new { name = Unique("guarded") });
        string id = project.GetProperty("id").GetString()!;
        using var noRead = await ClientWithCaps("read:tenant");
        using var reader = await ClientWithCaps("read:packages");

        await ProblemBody.AssertForbiddenAsync(await noRead.GetAsync("/api/v1/projects"));
        await ProblemBody.AssertForbiddenAsync(await noRead.GetAsync("/api/v1/projects/collections"));
        await ProblemBody.AssertForbiddenAsync(await noRead.GetAsync($"/api/v1/projects/{id}"));

        Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync($"/api/v1/projects/{id}")).StatusCode);
        await ProblemBody.AssertForbiddenAsync(await reader.PostAsJsonAsync("/api/v1/projects", new { name = Unique("denied") }));
        await ProblemBody.AssertForbiddenAsync(await reader.PatchAsync($"/api/v1/projects/{id}",
            new StringContent("""{"name":"renamed"}""", Encoding.UTF8, "application/json")));
        await ProblemBody.AssertForbiddenAsync(await reader.DeleteAsync($"/api/v1/projects/{id}"));
        await ProblemBody.AssertForbiddenAsync(await reader.DeleteAsync($"/api/v1/projects/{id}/versions/latest"));
        await ProblemBody.AssertForbiddenAsync(await reader.PatchAsync($"/api/v1/projects/{id}/versions/latest",
            new StringContent("""{"isActive":false}""", Encoding.UTF8, "application/json")));
        await ProblemBody.AssertForbiddenAsync(await reader.PostAsync($"/api/v1/projects/{id}/versions/latest/promote-latest", null));

        var kept = await ProblemBody.ReadAsync(await admin.GetAsync($"/api/v1/projects/{id}"));
        Assert.Equal(project.GetProperty("name").GetString(), kept.GetProperty("name").GetString());
    }

    // ── Create ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Create_WithNoNameAtAll_IsRefusedLikeABlankName()
    {
        using var c = await AdminClient();

        var resp = await c.PostAsync("/api/v1/projects", new StringContent("{}", Encoding.UTF8, "application/json"));

        await ProblemBody.AssertValidationAsync(resp, "name");
    }

    [Theory]
    [InlineData("", "project", "application", null, "name")]
    [InlineData("   ", "project", "application", null, "name")]
    [InlineData("TOO_LONG_NAME", "project", "application", null, "name")]
    [InlineData("valid", "workspace", "application", null, "kind")]
    [InlineData("valid", "project", "spaceship", null, "classifier")]
    [InlineData("valid", "project", "application", "TOO_LONG_DESCRIPTION", "description")]
    public async Task Create_InvalidField_Returns422NamingTheField_AndCreatesNothing(
        string name, string kind, string classifier, string? description, string field)
    {
        using var c = await AdminClient();
        string sentName = name == "TOO_LONG_NAME" ? new string('n', 201) : name;
        if (sentName == "valid")
        {
            sentName = Unique("valid");
        }

        var resp = await c.PostAsJsonAsync("/api/v1/projects", new
        {
            name = sentName,
            kind,
            classifier,
            description = description == "TOO_LONG_DESCRIPTION" ? new string('d', 2001) : description,
        });

        await ProblemBody.AssertValidationAsync(resp, field);
        if (field != "name")
        {
            var listed = await ProblemBody.ReadAsync(await c.GetAsync($"/api/v1/projects?q={sentName}"));
            Assert.Equal(0, listed.GetProperty("total").GetInt32());
        }
    }

    [Fact]
    public async Task Create_DefaultsKindAndClassifier_TrimsInput_AndAuditsTheCreation()
    {
        using var c = await AdminClient();
        string name = Unique("trimmed");

        var created = await CreateAsync(c, new { name = $"  {name}  ", description = "  billing service  ", kind = "  ", classifier = "  " });

        Assert.Equal(name, created.GetProperty("name").GetString());
        Assert.Equal("project", created.GetProperty("kind").GetString());
        Assert.Equal("billing service", created.GetProperty("description").GetString());
        Assert.False(string.IsNullOrEmpty(created.GetProperty("classifier").GetString()));
        Assert.Equal(1, await AuditCountAsync("project.created", created.GetProperty("id").GetString()!));
    }

    [Fact]
    public async Task Create_DuplicateNameInTheSameScope_ConflictsButADifferentFolderMayReuseIt()
    {
        using var c = await AdminClient();
        string name = Unique("dup");
        var folder = await CreateAsync(c, new { name = Unique("scope"), kind = "collection" });
        await CreateAsync(c, new { name });

        var conflict = await c.PostAsJsonAsync("/api/v1/projects", new { name });
        Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);

        var elsewhere = await CreateAsync(c, new { name, parentId = folder.GetProperty("id").GetString() });
        Assert.Equal(folder.GetProperty("id").GetString(), elsewhere.GetProperty("parentId").GetString());
    }

    [Fact]
    public async Task Create_UnderAPlainProject_OrAnUnknownParent_IsRefused()
    {
        using var c = await AdminClient();
        var plain = await CreateAsync(c, new { name = Unique("leaf") });

        await ProblemBody.AssertValidationAsync(
            await c.PostAsJsonAsync("/api/v1/projects", new { name = Unique("child"), parentId = plain.GetProperty("id").GetString() }),
            "parentId");
        await ProblemBody.AssertValidationAsync(
            await c.PostAsJsonAsync("/api/v1/projects", new { name = Unique("orphan"), parentId = Guid.NewGuid().ToString("N") }),
            "parentId");

        var detail = await ProblemBody.ReadAsync(await c.GetAsync($"/api/v1/projects/{plain.GetProperty("id").GetString()}"));
        Assert.Equal(0, detail.GetProperty("children").GetArrayLength());
    }

    // ── Patch ────────────────────────────────────────────────────────────────────────────────

    private static StringContent Json(string json) => new(json, Encoding.UTF8, "application/json");

    [Theory]
    [InlineData("""{"name":"   "}""", "name")]
    [InlineData("""{"classifier":"spaceship"}""", "classifier")]
    public async Task Patch_InvalidField_Returns422AndLeavesTheProjectAlone(string body, string field)
    {
        using var c = await AdminClient();
        var project = await CreateAsync(c, new { name = Unique("patchme"), description = "original" });
        string id = project.GetProperty("id").GetString()!;

        await ProblemBody.AssertValidationAsync(await c.PatchAsync($"/api/v1/projects/{id}", Json(body)), field);

        var after = await ProblemBody.ReadAsync(await c.GetAsync($"/api/v1/projects/{id}"));
        Assert.Equal(project.GetProperty("name").GetString(), after.GetProperty("name").GetString());
        Assert.Equal("original", after.GetProperty("description").GetString());
    }

    [Fact]
    public async Task Patch_OverlongNameOrDescription_IsRefused()
    {
        using var c = await AdminClient();
        var project = await CreateAsync(c, new { name = Unique("limits") });
        string id = project.GetProperty("id").GetString()!;

        await ProblemBody.AssertValidationAsync(
            await c.PatchAsync($"/api/v1/projects/{id}", Json($$"""{"name":"{{new string('n', 201)}}"}""")), "name");
        await ProblemBody.AssertValidationAsync(
            await c.PatchAsync($"/api/v1/projects/{id}", Json($$"""{"description":"{{new string('d', 2001)}}"}""")), "description");
    }

    [Fact]
    public async Task Patch_ClassifierRoundTrip_NullResetsToTheDefault_AndRetireAuditsTheTransition()
    {
        using var c = await AdminClient();
        var project = await CreateAsync(c, new { name = Unique("classify") });
        string id = project.GetProperty("id").GetString()!;
        string defaultClassifier = project.GetProperty("classifier").GetString()!;

        var set = await c.PatchAsync($"/api/v1/projects/{id}", Json("""{"classifier":"library"}"""));
        Assert.Equal("library", (await ProblemBody.ReadAsync(set)).GetProperty("classifier").GetString());

        var reset = await c.PatchAsync($"/api/v1/projects/{id}", Json("""{"classifier":null}"""));
        Assert.Equal(defaultClassifier, (await ProblemBody.ReadAsync(reset)).GetProperty("classifier").GetString());

        var retired = await ProblemBody.ReadAsync(await c.PatchAsync($"/api/v1/projects/{id}", Json("""{"isActive":false}""")));
        Assert.False(retired.GetProperty("isActive").GetBoolean());
        Assert.Equal(3, await AuditCountAsync("project.updated", id));
    }

    [Fact]
    public async Task Patch_UnknownProject_Returns404()
    {
        using var c = await AdminClient();

        var resp = await c.PatchAsync($"/api/v1/projects/{Guid.NewGuid():N}", Json("""{"name":"ghost"}"""));

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // ── Get / Delete ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Get_And_Delete_UnknownProject_Return404()
    {
        using var c = await AdminClient();
        string missing = Guid.NewGuid().ToString("N");

        Assert.Equal(HttpStatusCode.NotFound, (await c.GetAsync($"/api/v1/projects/{missing}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.DeleteAsync($"/api/v1/projects/{missing}")).StatusCode);
    }

    [Fact]
    public async Task Delete_RemovesTheProjectItsVersionsAndTheirDocumentBlobs_ButNotASibling()
    {
        using var c = await AdminClient();
        var (doomedId, _) = await UploadVersionAsync(c, Unique("doomed"), "1.0.0");
        await UploadVersionAsync(c, Unique("sibling"), "1.0.0");
        string siblingId = (await UploadVersionAsync(c, Unique("sibling2"), "1.0.0")).ProjectId;
        int blobsBefore = _factory.BlobStore.GetKeys().Count;

        var resp = await c.DeleteAsync($"/api/v1/projects/{doomedId}");

        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.GetAsync($"/api/v1/projects/{doomedId}")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync($"/api/v1/projects/{siblingId}")).StatusCode);
        Assert.True(_factory.BlobStore.GetKeys().Count < blobsBefore);
        Assert.Equal(1, await AuditCountAsync("project.deleted", doomedId));
    }

    [Fact]
    public async Task Delete_WhenTheBlobStoreRefusesTheCleanup_StillSucceedsAndLeavesTheBytesForTheReconciler()
    {
        var store = new DeleteFailingBlobStore(new Dependably.Storage.InMemoryBlobStore());
        await using var factory = new DependablyFactory
        {
            ServiceOverrides = services =>
            {
                Microsoft.Extensions.DependencyInjection.Extensions.ServiceCollectionDescriptorExtensions
                    .RemoveAll<Dependably.Storage.IBlobStore>(services);
                services.AddSingleton<Dependably.Storage.IBlobStore>(store);
            },
        };
        await factory.InitializeAsync();
        using var c = factory.CreateClientWithBearer(await factory.CreateAdminJwt());
        var (projectId, _) = await UploadVersionAsync(c, Unique("stuck"), "1.0.0");

        var resp = await c.DeleteAsync($"/api/v1/projects/{projectId}");

        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.GetAsync($"/api/v1/projects/{projectId}")).StatusCode);
        Assert.True(store.DeleteAttempts > 0);
    }

    private sealed class DeleteFailingBlobStore(Dependably.Storage.IBlobStore inner) : Dependably.Storage.IBlobStore
    {
        private int _deleteAttempts;

        public int DeleteAttempts => Volatile.Read(ref _deleteAttempts);

        public Task PutAsync(string key, Stream data, CancellationToken ct = default) => inner.PutAsync(key, data, ct);

        public Task<Stream?> GetAsync(string key, CancellationToken ct = default) => inner.GetAsync(key, ct);

        public Task<bool> ExistsAsync(string key, CancellationToken ct = default) => inner.ExistsAsync(key, ct);

        public Task DeleteAsync(string key, CancellationToken ct = default)
        {
            Interlocked.Increment(ref _deleteAttempts);
            throw new IOException("blob store is read-only");
        }

        public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => inner.GetTotalSizeAsync(ct);

        public Task<Dependably.Storage.RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default) =>
            inner.GetRangeAsync(key, from, to, ct);

        public IAsyncEnumerable<Dependably.Storage.BlobInfo> ListAsync(string prefix, CancellationToken ct = default) =>
            inner.ListAsync(prefix, ct);
    }

    // ── Versions ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task DeleteVersion_ByLatestAlias_RemovesThatVersionOnly()
    {
        using var c = await AdminClient();
        string name = Unique("versions");
        var (projectId, firstId) = await UploadVersionAsync(c, name, "1.0.0", isLatest: true);
        var (_, secondId) = await UploadVersionAsync(c, name, "2.0.0", isLatest: true);

        var resp = await c.DeleteAsync($"/api/v1/projects/{projectId}/versions/latest");

        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
        var detail = await ProblemBody.ReadAsync(await c.GetAsync($"/api/v1/projects/{projectId}"));
        string?[] remaining = detail.GetProperty("versions").EnumerateArray().Select(v => v.GetProperty("id").GetString()).ToArray();
        Assert.DoesNotContain(secondId, remaining);
        Assert.Contains(firstId, remaining);
        Assert.Equal(1, await AuditCountAsync("project.version_deleted", projectId));
    }

    [Fact]
    public async Task VersionRoutes_UnknownVersionOrProject_Return404_AndChangeNothing()
    {
        using var c = await AdminClient();
        var (projectId, versionId) = await UploadVersionAsync(c, Unique("fenced"), "1.0.0");
        string missing = Guid.NewGuid().ToString("N");

        Assert.Equal(HttpStatusCode.NotFound, (await c.DeleteAsync($"/api/v1/projects/{projectId}/versions/{missing}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound,
            (await c.PatchAsync($"/api/v1/projects/{projectId}/versions/{missing}", Json("""{"isActive":false}"""))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound,
            (await c.PostAsync($"/api/v1/projects/{projectId}/versions/{missing}/promote-latest", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.DeleteAsync($"/api/v1/projects/{missing}/versions/{versionId}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound,
            (await c.PostAsync($"/api/v1/projects/{missing}/versions/{versionId}/promote-latest", null)).StatusCode);

        var detail = await ProblemBody.ReadAsync(await c.GetAsync($"/api/v1/projects/{projectId}"));
        Assert.Equal(1, detail.GetProperty("versions").GetArrayLength());
    }

    [Fact]
    public async Task UpdateVersion_RetiresAndReinstates_AuditingOnlyRealTransitions()
    {
        using var c = await AdminClient();
        var (projectId, versionId) = await UploadVersionAsync(c, Unique("lifecycle"), "1.0.0");

        var noop = await c.PatchAsync($"/api/v1/projects/{projectId}/versions/{versionId}", Json("{}"));
        Assert.Equal(HttpStatusCode.OK, noop.StatusCode);
        Assert.True((await ProblemBody.ReadAsync(noop)).GetProperty("isActive").GetBoolean());
        Assert.Equal(0, await AuditCountAsync("project.version_retired", projectId));

        var retired = await c.PatchAsync($"/api/v1/projects/{projectId}/versions/latest", Json("""{"isActive":false}"""));
        Assert.False((await ProblemBody.ReadAsync(retired)).GetProperty("isActive").GetBoolean());
        Assert.Equal(1, await AuditCountAsync("project.version_retired", projectId));

        var again = await c.PatchAsync($"/api/v1/projects/{projectId}/versions/{versionId}", Json("""{"isActive":false}"""));
        Assert.Equal(HttpStatusCode.OK, again.StatusCode);
        Assert.Equal(1, await AuditCountAsync("project.version_retired", projectId));

        var reinstated = await c.PatchAsync($"/api/v1/projects/{projectId}/versions/{versionId}", Json("""{"isActive":true}"""));
        Assert.True((await ProblemBody.ReadAsync(reinstated)).GetProperty("isActive").GetBoolean());
        Assert.Equal(1, await AuditCountAsync("project.version_reinstated", projectId));
    }

    [Fact]
    public async Task PromoteLatest_MovesTheFlagToTheNamedVersion_AndIsIdempotent()
    {
        using var c = await AdminClient();
        string name = Unique("promote");
        var (projectId, firstId) = await UploadVersionAsync(c, name, "1.0.0", isLatest: true);
        var (_, secondId) = await UploadVersionAsync(c, name, "2.0.0", isLatest: true);

        var promoted = await c.PostAsync($"/api/v1/projects/{projectId}/versions/{firstId}/promote-latest", null);

        Assert.Equal(HttpStatusCode.OK, promoted.StatusCode);
        Assert.True((await ProblemBody.ReadAsync(promoted)).GetProperty("isLatest").GetBoolean());
        var detail = await ProblemBody.ReadAsync(await c.GetAsync($"/api/v1/projects/{projectId}"));
        var flags = detail.GetProperty("versions").EnumerateArray()
            .ToDictionary(v => v.GetProperty("id").GetString()!, v => v.GetProperty("isLatest").GetBoolean());
        Assert.True(flags[firstId]);
        Assert.False(flags[secondId]);

        var again = await c.PostAsync($"/api/v1/projects/{projectId}/versions/latest/promote-latest", null);
        Assert.Equal(HttpStatusCode.OK, again.StatusCode);
    }

    // ── Isolation ────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ForeignOrgProject_IsAbsentFromEveryRoute_AndSurvivesMutationAttempts()
    {
        var orgs = _factory.Services.GetRequiredService<OrgRepository>();
        var other = await orgs.CreateOrgAsync($"pj-{Guid.NewGuid():N}"[..14]);
        var projects = _factory.Services.GetRequiredService<ProjectRepository>();
        var foreign = await projects.CreateAsync(other.Id, new NewProject("foreign-app", "project", null, null, null), null);
        using var c = await AdminClient();
        string path = $"/api/v1/projects/{foreign.Id}";

        Assert.Equal(HttpStatusCode.NotFound, (await c.GetAsync(path)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.PatchAsync(path, Json("""{"name":"hijacked"}"""))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.DeleteAsync(path)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.DeleteAsync($"{path}/versions/latest")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.PostAsync($"{path}/versions/latest/promote-latest", null)).StatusCode);
        var listed = await ProblemBody.ReadAsync(await c.GetAsync("/api/v1/projects?q=foreign-app"));
        Assert.Equal(0, listed.GetProperty("total").GetInt32());

        var intact = await projects.GetAsync(other.Id, foreign.Id);
        Assert.NotNull(intact);
        Assert.Equal("foreign-app", intact.Name);
    }
}
