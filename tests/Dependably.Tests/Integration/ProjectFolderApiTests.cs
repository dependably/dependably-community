using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// The folder-filing surface of the projects plane: creating a collection, the flat collection
/// listing the relocation picker reads, the root-first ancestor chain the breadcrumb climbs, and
/// <c>PATCH /api/v1/projects/{id}</c>'s rename/relocate semantics.
///
/// Two properties get an adversarial twin rather than a single happy-path probe, because both
/// fail silently in the direction that matters:
/// <list type="bullet">
///   <item>a refused move must also leave the tree exactly as it was — a refusal that still wrote
///   would strand the subtree in a cycle no read can reach; and</item>
///   <item>leave-unchanged-on-absent must actually leave the untouched columns alone — a PATCH
///   that blanks a description nobody edited looks identical to a successful rename.</item>
/// </list>
/// </summary>
[Trait("Category", "Integration")]
public sealed class ProjectFolderApiTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public ProjectFolderApiTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    // ── Create ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task NewFolder_IsCreatedAsACollectionAtTheRoot()
    {
        using var client = await AdminClient();

        var created = await CreateFolderAsync(client, Unique("platform"));

        Assert.Equal("collection", created.GetProperty("kind").GetString());
        Assert.Equal(JsonValueKind.Null, created.GetProperty("parentId").ValueKind);
    }

    [Fact]
    public async Task ListCollections_ReturnsFoldersAndNotPlainProjects()
    {
        using var client = await AdminClient();
        string folderName = Unique("folder");
        string projectName = Unique("plain");
        var folder = await CreateFolderAsync(client, folderName);
        await CreateProjectAsync(client, projectName);

        using var resp = await client.GetAsync("/api/v1/projects/collections");
        resp.EnsureSuccessStatusCode();
        var items = (await ReadJsonAsync(resp)).GetProperty("items").EnumerateArray().ToList();

        Assert.Contains(items, i => i.GetProperty("id").GetString() == folder.GetProperty("id").GetString());
        Assert.DoesNotContain(items, i => i.GetProperty("name").GetString() == projectName);
    }

    // ── Ancestors (the breadcrumb's input) ───────────────────────────────────────────────────

    [Fact]
    public async Task ProjectDetail_CarriesTheAncestorChainRootFirst()
    {
        using var client = await AdminClient();
        var outer = await CreateFolderAsync(client, Unique("outer"));
        var inner = await CreateFolderAsync(client, Unique("inner"), ParentOf(outer));
        var project = await CreateProjectAsync(client, Unique("api"), ParentOf(inner));

        var detail = await GetProjectAsync(client, IdOf(project));
        string[] chain = detail.GetProperty("ancestors").EnumerateArray()
            .Select(a => a.GetProperty("id").GetString()!).ToArray();

        Assert.Equal([IdOf(outer), IdOf(inner)], chain);
    }

    [Fact]
    public async Task ProjectDetail_ForARootProject_CarriesAnEmptyAncestorChain()
    {
        using var client = await AdminClient();
        var project = await CreateProjectAsync(client, Unique("standalone"));

        var detail = await GetProjectAsync(client, IdOf(project));

        Assert.Empty(detail.GetProperty("ancestors").EnumerateArray());
    }

    // ── Relocate ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Patch_MovesAProjectIntoAFolderAndBackToTheRoot()
    {
        using var client = await AdminClient();
        var folder = await CreateFolderAsync(client, Unique("platform"));
        var project = await CreateProjectAsync(client, Unique("api"));

        var moved = await PatchAsync(client, IdOf(project), $$"""{"parentId":"{{IdOf(folder)}}"}""");
        Assert.Equal(HttpStatusCode.OK, moved.Status);
        Assert.Equal(IdOf(folder), moved.Body.GetProperty("parentId").GetString());

        // An explicit null is the only way back to the root — the whole reason parentId is
        // tri-state rather than a plain nullable.
        var home = await PatchAsync(client, IdOf(project), """{"parentId":null}""");
        Assert.Equal(HttpStatusCode.OK, home.Status);
        Assert.Equal(JsonValueKind.Null, home.Body.GetProperty("parentId").ValueKind);
        Assert.Empty((await GetProjectAsync(client, IdOf(project))).GetProperty("ancestors").EnumerateArray());
    }

    [Fact]
    public async Task Patch_IntoOwnDescendant_IsRefusedAndTheTreeIsUnchanged()
    {
        using var client = await AdminClient();
        var outer = await CreateFolderAsync(client, Unique("outer"));
        var inner = await CreateFolderAsync(client, Unique("inner"), ParentOf(outer));

        var result = await PatchAsync(client, IdOf(outer), $$"""{"parentId":"{{IdOf(inner)}}"}""");

        Assert.Equal(HttpStatusCode.UnprocessableEntity, result.Status);
        // The adversarial half: outer must still be at the root and inner still inside it. A
        // refusal that wrote anyway would leave both rows reachable only from each other.
        Assert.Equal(JsonValueKind.Null, (await GetProjectAsync(client, IdOf(outer))).GetProperty("parentId").ValueKind);
        Assert.Equal(IdOf(outer), (await GetProjectAsync(client, IdOf(inner))).GetProperty("parentId").GetString());
    }

    [Fact]
    public async Task Patch_IntoItself_IsRefused()
    {
        using var client = await AdminClient();
        var folder = await CreateFolderAsync(client, Unique("platform"));

        var result = await PatchAsync(client, IdOf(folder), $$"""{"parentId":"{{IdOf(folder)}}"}""");

        Assert.Equal(HttpStatusCode.UnprocessableEntity, result.Status);
        Assert.Equal(JsonValueKind.Null, (await GetProjectAsync(client, IdOf(folder))).GetProperty("parentId").ValueKind);
    }

    [Fact]
    public async Task Patch_IntoAPlainProject_IsRefused()
    {
        using var client = await AdminClient();
        var host = await CreateProjectAsync(client, Unique("host"));
        var project = await CreateProjectAsync(client, Unique("api"));

        var result = await PatchAsync(client, IdOf(project), $$"""{"parentId":"{{IdOf(host)}}"}""");

        Assert.Equal(HttpStatusCode.UnprocessableEntity, result.Status);
    }

    [Fact]
    public async Task Patch_IntoAnUnknownFolder_IsRefused()
    {
        using var client = await AdminClient();
        var project = await CreateProjectAsync(client, Unique("api"));

        var result = await PatchAsync(
            client, IdOf(project), $$"""{"parentId":"{{Guid.NewGuid():N}}"}""");

        Assert.Equal(HttpStatusCode.UnprocessableEntity, result.Status);
    }

    // ── Rename, and the leave-unchanged posture ──────────────────────────────────────────────

    [Fact]
    public async Task Patch_RenamingLeavesTheDescriptionAndFolderAlone()
    {
        using var client = await AdminClient();
        var folder = await CreateFolderAsync(client, Unique("platform"));
        string original = Unique("api");
        var project = await CreateProjectAsync(client, original, ParentOf(folder), description: "the edge api");

        string renamed = Unique("gateway");
        var result = await PatchAsync(client, IdOf(project), $$"""{"name":"{{renamed}}"}""");

        Assert.Equal(HttpStatusCode.OK, result.Status);
        var detail = await GetProjectAsync(client, IdOf(project));
        Assert.Equal(renamed, detail.GetProperty("name").GetString());
        // Both untouched fields, not just one: a PATCH that defaulted absent fields would blank
        // the description AND move the project to the root, and either alone reads as a bug in
        // the other feature.
        Assert.Equal("the edge api", detail.GetProperty("description").GetString());
        Assert.Equal(IdOf(folder), detail.GetProperty("parentId").GetString());
    }

    [Fact]
    public async Task Patch_ExplicitNullDescription_ClearsIt()
    {
        using var client = await AdminClient();
        var project = await CreateProjectAsync(client, Unique("api"), description: "to be cleared");

        var result = await PatchAsync(client, IdOf(project), """{"description":null}""");

        Assert.Equal(HttpStatusCode.OK, result.Status);
        var detail = await GetProjectAsync(client, IdOf(project));
        Assert.Equal(JsonValueKind.Null, detail.GetProperty("description").ValueKind);
    }

    [Fact]
    public async Task Patch_ToANameAlreadyTakenInTheTargetScope_Conflicts()
    {
        using var client = await AdminClient();
        string taken = Unique("billing");
        await CreateProjectAsync(client, taken);
        var project = await CreateProjectAsync(client, Unique("api"));

        var result = await PatchAsync(client, IdOf(project), $$"""{"name":"{{taken}}"}""");

        Assert.Equal(HttpStatusCode.Conflict, result.Status);
    }

    [Fact]
    public async Task Patch_BlankName_IsRefused()
    {
        using var client = await AdminClient();
        var project = await CreateProjectAsync(client, Unique("api"));

        var result = await PatchAsync(client, IdOf(project), """{"name":"   "}""");

        Assert.Equal(HttpStatusCode.UnprocessableEntity, result.Status);
    }

    [Fact]
    public async Task Patch_Kind_IsNotAnEditableField()
    {
        using var client = await AdminClient();
        var folder = await CreateFolderAsync(client, Unique("platform"));

        // Binding runs with JsonUnmappedMemberHandling.Disallow, so an unmodelled field is a 400
        // rather than a silently ignored key. Flipping kind would strand the subtree.
        var result = await PatchAsync(client, IdOf(folder), """{"kind":"project"}""");

        Assert.Equal(HttpStatusCode.BadRequest, result.Status);
        Assert.Equal("collection", (await GetProjectAsync(client, IdOf(folder))).GetProperty("kind").GetString());
    }

    // ── Rollups ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task FolderDetail_CarriesASubtreeRollup_AndAPlainProjectDoesNot()
    {
        using var client = await AdminClient();
        var folder = await CreateFolderAsync(client, Unique("platform"));
        var project = await CreateProjectAsync(client, Unique("api"), ParentOf(folder));

        var folderDetail = await GetProjectAsync(client, IdOf(folder));
        Assert.True(folderDetail.TryGetProperty("rollup", out var rollup));
        Assert.Equal(JsonValueKind.Object, rollup.ValueKind);
        Assert.Equal(1, rollup.GetProperty("projectCount").GetInt32());
        // Nothing uploaded yet, so the folder reports no verdict — never a pass.
        Assert.Equal(JsonValueKind.Null, rollup.GetProperty("policyStatus").ValueKind);

        // A plain project summarizes its own versions, which are already in the payload.
        var projectDetail = await GetProjectAsync(client, IdOf(project));
        Assert.True(projectDetail.TryGetProperty("rollup", out var none));
        Assert.Equal(JsonValueKind.Null, none.ValueKind);
    }

    [Fact]
    public async Task FolderRollup_CountsProjectsAtEveryDepth()
    {
        using var client = await AdminClient();
        var outer = await CreateFolderAsync(client, Unique("outer"));
        var inner = await CreateFolderAsync(client, Unique("inner"), ParentOf(outer));
        await CreateProjectAsync(client, Unique("deep"), ParentOf(inner));
        await CreateProjectAsync(client, Unique("direct"), ParentOf(outer));

        var detail = await GetProjectAsync(client, IdOf(outer));

        // Two projects, not three rows — the nested folder is structure, not inventory.
        Assert.Equal(2, detail.GetProperty("rollup").GetProperty("projectCount").GetInt32());
    }

    [Fact]
    public async Task EmptyFolder_ReportsZeroesRatherThanAnAbsentRollup()
    {
        using var client = await AdminClient();
        var folder = await CreateFolderAsync(client, Unique("empty"));

        var rollup = (await GetProjectAsync(client, IdOf(folder))).GetProperty("rollup");

        // Zeroes with a null verdict, distinct from a plain project's absent rollup.
        Assert.Equal(0, rollup.GetProperty("projectCount").GetInt32());
        Assert.Equal(0, rollup.GetProperty("componentCount").GetInt32());
        Assert.Equal(JsonValueKind.Null, rollup.GetProperty("policyStatus").ValueKind);
    }

    [Fact]
    public async Task ChildRows_CarryTheirOwnComponentCountAndSeverityCounts()
    {
        using var client = await AdminClient();
        var outer = await CreateFolderAsync(client, Unique("outer"));
        var inner = await CreateFolderAsync(client, Unique("inner"), ParentOf(outer));
        var direct = await CreateProjectAsync(client, Unique("direct"), ParentOf(outer));

        var children = (await GetProjectAsync(client, IdOf(outer)))
            .GetProperty("children").EnumerateArray().ToList();

        // Both shapes carry the fields, so the table renders one way at every level rather than
        // branching on kind and leaving a folder's cells blank.
        foreach (string id in new[] { IdOf(inner), IdOf(direct) })
        {
            var child = children.Single(c => c.GetProperty("id").GetString() == id);
            Assert.Equal(0, child.GetProperty("componentCount").GetInt32());
            Assert.Equal(0, child.GetProperty("severityCounts").GetProperty("critical").GetInt32());
        }
    }

    [Fact]
    public async Task FolderListRow_CarriesTheRollupNotTheFoldersOwnZeroes()
    {
        using var client = await AdminClient();
        string folderName = Unique("platform");
        var folder = await CreateFolderAsync(client, folderName);
        await CreateProjectAsync(client, Unique("api"), ParentOf(folder));

        using var resp = await client.GetAsync("/api/v1/projects?limit=200");
        resp.EnsureSuccessStatusCode();
        var row = (await ReadJsonAsync(resp)).GetProperty("items").EnumerateArray()
            .Single(i => i.GetProperty("id").GetString() == IdOf(folder));

        // The list row and the detail rollup are two code paths over the same fold; a divergence
        // between them is exactly what an operator would read as a bug in one of the two screens.
        Assert.Equal(0, row.GetProperty("componentCount").GetInt32());
        Assert.Equal(JsonValueKind.Null, row.GetProperty("policyStatus").ValueKind);
        Assert.Equal(JsonValueKind.Null, row.GetProperty("latestVersion").ValueKind);
    }

    // ── Tenancy ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Patch_AnotherOrgsProject_IsReportedAbsent()
    {
        using var client = await AdminClient();
        var db = _factory.Services.GetRequiredService<IMetadataStore>();

        string foreignOrg = "org-" + Guid.NewGuid().ToString("N")[..8];
        string foreignProject = Guid.NewGuid().ToString("N");
        await using (var conn = await db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
                new { id = foreignOrg, slug = foreignOrg });
            await conn.ExecuteAsync(
                """
                INSERT INTO projects (id, org_id, kind, name, classifier, created_at)
                VALUES (@id, @orgId, 'project', 'their-api', 'application',
                        strftime('%Y-%m-%dT%H:%M:%SZ','now'))
                """,
                new { id = foreignProject, orgId = foreignOrg });
        }

        var result = await PatchAsync(client, foreignProject, """{"name":"hijacked"}""");

        // 404, not 403 — ids stay unenumerable.
        Assert.Equal(HttpStatusCode.NotFound, result.Status);
        await using (var conn = await db.OpenAsync())
        {
            Assert.Equal("their-api", await conn.ExecuteScalarAsync<string>(
                "SELECT name FROM projects WHERE id = @id", new { id = foreignProject }));
        }
    }

    [Fact]
    public async Task ListCollections_DoesNotLeakAnotherOrgsFolders()
    {
        using var client = await AdminClient();
        var db = _factory.Services.GetRequiredService<IMetadataStore>();

        string foreignOrg = "org-" + Guid.NewGuid().ToString("N")[..8];
        string foreignFolder = Guid.NewGuid().ToString("N");
        await using (var conn = await db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
                new { id = foreignOrg, slug = foreignOrg });
            await conn.ExecuteAsync(
                """
                INSERT INTO projects (id, org_id, kind, name, classifier, created_at)
                VALUES (@id, @orgId, 'collection', 'their-folder', 'application',
                        strftime('%Y-%m-%dT%H:%M:%SZ','now'))
                """,
                new { id = foreignFolder, orgId = foreignOrg });
        }

        using var resp = await client.GetAsync("/api/v1/projects/collections");
        resp.EnsureSuccessStatusCode();
        var items = (await ReadJsonAsync(resp)).GetProperty("items").EnumerateArray().ToList();

        Assert.DoesNotContain(items, i => i.GetProperty("id").GetString() == foreignFolder);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────

    private async Task<HttpClient> AdminClient()
    {
        string jwt = await _factory.CreateAdminJwt();
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }

    // The default org is shared across every test in the class, and project names are unique per
    // parent scope — a fixed literal would make two tests collide on a 409 depending on order.
    private static string Unique(string stem) => $"{stem}-{Guid.NewGuid().ToString("N")[..8]}";

    private static string IdOf(JsonElement project) => project.GetProperty("id").GetString()!;

    private static string ParentOf(JsonElement folder) => IdOf(folder);

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage resp)
    {
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return doc.RootElement.Clone();
    }

    private static async Task<JsonElement> CreateFolderAsync(
        HttpClient client, string name, string? parentId = null)
    {
        using var resp = await client.PostAsJsonAsync("/api/v1/projects", new
        {
            name,
            kind = "collection",
            parentId,
        });
        resp.EnsureSuccessStatusCode();
        return await ReadJsonAsync(resp);
    }

    private static async Task<JsonElement> CreateProjectAsync(
        HttpClient client, string name, string? parentId = null, string? description = null)
    {
        using var resp = await client.PostAsJsonAsync("/api/v1/projects", new
        {
            name,
            kind = "project",
            parentId,
            description,
        });
        resp.EnsureSuccessStatusCode();
        return await ReadJsonAsync(resp);
    }

    private static async Task<JsonElement> GetProjectAsync(HttpClient client, string id)
    {
        using var resp = await client.GetAsync($"/api/v1/projects/{id}");
        resp.EnsureSuccessStatusCode();
        return await ReadJsonAsync(resp);
    }

    // Raw JSON rather than an anonymous object, because the whole point of several of these
    // cases is the difference between an ABSENT key and one explicitly set to null — a shape
    // a serialized C# object cannot express without extra converter ceremony.
    private static async Task<PatchResult> PatchAsync(HttpClient client, string id, string json)
    {
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var resp = await client.PatchAsync($"/api/v1/projects/{id}", content);
        string text = await resp.Content.ReadAsStringAsync();
        if (string.IsNullOrWhiteSpace(text))
        {
            return new PatchResult(resp.StatusCode, default);
        }

        using var doc = JsonDocument.Parse(text);
        return new PatchResult(resp.StatusCode, doc.RootElement.Clone());
    }

    private sealed record PatchResult(HttpStatusCode Status, JsonElement Body);
}
