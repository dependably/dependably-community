using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Uploading into a folder, and the ambiguity folders introduced.
///
/// <para>A project name is unique within its PARENT SCOPE, not across the org — two folders may
/// each hold an <c>api</c>. Every upload surface resolves its target by name, so the moment
/// collections became reachable from the product that resolution stopped identifying one row. The
/// cases below pin both halves: <c>parentId</c> names a scope unambiguously, and a name that still
/// matches more than one project is reported rather than guessed at.</para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class SbomUploadIntoFolderTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public SbomUploadIntoFolderTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task SbomUpload_WithParentId_CreatesTheProjectInsideThatFolder()
    {
        using var client = await AdminClient();
        string outer = await CreateFolderAsync(client, Unique("outer"));
        string inner = await CreateFolderAsync(client, Unique("inner"), outer);
        string name = Unique("api");

        var resp = await UploadSbomAsync(client, name, "1.0.0", parentId: inner);
        Assert.Equal(HttpStatusCode.OK, resp.Status);

        string projectId = resp.Body.GetProperty("project").GetProperty("id").GetString()!;
        var detail = await GetProjectAsync(client, projectId);
        Assert.Equal(inner, detail.GetProperty("parentId").GetString());
        // Two levels down, which is the case parentName cannot reach at all.
        Assert.Equal(2, detail.GetProperty("ancestors").GetArrayLength());
    }

    [Fact]
    public async Task SbomUpload_WithoutParentId_StillLandsAtTheRoot()
    {
        using var client = await AdminClient();
        string name = Unique("rootward");

        // The adversarial twin of the case above: the CI shape that names no parent must keep
        // behaving exactly as it did, or every existing pipeline quietly changes where it files.
        var resp = await UploadSbomAsync(client, name, "1.0.0", parentId: null);
        Assert.Equal(HttpStatusCode.OK, resp.Status);

        string projectId = resp.Body.GetProperty("project").GetProperty("id").GetString()!;
        Assert.Equal(
            JsonValueKind.Null,
            (await GetProjectAsync(client, projectId)).GetProperty("parentId").ValueKind);
    }

    [Fact]
    public async Task SbomUpload_SameNameInTwoFolders_AreTwoDistinctProjects()
    {
        using var client = await AdminClient();
        string left = await CreateFolderAsync(client, Unique("left"));
        string right = await CreateFolderAsync(client, Unique("right"));
        string shared = Unique("api");

        var first = await UploadSbomAsync(client, shared, "1.0.0", parentId: left);
        var second = await UploadSbomAsync(client, shared, "1.0.0", parentId: right);
        Assert.Equal(HttpStatusCode.OK, first.Status);
        Assert.Equal(HttpStatusCode.OK, second.Status);

        string firstId = first.Body.GetProperty("project").GetProperty("id").GetString()!;
        string secondId = second.Body.GetProperty("project").GetProperty("id").GetString()!;
        // Not a re-upload of the first: each folder is its own name namespace, and collapsing them
        // would merge one team's inventory into another's under a shared name like "api".
        Assert.NotEqual(firstId, secondId);
    }

    [Fact]
    public async Task VexUpload_AgainstAnAmbiguousName_IsReportedRatherThanGuessed()
    {
        using var client = await AdminClient();
        string left = await CreateFolderAsync(client, Unique("left"));
        string right = await CreateFolderAsync(client, Unique("right"));
        string shared = Unique("api");
        await UploadSbomAsync(client, shared, "1.0.0", parentId: left);
        await UploadSbomAsync(client, shared, "1.0.0", parentId: right);

        // Before folders this could not happen, so the resolver read a single row and threw on the
        // second — a 500. It answers 409 and names the field that resolves it.
        var ambiguous = await UploadVexAsync(client, shared, "1.0.0", parentId: null);
        Assert.Equal(HttpStatusCode.Conflict, ambiguous.Status);
        Assert.Contains("parentId", ambiguous.Body.GetProperty("detail").GetString()!, StringComparison.Ordinal);

        // And the disambiguated form goes through.
        var scoped = await UploadVexAsync(client, shared, "1.0.0", parentId: right);
        Assert.Equal(HttpStatusCode.OK, scoped.Status);
    }

    [Fact]
    public async Task VexUpload_AgainstAUniqueNestedName_NeedsNoParentId()
    {
        using var client = await AdminClient();
        string folder = await CreateFolderAsync(client, Unique("solo"));
        string name = Unique("api");
        await UploadSbomAsync(client, name, "1.0.0", parentId: folder);

        // A null parentId means "the caller did not say", not "the root scope" — narrowing it to
        // the root would stop resolving every project anyone had filed into a folder.
        var resp = await UploadVexAsync(client, name, "1.0.0", parentId: null);
        Assert.Equal(HttpStatusCode.OK, resp.Status);
    }

    [Fact]
    public async Task SbomUpload_WithAnUnknownParentId_IsRefusedAndCreatesNothing()
    {
        using var client = await AdminClient();
        string name = Unique("api");

        var resp = await UploadSbomAsync(client, name, "1.0.0", parentId: Guid.NewGuid().ToString("N"));

        // 404, matching this surface's existing answer for a parent it cannot resolve and keeping
        // a folder id belonging to another tenant unenumerable.
        Assert.Equal(HttpStatusCode.NotFound, resp.Status);

        // The half that matters: it did NOT quietly fall back to the root. An upload that lands
        // somewhere other than where the caller said is worse than one that fails, and the status
        // code alone cannot tell those apart.
        using var listed = await client.GetAsync($"/api/v1/projects?q={Uri.EscapeDataString(name)}");
        listed.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await listed.Content.ReadAsStringAsync());
        Assert.Empty(doc.RootElement.GetProperty("items").EnumerateArray());
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────

    private static string Unique(string stem) => $"{stem}-{Guid.NewGuid().ToString("N")[..8]}";

    private async Task<HttpClient> AdminClient()
    {
        string jwt = await _factory.CreateAdminJwt();
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }

    private static async Task<string> CreateFolderAsync(HttpClient client, string name, string? parentId = null)
    {
        using var resp = await client.PostAsJsonAsync("/api/v1/projects", new { name, kind = "collection", parentId });
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("id").GetString()!;
    }

    private static async Task<JsonElement> GetProjectAsync(HttpClient client, string id)
    {
        using var resp = await client.GetAsync($"/api/v1/projects/{id}");
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return doc.RootElement.Clone();
    }

    private static Task<UploadResult> UploadSbomAsync(
        HttpClient client, string projectName, string version, string? parentId)
    {
        string q = $"projectName={Uri.EscapeDataString(projectName)}&projectVersion={version}" +
                   "&autoCreate=true&isLatest=true" +
                   (parentId is null ? "" : $"&parentId={Uri.EscapeDataString(parentId)}");
        return PutAsync(client, $"/api/v1/sbom?{q}", "cyclonedx-1.6-inventory.json");
    }

    private static Task<UploadResult> UploadVexAsync(
        HttpClient client, string projectName, string version, string? parentId)
    {
        string q = $"projectName={Uri.EscapeDataString(projectName)}&projectVersion={version}" +
                   (parentId is null ? "" : $"&parentId={Uri.EscapeDataString(parentId)}");
        return PutAsync(client, $"/api/v1/vex?{q}", "cyclonedx-1.6-vex.json");
    }

    /// <summary>Named rather than a tuple so `var` locals do not trip the deconstruction rule.</summary>
    private sealed record UploadResult(HttpStatusCode Status, JsonElement Body);

    private static async Task<UploadResult> PutAsync(
        HttpClient client, string path, string fixture)
    {
        string body = await File.ReadAllTextAsync(
            Path.Combine(FixtureManifest.SbomFixturesRoot, fixture));
        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        using var resp = await client.PutAsync(path, content);
        string text = await resp.Content.ReadAsStringAsync();
        if (string.IsNullOrWhiteSpace(text))
        {
            return new UploadResult(resp.StatusCode, default);
        }

        using var doc = JsonDocument.Parse(text);
        return new UploadResult(resp.StatusCode, doc.RootElement.Clone());
    }
}
