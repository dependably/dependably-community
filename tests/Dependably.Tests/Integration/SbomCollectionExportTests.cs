using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// The collection-scoped CycloneDX export: one document covering every project beneath a folder.
///
/// <para>Three properties carry the design and each fails silently if broken, which is why they are
/// asserted on the document rather than on the response code: bom-refs must be unique across the
/// whole document (the same library in two projects would otherwise collide, producing an INVALID
/// BOM that most consumers accept and then mis-resolve); the same library must appear once per
/// project rather than being merged (VEX analysis is per-project, so a merged entry would have to
/// hold two contradictory truths); and the document must state which version of each project it
/// selected, because one that does not is read as exhaustive.</para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class SbomCollectionExportTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public SbomCollectionExportTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Export_NestsEveryProjectAndKeepsBomRefsUnique()
    {
        using var client = await AdminClient();
        string folder = await CreateFolderAsync(client, Unique("platform"));
        string inner = await CreateFolderAsync(client, Unique("payments"), folder);
        string first = Unique("ledger");
        string second = Unique("billing");
        await UploadAsync(client, first, "1.0.0", folder);
        await UploadAsync(client, second, "2.0.0", inner);

        var doc = await ExportAsync(client, folder, "inventory");

        var projects = doc.GetProperty("components").EnumerateArray().ToList();
        // Both, including the one two levels down — the walk is the whole subtree, not the
        // direct children.
        Assert.Equal(2, projects.Count);
        Assert.Contains(projects, p => p.GetProperty("name").GetString() == first);
        Assert.Contains(projects, p => p.GetProperty("name").GetString() == second);

        // Each project carries its own libraries nested, which is the only thing this document
        // adds over two separate per-project exports.
        foreach (var project in projects)
        {
            Assert.True(project.TryGetProperty("components", out var nested));
            Assert.NotEmpty(nested.EnumerateArray());
        }

        var refs = AllBomRefs(doc).ToList();
        Assert.Equal(refs.Count, refs.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public async Task Export_KeepsTheSameLibraryOncePerProject_WithTheBarePurlIntact()
    {
        using var client = await AdminClient();
        string folder = await CreateFolderAsync(client, Unique("platform"));
        string a = Unique("alpha");
        string b = Unique("beta");
        // The same fixture twice, so every component is shared between the two projects — the
        // case a naive merge would collapse.
        await UploadAsync(client, a, "1.0.0", folder);
        await UploadAsync(client, b, "1.0.0", folder);

        var doc = await ExportAsync(client, folder, "inventory");
        var purls = doc.GetProperty("components").EnumerateArray()
            .SelectMany(p => p.GetProperty("components").EnumerateArray())
            .Select(c => c.TryGetProperty("purl", out var purl) ? purl.GetString() : null)
            .Where(p => p is not null)
            .ToList();

        // Deliberately NOT deduplicated: one entry per project that ships it.
        var duplicated = purls.GroupBy(p => p, StringComparer.Ordinal).Where(g => g.Count() > 1).ToList();
        Assert.NotEmpty(duplicated);
        Assert.All(duplicated, g => Assert.Equal(2, g.Count()));

        // And the purl FIELD is the bare purl a consumer matches on — only the bom-ref is
        // namespaced. Prefixing the purl would break every downstream lookup.
        Assert.All(purls, p => Assert.DoesNotContain("collection:", p!, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Export_DeclaresItsSelectionAndListsProjectsWithNoSbom()
    {
        using var client = await AdminClient();
        string folder = await CreateFolderAsync(client, Unique("platform"));
        string uploaded = Unique("has-sbom");
        string empty = Unique("no-sbom");
        await UploadAsync(client, uploaded, "1.0.0", folder);
        await CreateProjectAsync(client, empty, folder);

        var doc = await ExportAsync(client, folder, "inventory");
        var props = doc.GetProperty("metadata").GetProperty("properties").EnumerateArray()
            .ToDictionary(p => p.GetProperty("name").GetString()!, p => p.GetProperty("value").GetString()!);

        // A document that does not say what it chose is read as exhaustive.
        Assert.Equal("collection", props["dependably:aggregate"]);
        Assert.Equal("latest-per-project", props["dependably:selection"]);
        Assert.Equal("2", props["dependably:projectCount"]);
        Assert.Equal("1", props["dependably:projectsWithoutSbom"]);

        // The empty project is present and marked, not dropped — dropping it is what would make
        // the count above a lie.
        var emptyEntry = doc.GetProperty("components").EnumerateArray()
            .Single(c => c.GetProperty("name").GetString() == empty);
        Assert.False(emptyEntry.TryGetProperty("components", out _));
        Assert.Contains(
            emptyEntry.GetProperty("properties").EnumerateArray(),
            p => p.GetProperty("name").GetString() == "dependably:noSbom");
    }

    /// <summary>
    /// GitLab issue #610: document-level scan coverage is a genuine aggregate across the whole
    /// subtree, not a per-project figure — <see cref="SbomExportService"/>'s <c>CoverageAccumulator</c>
    /// is the code path this pins, distinct from the single-project producer's own coverage test.
    /// </summary>
    [Fact]
    public async Task Export_AggregatesScanCoverageAcrossTheWholeSubtree()
    {
        using var client = await AdminClient();
        string folder = await CreateFolderAsync(client, Unique("platform"));
        string scanned = Unique("scanned");
        string unscanned = Unique("unscanned");
        await UploadAsync(client, scanned, "1.0.0", folder);
        await UploadAsync(client, unscanned, "1.0.0", folder);

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();

        string scannedProjectId = await FindProjectIdAsync(client, scanned);
        int stamped = await conn.ExecuteAsync(
            """
            UPDATE sbom_components SET vuln_checked_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
            WHERE project_version_id IN (
                SELECT id FROM project_versions WHERE project_id = @scannedProjectId)
            """,
            new { scannedProjectId });
        Assert.True(stamped > 0, "the fixture must contribute at least one component to stamp");

        var doc = await ExportAsync(client, folder, "inventory");
        var props = doc.GetProperty("metadata").GetProperty("properties").EnumerateArray()
            .ToDictionary(p => p.GetProperty("name").GetString()!, p => p.GetProperty("value").GetString()!);

        int totalComponents = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*) FROM sbom_components sc
            JOIN project_versions pv ON pv.id = sc.project_version_id
            JOIN projects p ON p.id = pv.project_id
            WHERE p.name IN (@scanned, @unscanned)
            """,
            new { scanned, unscanned });

        Assert.Equal(stamped.ToString(), props["dependably:scanned-count"]);
        Assert.Equal((totalComponents - stamped).ToString(), props["dependably:unscanned-count"]);
        Assert.Equal("0", props["dependably:unscannable-count"]);
        Assert.True(props.ContainsKey("dependably:last-scan-at"));
        // Neither project's own version turned the operator's tracker connection on — this
        // is a document-level, deployment-wide fact, not derived from anything just uploaded.
        Assert.Equal("false", props["dependably:tracker-configured"]);
    }

    [Fact]
    public async Task Export_MetadataComponentIsTheCollectionAndCarriesNoVersion()
    {
        using var client = await AdminClient();
        string name = Unique("platform");
        string folder = await CreateFolderAsync(client, name);

        var root = (await ExportAsync(client, folder, "inventory"))
            .GetProperty("metadata").GetProperty("component");

        Assert.Equal(name, root.GetProperty("name").GetString());
        // A collection holds no versions, and CycloneDX permits omitting it. Inventing one would
        // be the document asserting something the model does not hold.
        Assert.False(root.TryGetProperty("version", out _));
    }

    [Fact]
    public async Task Export_EmptyFolder_IsAValidDocumentWithNoProjects()
    {
        using var client = await AdminClient();
        string folder = await CreateFolderAsync(client, Unique("empty"));

        var doc = await ExportAsync(client, folder, "inventory");

        Assert.Empty(doc.GetProperty("components").EnumerateArray());
        Assert.Equal("CycloneDX", doc.GetProperty("bomFormat").GetString());
    }

    [Fact]
    public async Task Export_OnAPlainProject_Is404RatherThanItsLatestVersion()
    {
        using var client = await AdminClient();
        string name = Unique("standalone");
        await UploadAsync(client, name, "1.0.0", parentId: null);
        string projectId = await FindProjectIdAsync(client, name);

        using var resp = await client.GetAsync($"/api/v1/projects/{projectId}/export/sbom");

        // Answering a different question from the one asked is how a caller ships the wrong
        // document; the project already has a version-scoped export.
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task Export_AnUnknownVariant_IsRefused()
    {
        using var client = await AdminClient();
        string folder = await CreateFolderAsync(client, Unique("platform"));

        using var resp = await client.GetAsync($"/api/v1/projects/{folder}/export/sbom?variant=nonsense");

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task Export_Vdr_AffectsRefsResolveToComponentsInTheSameProject()
    {
        using var client = await AdminClient();
        string folder = await CreateFolderAsync(client, Unique("platform"));
        await UploadAsync(client, Unique("alpha"), "1.0.0", folder);
        await UploadAsync(client, Unique("beta"), "1.0.0", folder);

        var doc = await ExportAsync(client, folder, "vdr");
        Assert.True(doc.TryGetProperty("vulnerabilities", out var vulns));

        var refs = new HashSet<string>(AllBomRefs(doc), StringComparer.Ordinal);
        foreach (var affected in vulns.EnumerateArray()
                     .SelectMany(v => v.GetProperty("affects").EnumerateArray()))
        {
            // A bare purl here would resolve to whichever project's copy came first, silently
            // attributing one project's finding to another.
            Assert.Contains(affected.GetProperty("ref").GetString()!, refs);
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────

    private static string Unique(string stem) => $"{stem}-{Guid.NewGuid().ToString("N")[..8]}";

    /// <summary>Every bom-ref the document declares, at any nesting depth.</summary>
    private static IEnumerable<string> AllBomRefs(JsonElement doc)
    {
        var root = doc.GetProperty("metadata").GetProperty("component");
        yield return root.GetProperty("bom-ref").GetString()!;

        foreach (var project in doc.GetProperty("components").EnumerateArray())
        {
            yield return project.GetProperty("bom-ref").GetString()!;
            if (!project.TryGetProperty("components", out var nested))
            {
                continue;
            }

            foreach (var component in nested.EnumerateArray())
            {
                yield return component.GetProperty("bom-ref").GetString()!;
            }
        }
    }

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

    private static async Task CreateProjectAsync(HttpClient client, string name, string parentId)
    {
        using var resp = await client.PostAsJsonAsync("/api/v1/projects", new { name, kind = "project", parentId });
        resp.EnsureSuccessStatusCode();
    }

    private static async Task<string> FindProjectIdAsync(HttpClient client, string name)
    {
        using var resp = await client.GetAsync($"/api/v1/projects?q={Uri.EscapeDataString(name)}");
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("items").EnumerateArray()
            .Single(i => i.GetProperty("name").GetString() == name)
            .GetProperty("id").GetString()!;
    }

    private static async Task UploadAsync(HttpClient client, string projectName, string version, string? parentId)
    {
        string body = await File.ReadAllTextAsync(
            Path.Combine(FixtureManifest.SbomFixturesRoot, "cyclonedx-1.6-inventory.json"));
        string q = $"projectName={Uri.EscapeDataString(projectName)}&projectVersion={version}" +
                   "&autoCreate=true&isLatest=true" +
                   (parentId is null ? "" : $"&parentId={Uri.EscapeDataString(parentId)}");
        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        using var resp = await client.PutAsync($"/api/v1/sbom?{q}", content);
        resp.EnsureSuccessStatusCode();
    }

    private static async Task<JsonElement> ExportAsync(HttpClient client, string collectionId, string variant)
    {
        using var resp = await client.GetAsync($"/api/v1/projects/{collectionId}/export/sbom?variant={variant}");
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return doc.RootElement.Clone();
    }
}
