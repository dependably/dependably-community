using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Two claims a re-upload makes that the dedup/reapply fast paths do not automatically keep true.
///
/// <para><b>A reapply preserves the document's own provenance.</b> Re-uploading an SBOM re-runs the
/// version's already-stored VEX against the inventory it just wrote, so every SBOM upload touches
/// every VEX row's write path — but only the actor and instant the VEX document itself carried may
/// be recorded there. Stamping the SBOM uploader's identity instead would make the triage editor's
/// "set by {user}" line lie about who made the call, on every SBOM re-upload.</para>
///
/// <para><b>A dedup no-op still honours a requested promotion.</b> A byte-identical re-upload skips
/// the merge, but `isLatest=true` is a request the caller made about the version, not about the
/// document's bytes — dropping it silently would make the no-op response lie about what it did.</para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class SbomIngestReuploadTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory = new()
    {
        FrozenClock = TestTime.Frozen(),
    };

    public async Task InitializeAsync() => await _factory.InitializeAsync();

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    private static string Fixture(string name) =>
        Path.Combine(FixtureManifest.SbomFixturesRoot, name);

    private HttpClient Client(string jwt)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }

    private static HttpContent FileBody(string fixtureName)
    {
        var content = new ByteArrayContent(File.ReadAllBytes(Fixture(fixtureName)));
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        return content;
    }

    private static HttpContent JsonBody(string json)
    {
        var content = new StringContent(json, Encoding.UTF8);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        return content;
    }

    private async Task<T?> ScalarAsync<T>(string sql, object? parameters = null)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return await conn.ExecuteScalarAsync<T>(sql, parameters);
    }

    private async Task<string> VersionIdAsync(string project, string version)
    {
        return (await ScalarAsync<string>(
            """
            SELECT v.id FROM project_versions v
            JOIN projects p ON p.id = v.project_id
            WHERE p.name = @project AND v.version = @version
            """,
            new { project, version }))!;
    }

    // ── A reapply must not restamp VEX provenance to the SBOM re-uploader ──────────────────────

    private const string VexOne = """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "vulnerabilities": [
            { "id": "CVE-2100-4001", "affects": [ { "ref": "pkg:npm/minimist@1.2.5" } ],
              "analysis": { "state": "not_affected", "justification": "code_not_reachable" } }
          ]
        }
        """;

    [Fact]
    public async Task SbomReupload_ReappliesStoredVex_WithoutRestampingItsProvenance()
    {
        const string project = "reupload-vex-provenance";

        string ownerJwt = await _factory.CreateAdminJwt();
        using var owner = Client(ownerJwt);
        string ownerId = (await ScalarAsync<string>(
            "SELECT id FROM users WHERE tenant_id = (SELECT id FROM orgs WHERE slug = 'default') AND role = 'owner' LIMIT 1"))!;

        // The SBOM's uploader and the VEX's uploader are two different people, so a restamp is
        // observable as a changed actor, not just a changed timestamp.
        string vexUploaderId = await _factory.CreateUser("vex-author@example.test", "irrelevant-pw", "admin");
        string vexUploaderJwt = await _factory.CreateUserJwt(vexUploaderId, "admin");
        using var vexUploader = Client(vexUploaderJwt);

        Assert.Equal(HttpStatusCode.OK, (await owner.PutAsync(
            $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0&autoCreate=true",
            FileBody("cyclonedx-1.6-inventory.json"))).StatusCode);
        string versionId = await VersionIdAsync(project, "1.0.0");

        Assert.Equal(HttpStatusCode.OK, (await vexUploader.PutAsync(
            $"/api/v1/vex?projectName={project}&projectVersion=1.0.0", JsonBody(VexOne))).StatusCode);

        string? originalActor = await ScalarAsync<string>(
            "SELECT updated_by FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = 'CVE-2100-4001'",
            new { versionId });
        string? originalUpdatedAt = await ScalarAsync<string>(
            "SELECT updated_at FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = 'CVE-2100-4001'",
            new { versionId });
        Assert.Equal(vexUploaderId, originalActor);
        Assert.NotNull(originalUpdatedAt);

        // A different actor re-uploads the SBOM (different bytes, so the dedup no-op does not
        // short-circuit the merge) well after the VEX was recorded.
        _factory.FrozenClock!.Advance(TimeSpan.FromHours(6));
        Assert.Equal(HttpStatusCode.OK, (await owner.PutAsync(
            $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0",
            FileBody("cyclonedx-1.5-minimal.json"))).StatusCode);

        string? actorAfterReupload = await ScalarAsync<string>(
            "SELECT updated_by FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = 'CVE-2100-4001'",
            new { versionId });
        string? updatedAtAfterReupload = await ScalarAsync<string>(
            "SELECT updated_at FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = 'CVE-2100-4001'",
            new { versionId });

        // The VEX statement itself was never re-uploaded, so its provenance must read exactly as
        // it did the moment its own uploader wrote it — never the SBOM re-uploader, never a later
        // instant.
        Assert.Equal(originalActor, actorAfterReupload);
        Assert.Equal(originalUpdatedAt, updatedAtAfterReupload);
        Assert.NotEqual(ownerId, actorAfterReupload);
    }

    // ── A dedup no-op still honours a requested isLatest promotion ─────────────────────────────

    [Fact]
    public async Task SbomDedupNoOp_WithIsLatestTrue_StillPromotesTheVersion()
    {
        const string project = "reupload-dedup-promote";
        using var client = Client(await _factory.CreateAdminJwt());

        string v1Bytes = "cyclonedx-1.6-inventory.json";
        string v2Bytes = "cyclonedx-1.5-minimal.json";

        Assert.Equal(HttpStatusCode.OK, (await client.PutAsync(
            $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0&autoCreate=true&isLatest=true",
            FileBody(v1Bytes))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.PutAsync(
            $"/api/v1/sbom?projectName={project}&projectVersion=2.0.0&autoCreate=true&isLatest=true",
            FileBody(v2Bytes))).StatusCode);

        string v1Id = await VersionIdAsync(project, "1.0.0");
        string v2Id = await VersionIdAsync(project, "2.0.0");
        Assert.Equal(0L, await ScalarAsync<long>(
            "SELECT is_latest FROM project_versions WHERE id = @id", new { id = v1Id }));
        Assert.Equal(1L, await ScalarAsync<long>(
            "SELECT is_latest FROM project_versions WHERE id = @id", new { id = v2Id }));

        // A byte-identical re-upload of v1 asking to be promoted: the dedup arm must not silently
        // drop the promotion just because the merge itself was a no-op.
        var dedupResponse = await client.PutAsync(
            $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0&isLatest=true",
            FileBody(v1Bytes));
        Assert.Equal(HttpStatusCode.OK, dedupResponse.StatusCode);
        var body = JsonDocument.Parse(await dedupResponse.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(0, body.GetProperty("components").GetProperty("added").GetInt32());

        Assert.Equal(1L, await ScalarAsync<long>(
            "SELECT is_latest FROM project_versions WHERE id = @id", new { id = v1Id }));
        Assert.Equal(0L, await ScalarAsync<long>(
            "SELECT is_latest FROM project_versions WHERE id = @id", new { id = v2Id }));
    }
}
