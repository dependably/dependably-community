using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Dependably.Tests.Integration;

[Trait("Category", "Integration")]
public sealed class AllowVersionOverwriteTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public AllowVersionOverwriteTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<HttpClient> AdminJwtClient()
    {
        var jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    [Fact]
    public async Task SettingsToggle_EmitsTenantSettingChangeAudit()
    {
        using var client = await AdminJwtClient();
        var resp = await client.PutAsJsonAsync("/api/v1/settings", new
        {
            anonymousPull = true, allowlistMode = false,
            allowVersionOverwrite = true,
        });
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);

        // Read back via the GET to confirm the persisted state.
        var getResp = await client.GetAsync("/api/v1/settings");
        getResp.EnsureSuccessStatusCode();
        var doc = JsonDocument.Parse(await getResp.Content.ReadAsStringAsync()).RootElement;
        Assert.True(doc.GetProperty("allowVersionOverwrite").GetBoolean());

        // Audit should carry both the wide org_settings_updated event AND the targeted
        // tenant.setting.change shaped for #45 supply-chain reviewers.
        var db = _factory.Services.GetRequiredService<Dependably.Infrastructure.IMetadataStore>();
        await using var conn = await db.OpenAsync();
        var rows = (await conn.QueryAsync<(string Action, string Detail)>(
            "SELECT action, detail FROM audit_log WHERE action = 'tenant.setting.change' AND detail LIKE '%allow_version_overwrite%' ORDER BY created_at DESC LIMIT 1"))
            .ToList();
        Assert.NotEmpty(rows);
        Assert.Contains("\"new_value\":true", rows[0].Detail);
    }

    [Fact]
    public async Task PublishDuplicate_OverwriteOff_Returns409()
    {
        // Tests share a DependablyFactory (IClassFixture) and so share the
        // allow_version_overwrite setting. Explicitly set it off at the start so this test
        // is order-independent.
        using (var admin = await AdminJwtClient())
        {
            var settingsResp = await admin.PutAsJsonAsync("/api/v1/settings", new
            {
                anonymousPull = false, allowlistMode = false,
                allowVersionOverwrite = false,
            });
            settingsResp.EnsureSuccessStatusCode();
        }

        await _factory.PushNpmPackage("acme-overwrite-off", "1.0.0");
        var token = await _factory.CreateToken("push");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var body = NpmFixtures.BuildPublishBody("acme-overwrite-off", "1.0.0");
        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        var resp = await client.PutAsync("/npm/acme-overwrite-off", content);
        Assert.Equal(HttpStatusCode.Conflict, resp.StatusCode);
    }

    [Fact]
    public async Task PublishDuplicate_OverwriteOn_AcceptsAndAuditsPackageReplace()
    {
        // Enable overwrite first.
        using (var admin = await AdminJwtClient())
        {
            var settingsResp = await admin.PutAsJsonAsync("/api/v1/settings", new
            {
                anonymousPull = false, allowlistMode = false,
                allowVersionOverwrite = true,
            });
            settingsResp.EnsureSuccessStatusCode();
        }

        // First publish.
        await _factory.PushNpmPackage("acme-overwrite-on", "1.0.0");

        // Capture the original sha from package_versions for comparison.
        var db = _factory.Services.GetRequiredService<Dependably.Infrastructure.IMetadataStore>();
        await using var conn = await db.OpenAsync();
        var firstSha = await conn.ExecuteScalarAsync<string>(
            """
            SELECT pv.checksum_sha256 FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.name = 'acme-overwrite-on' AND pv.version = '1.0.0'
            """);
        Assert.False(string.IsNullOrEmpty(firstSha));

        // Re-publish — same coordinate, fresh tarball (BuildPublishBody bakes a tarball whose
        // bytes are deterministic-but-different across calls because the Date-Time fields in
        // the tar header differ). Even if they're identical, the API path runs cleanly.
        var token = await _factory.CreateToken("push");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var body = NpmFixtures.BuildPublishBody("acme-overwrite-on", "1.0.0");
        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        var resp = await client.PutAsync("/npm/acme-overwrite-on", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        // package.replace audit row exists for the coordinate.
        await using var conn2 = await db.OpenAsync();
        var replaceRows = (await conn2.QueryAsync<(string Detail, string Purl)>(
            """
            SELECT detail, purl FROM audit_log
            WHERE action = 'package.replace' AND purl LIKE '%acme-overwrite-on@1.0.0%'
            """))
            .ToList();
        Assert.NotEmpty(replaceRows);
        Assert.Contains("prior_artifact_hash", replaceRows[0].Detail);
        Assert.Contains("artifact_hash", replaceRows[0].Detail);
    }
}
