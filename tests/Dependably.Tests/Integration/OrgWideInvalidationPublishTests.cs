using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// The host's org-wide invalidation wiring, end to end through the real composition root: each
/// management change that expires an org's derived caches hands one org-wide message to the bus,
/// and a message received from a peer clears the same reservation list the host's
/// <see cref="ReservedNamespaceService"/> reads.
/// </summary>
[Trait("Category", "Integration")]
public sealed class OrgWideInvalidationPublishTests : IAsyncLifetime
{
    private readonly RecordingMetadataInvalidationBus _bus = new();
    private readonly DependablyFactory _factory;

    public OrgWideInvalidationPublishTests()
    {
        _factory = new DependablyFactory
        {
            ServiceOverrides = services =>
            {
                services.RemoveAll<IMetadataInvalidationBus>();
                services.AddSingleton<IMetadataInvalidationBus>(_bus);
            },
        };
    }

    public async Task InitializeAsync() => await _factory.InitializeAsync();

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    [Fact]
    public async Task ProxySettingsPut_PublishesOneOrgWideInvalidation()
    {
        using var admin = await AdminClientAsync();
        string orgId = await DefaultOrgIdAsync();

        var put = await admin.PutAsJsonAsync("/api/v1/proxy-settings", new
        {
            proxyPassthroughEnabled = true,
            maxOsvScoreTolerance = 10.0,
        });
        put.EnsureSuccessStatusCode();

        Assert.Equal([MetadataInvalidation.ForOrg(orgId)], OrgWide());
    }

    [Fact]
    public async Task ReservationAddAndDelete_EachPublishOneOrgWideInvalidation()
    {
        using var admin = await AdminClientAsync();
        string orgId = await DefaultOrgIdAsync();

        var add = await admin.PostAsJsonAsync("/api/v1/reserved-namespaces",
            new { ecosystem = "maven", pattern = $"com.owi{Guid.NewGuid():N}"[..20] });
        Assert.Equal(HttpStatusCode.Created, add.StatusCode);
        Assert.Equal([MetadataInvalidation.ForOrg(orgId)], OrgWide());

        using var created = await JsonDocument.ParseAsync(await add.Content.ReadAsStreamAsync());
        string id = created.RootElement.GetProperty("id").GetString()!;
        var remove = await admin.DeleteAsync($"/api/v1/reserved-namespaces/{id}");
        Assert.Equal(HttpStatusCode.NoContent, remove.StatusCode);

        Assert.Equal([MetadataInvalidation.ForOrg(orgId), MetadataInvalidation.ForOrg(orgId)], OrgWide());
    }

    /// <summary>
    /// The licence-mode PUT is read by the serve gate and by every cached lookup verdict, so it
    /// invalidates the org like the proxy-settings PUT: one org-wide message, and the next
    /// lookup on this host reports the new mode rather than the outcome cached under the old one.
    /// </summary>
    [Fact]
    public async Task LicenseModePut_PublishesOneOrgWideInvalidation_AndTheNextLookupReportsTheNewMode()
    {
        using var admin = await AdminClientAsync();
        string orgId = await DefaultOrgIdAsync();
        string name = $"owi-lic-{Guid.NewGuid():N}"[..20];
        StubNpmPackument(name, "1.0.0");

        Assert.Equal("off", await LookupLicenseModeAsync(admin, name));

        var put = await admin.PutAsJsonAsync("/api/v1/license-policy/mode", new { mode = "warn" });
        put.EnsureSuccessStatusCode();

        Assert.Equal([MetadataInvalidation.ForOrg(orgId)], OrgWide());
        Assert.Equal("warn", await LookupLicenseModeAsync(admin, name));
    }

    /// <summary>
    /// The allowlist decides every block-mode lookup verdict, so each allowlist edit that commits
    /// expires the org's cached verdicts like the licence-mode PUT: one org-wide message per
    /// edit, and the next lookup reports the verdict the edited list produces.
    /// </summary>
    [Fact]
    public async Task LicenseAllowlistEdits_EachPublishOneOrgWideInvalidation_AndTheNextLookupReportsTheNewVerdict()
    {
        using var admin = await AdminClientAsync();
        string orgId = await DefaultOrgIdAsync();
        string name = $"owi-alw-{Guid.NewGuid():N}"[..20];
        StubNpmPackument(name, "1.0.0");
        await SetLicenseModeAsync(admin, "block");

        var refused = await LookupLicenseAsync(admin, name);
        Assert.False(refused.GetProperty("allowed").GetBoolean());
        Assert.Equal("MIT", refused.GetProperty("blockedLicense").GetString());

        int mark = OrgWide().Length;
        var add = await admin.PostAsJsonAsync("/api/v1/license-policy/allowlist", new { licenseSpdx = "MIT" });
        Assert.Equal(HttpStatusCode.Created, add.StatusCode);
        Assert.Equal([MetadataInvalidation.ForOrg(orgId)], OrgWideSince(mark));
        var allowed = await LookupLicenseAsync(admin, name);
        Assert.True(allowed.GetProperty("allowed").GetBoolean());
        Assert.Empty(allowed.GetProperty("conditionalLicenses").EnumerateArray());

        mark = OrgWide().Length;
        var patch = await admin.PatchAsJsonAsync("/api/v1/license-policy/allowlist/MIT",
            new { disposition = "conditional", note = "internal tools only" });
        Assert.Equal(HttpStatusCode.OK, patch.StatusCode);
        Assert.Equal([MetadataInvalidation.ForOrg(orgId)], OrgWideSince(mark));
        var conditional = await LookupLicenseAsync(admin, name);
        Assert.Equal(["MIT"], conditional.GetProperty("conditionalLicenses").EnumerateArray().Select(e => e.GetString()));

        mark = OrgWide().Length;
        var remove = await admin.DeleteAsync("/api/v1/license-policy/allowlist/MIT");
        Assert.Equal(HttpStatusCode.NoContent, remove.StatusCode);
        Assert.Equal([MetadataInvalidation.ForOrg(orgId)], OrgWideSince(mark));
        var refusedAgain = await LookupLicenseAsync(admin, name);
        Assert.False(refusedAgain.GetProperty("allowed").GetBoolean());
    }

    /// <summary>
    /// The blocklist refuses in any non-off mode, so adding a licence to it flips a cached
    /// "allowed" verdict and removing it flips it back; each committed edit, the note-only PATCH
    /// included, publishes one org-wide message.
    /// </summary>
    [Fact]
    public async Task LicenseBlocklistEdits_EachPublishOneOrgWideInvalidation_AndTheNextLookupReportsTheNewVerdict()
    {
        using var admin = await AdminClientAsync();
        string orgId = await DefaultOrgIdAsync();
        string name = $"owi-blk-{Guid.NewGuid():N}"[..20];
        StubNpmPackument(name, "1.0.0");
        await SetLicenseModeAsync(admin, "warn");

        Assert.True((await LookupLicenseAsync(admin, name)).GetProperty("allowed").GetBoolean());

        int mark = OrgWide().Length;
        var add = await admin.PostAsJsonAsync("/api/v1/license-policy/blocklist", new { licenseSpdx = "MIT" });
        Assert.Equal(HttpStatusCode.Created, add.StatusCode);
        Assert.Equal([MetadataInvalidation.ForOrg(orgId)], OrgWideSince(mark));
        var blocked = await LookupLicenseAsync(admin, name);
        Assert.False(blocked.GetProperty("allowed").GetBoolean());
        Assert.Equal("MIT", blocked.GetProperty("blockedLicense").GetString());

        mark = OrgWide().Length;
        var patch = await admin.PatchAsJsonAsync("/api/v1/license-policy/blocklist/MIT", new { note = "copyleft review" });
        Assert.Equal(HttpStatusCode.OK, patch.StatusCode);
        Assert.Equal([MetadataInvalidation.ForOrg(orgId)], OrgWideSince(mark));

        mark = OrgWide().Length;
        var remove = await admin.DeleteAsync("/api/v1/license-policy/blocklist/MIT");
        Assert.Equal(HttpStatusCode.NoContent, remove.StatusCode);
        Assert.Equal([MetadataInvalidation.ForOrg(orgId)], OrgWideSince(mark));
        Assert.True((await LookupLicenseAsync(admin, name)).GetProperty("allowed").GetBoolean());
    }

    /// <summary>
    /// A licence-list edit that writes nothing (a validation failure, a duplicate add, or a
    /// PATCH or DELETE naming an entry the org does not have) leaves every cached verdict true,
    /// so it publishes nothing.
    /// </summary>
    [Fact]
    public async Task RejectedLicenseListEdits_PublishNothing()
    {
        using var admin = await AdminClientAsync();
        string orgId = await DefaultOrgIdAsync();
        string tooLong = new('x', 2001);

        var seeded = await admin.PostAsJsonAsync("/api/v1/license-policy/allowlist", new { licenseSpdx = "MIT" });
        Assert.Equal(HttpStatusCode.Created, seeded.StatusCode);
        var seededBlock = await admin.PostAsJsonAsync("/api/v1/license-policy/blocklist", new { licenseSpdx = "GPL-3.0-only" });
        Assert.Equal(HttpStatusCode.Created, seededBlock.StatusCode);
        Assert.Equal([MetadataInvalidation.ForOrg(orgId), MetadataInvalidation.ForOrg(orgId)], OrgWide());

        HttpResponseMessage[] rejected =
        [
            await admin.PostAsJsonAsync("/api/v1/license-policy/allowlist", new { licenseSpdx = " " }),
            await admin.PostAsJsonAsync("/api/v1/license-policy/allowlist", new { licenseSpdx = "ISC", disposition = "maybe" }),
            await admin.PostAsJsonAsync("/api/v1/license-policy/allowlist", new { licenseSpdx = "MIT" }),
            await admin.PatchAsJsonAsync("/api/v1/license-policy/allowlist/MIT", new { disposition = "maybe" }),
            await admin.PatchAsJsonAsync("/api/v1/license-policy/allowlist/ISC", new { note = "absent" }),
            await admin.DeleteAsync("/api/v1/license-policy/allowlist/ISC"),
            await admin.PostAsJsonAsync("/api/v1/license-policy/blocklist", new { licenseSpdx = "" }),
            await admin.PostAsJsonAsync("/api/v1/license-policy/blocklist", new { licenseSpdx = "GPL-3.0-only" }),
            await admin.PatchAsJsonAsync("/api/v1/license-policy/blocklist/GPL-3.0-only", new { note = tooLong }),
            await admin.PatchAsJsonAsync("/api/v1/license-policy/blocklist/ISC", new { note = "absent" }),
            await admin.DeleteAsync("/api/v1/license-policy/blocklist/ISC"),
        ];

        Assert.All(rejected, r => Assert.False(r.IsSuccessStatusCode, $"{r.RequestMessage?.Method} {r.RequestMessage?.RequestUri} -> {(int)r.StatusCode}"));
        Assert.Equal([MetadataInvalidation.ForOrg(orgId), MetadataInvalidation.ForOrg(orgId)], OrgWide());
    }

    [Fact]
    public async Task ReceivedOrgWideMessage_ClearsTheReservationListTheHostReads()
    {
        _factory.CreateClient().Dispose();
        string orgId = await DefaultOrgIdAsync();
        var reserved = _factory.Services.GetRequiredService<ReservedNamespaceService>();
        var receiver = _factory.Services.GetRequiredService<MetadataInvalidationReceiver>();
        string pattern = $"com.peer{Guid.NewGuid():N}"[..20];

        Assert.False(await reserved.IsReservedAsync(orgId, "maven", pattern));

        // A peer replica committed the reservation; this host's list is still cached.
        await using (var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO reserved_namespace (id, org_id, ecosystem, pattern)
                VALUES (@id, @orgId, 'maven', @pattern)
                """,
                new { id = Guid.NewGuid().ToString("N"), orgId, pattern });
        }

        Assert.False(await reserved.IsReservedAsync(orgId, "maven", pattern));

        string payload = MetadataInvalidationCodec.Encode(MetadataInvalidation.ForOrg(orgId), origin: "peer-replica");
        Assert.True(receiver.Apply(payload, selfOrigin: "this-replica"));

        Assert.True(await reserved.IsReservedAsync(orgId, "maven", pattern));
    }

    private static async Task<string?> LookupLicenseModeAsync(HttpClient client, string name)
    {
        var resp = await client.GetAsync($"/api/v1/lookup?ecosystem=npm&name={name}&version=1.0.0");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("license").GetProperty("mode").GetString();
    }

    private static async Task<JsonElement> LookupLicenseAsync(HttpClient client, string name)
    {
        var resp = await client.GetAsync($"/api/v1/lookup?ecosystem=npm&name={name}&version=1.0.0");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("license").Clone();
    }

    private static async Task SetLicenseModeAsync(HttpClient client, string mode)
    {
        var put = await client.PutAsJsonAsync("/api/v1/license-policy/mode", new { mode });
        put.EnsureSuccessStatusCode();
    }

    private void StubNpmPackument(string name, string version)
    {
        string json = $$"""
            {
              "name": "{{name}}",
              "dist-tags": { "latest": "{{version}}" },
              "versions": {
                "{{version}}": { "name": "{{name}}", "version": "{{version}}", "license": "MIT" }
              },
              "time": { "{{version}}": "2024-03-01T00:00:00.000Z" }
            }
            """;
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(json));
    }

    private MetadataInvalidation[] OrgWide() =>
        _bus.Published.Where(i => i.Ecosystem == MetadataInvalidationEcosystems.Org).ToArray();

    private MetadataInvalidation[] OrgWideSince(int mark) => OrgWide()[mark..];

    private async Task<string> DefaultOrgIdAsync()
    {
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        return (await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
    }

    private async Task<HttpClient> AdminClientAsync()
    {
        string jwt = await _factory.CreateAdminJwt();
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }
}
