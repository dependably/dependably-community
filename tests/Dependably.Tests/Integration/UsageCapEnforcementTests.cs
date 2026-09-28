using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Usage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end enforcement of per-meter usage caps through the full pipeline (single mode, the one
/// default org). Each threshold is paired with its active twin one unit below it, so a gate that
/// refuses nothing or everything fails: uploads are refused at 100 % of each capped meter and
/// admitted below it; downloads are throttled at 110 % of a capped egress meter and not below it;
/// an org with no caps is never enforced; DELETE, npm's unpublish prune PUT, and downloads stay
/// admitted at the cap; and the
/// hourly rollup, not only a direct recompute, trips the posture.
/// </summary>
[Trait("Category", "Integration")]
public sealed class UsageCapEnforcementTests : IAsyncLifetime
{
    private const string InfoUrl = "https://billing.example.com/usage";

    // A tight throttled budget with no queue, so a short burst from a throttled org meets a 429
    // well inside one window.
    private readonly DependablyFactory _factory = new()
    {
        ExtraSettings = new Dictionary<string, string?>
        {
            ["TENANT_THROTTLED_RATE_LIMIT_PERMITS"] = "2",
            ["TENANT_THROTTLED_RATE_LIMIT_QUEUE"] = "0",
            ["USAGE_CAP_INFO_URL"] = InfoUrl,
        },
    };

    public async Task InitializeAsync() => await _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    private IMetadataStore Db => _factory.Services.GetRequiredService<IMetadataStore>();
    private UsagePostureRepository Postures => _factory.Services.GetRequiredService<UsagePostureRepository>();

    private async Task<string> DefaultOrgIdAsync()
    {
        await using var conn = await Db.OpenAsync();
        return await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default'")
            ?? throw new InvalidOperationException("default org missing");
    }

    // Seeded usage sits in the first hour of the current UTC month: inside the month-to-date sum,
    // and away from the current hour, where this test's own requests land metered events that a
    // scheduled hourly rollup would recompute the bucket from.
    private string MonthStartBucket()
    {
        var now = _factory.Services.GetRequiredService<TimeProvider>().GetUtcNow();
        return new DateTimeOffset(now.Year, now.Month, 1, 0, 0, 0, TimeSpan.Zero).ToUtcIso();
    }

    private string Today() =>
        _factory.Services.GetRequiredService<TimeProvider>().GetUtcNow().ToUtcIso()[..10];

    private async Task SetEgressAsync(string orgId, string meter, long quantity)
    {
        await using var conn = await Db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO usage_hourly (org_id, meter, bucket, quantity, redirect_quantity, request_count, computed_at)
            VALUES (@orgId, @meter, @bucket, @quantity, 0, 1, @bucket)
            ON CONFLICT (org_id, meter, bucket) DO UPDATE SET quantity = excluded.quantity
            """,
            new { orgId, meter, bucket = MonthStartBucket(), quantity });
    }

    private async Task SetSnapshotAsync(string orgId, long billable, long hostedVersions, long ociManifests)
    {
        string day = Today();
        await using var conn = await Db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO storage_snapshot
                (org_id, day_utc, hosted_bytes, oci_uploaded_bytes, cache_attributed_bytes, billable_bytes,
                 hosted_version_count, oci_manifest_count, oci_blob_count, cache_entry_count, db_row_count, captured_at)
            VALUES (@orgId, @day, 0, 0, 0, @billable, @hostedVersions, @ociManifests, 0, 0, 0, @day || 'T00:05:00Z')
            ON CONFLICT (org_id, day_utc) DO UPDATE SET
                billable_bytes = excluded.billable_bytes,
                hosted_version_count = excluded.hosted_version_count,
                oci_manifest_count = excluded.oci_manifest_count
            """,
            new { orgId, day, billable, hostedVersions, ociManifests });
    }

    private async Task<string> CapAsync(string orgId, string meter, long? cap)
    {
        await Postures.SetCapsAsync(orgId, new Dictionary<string, long?> { [meter] = cap });
        return await Postures.RecomputeForOrgAsync(orgId);
    }

    private async Task<HttpResponseMessage> PublishNpmAsync(string token)
    {
        string name = $"cap-{Guid.NewGuid():N}"[..20];
        using var client = _factory.CreateClientWithBearer(token);
        return await client.PutAsync(
            $"/npm/{name}",
            new StringContent(NpmFixtures.BuildPublishBody(name, "1.0.0"), Encoding.UTF8, "application/json"));
    }

    private static ByteArrayContent FilePart(byte[] bytes)
    {
        var part = new ByteArrayContent(bytes);
        part.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        return part;
    }

    private async Task<HttpResponseMessage> ImportNpmAsync(string name)
    {
        var (bytes, _, _) = NpmFixtures.BuildTarball(name, "1.0.0");
        using var client = _factory.CreateClientWithBearer(await _factory.CreateAdminJwt());
        using var content = new MultipartFormDataContent();
        content.Add(FilePart(bytes), "files", $"{name}-1.0.0.tgz");
        return await client.PostAsync("/api/v1/admin/upload", content);
    }

    private async Task<long> HostedVersionCountAsync(string orgId, string name)
    {
        await using var conn = await Db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.name = @name
            """,
            new { orgId, name });
    }

    private static async Task AssertUsageCapRefusalAsync(HttpResponseMessage resp)
    {
        Assert.Equal(HttpStatusCode.PaymentRequired, resp.StatusCode);
        Assert.Equal("application/problem+json", resp.Content.Headers.ContentType?.MediaType);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("UsageCapReached", doc.RootElement.GetProperty("reason").GetString());
        Assert.Equal(InfoUrl, doc.RootElement.GetProperty("type").GetString());
        Assert.Contains($"<{InfoUrl}>", resp.Headers.GetValues("Link").Single());
    }

    private async Task<int> BurstOf429Async(string path, int requests)
    {
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var responses = await Task.WhenAll(Enumerable.Range(0, requests).Select(_ => client.GetAsync(path)));
        try
        {
            Assert.All(responses, r => Assert.True(
                r.StatusCode is HttpStatusCode.OK or HttpStatusCode.TooManyRequests,
                $"unexpected {(int)r.StatusCode}"));
            return responses.Count(r => r.StatusCode == HttpStatusCode.TooManyRequests);
        }
        finally
        {
            foreach (var r in responses)
            {
                r.Dispose();
            }
        }
    }

    // ── Upload refusal at 100 % of each meter, with its active twin ─────────────

    [Theory]
    [InlineData(UsageCapMeters.EgressBytes)]
    [InlineData(UsageCapMeters.EgressMetadataBytes)]
    public async Task Egress_at_the_cap_refuses_uploads_and_one_byte_below_admits_them(string meter)
    {
        string orgId = await DefaultOrgIdAsync();
        string token = await _factory.CreateToken("push");

        await SetEgressAsync(orgId, meter, 999);
        Assert.Equal(UsagePostures.Normal, await CapAsync(orgId, meter, 1000));
        using (var below = await PublishNpmAsync(token))
        {
            Assert.Equal(HttpStatusCode.OK, below.StatusCode);
        }

        await SetEgressAsync(orgId, meter, 1000);
        Assert.Equal(UsagePostures.UploadsRefused, await Postures.RecomputeForOrgAsync(orgId));
        using var atCap = await PublishNpmAsync(token);
        await AssertUsageCapRefusalAsync(atCap);
    }

    [Fact]
    public async Task Storage_at_the_cap_refuses_uploads_and_below_admits_them()
    {
        string orgId = await DefaultOrgIdAsync();
        string token = await _factory.CreateToken("push");
        await SetSnapshotAsync(orgId, billable: 5000, hostedVersions: 0, ociManifests: 0);

        Assert.Equal(UsagePostures.Normal, await CapAsync(orgId, UsageCapMeters.StorageBytes, 5001));
        using (var below = await PublishNpmAsync(token))
        {
            Assert.Equal(HttpStatusCode.OK, below.StatusCode);
        }

        Assert.Equal(UsagePostures.UploadsRefused, await CapAsync(orgId, UsageCapMeters.StorageBytes, 5000));
        using var atCap = await PublishNpmAsync(token);
        await AssertUsageCapRefusalAsync(atCap);
    }

    [Fact]
    public async Task Artifact_count_at_the_cap_refuses_uploads_and_below_admits_them()
    {
        string orgId = await DefaultOrgIdAsync();
        string token = await _factory.CreateToken("push");
        // Four uploaded package versions and two uploaded OCI manifests make six artefacts.
        await SetSnapshotAsync(orgId, billable: 0, hostedVersions: 4, ociManifests: 2);

        Assert.Equal(UsagePostures.Normal, await CapAsync(orgId, UsageCapMeters.ArtifactCount, 7));
        using (var below = await PublishNpmAsync(token))
        {
            Assert.Equal(HttpStatusCode.OK, below.StatusCode);
        }

        Assert.Equal(UsagePostures.UploadsRefused, await CapAsync(orgId, UsageCapMeters.ArtifactCount, 6));
        using var atCap = await PublishNpmAsync(token);
        await AssertUsageCapRefusalAsync(atCap);
    }

    [Fact]
    public async Task Oci_upload_at_the_cap_is_denied_in_the_registry_error_shape()
    {
        string orgId = await DefaultOrgIdAsync();
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        byte[] activeBytes = RandomNumberGenerator.GetBytes(128);
        using (var active = await client.PostAsync(
            $"/v2/cap-oci/blobs/uploads/?digest={Digest(activeBytes)}", new ByteArrayContent(activeBytes)))
        {
            Assert.Equal(HttpStatusCode.Created, active.StatusCode);
        }

        await SetEgressAsync(orgId, UsageCapMeters.EgressBytes, 1000);
        Assert.Equal(UsagePostures.UploadsRefused, await CapAsync(orgId, UsageCapMeters.EgressBytes, 1000));

        byte[] bytes = RandomNumberGenerator.GetBytes(128);
        using var refused = await client.PostAsync(
            $"/v2/cap-oci/blobs/uploads/?digest={Digest(bytes)}", new ByteArrayContent(bytes));

        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        using var doc = JsonDocument.Parse(await refused.Content.ReadAsStringAsync());
        var error = doc.RootElement.GetProperty("errors")[0];
        Assert.Equal("DENIED", error.GetProperty("code").GetString());
        Assert.Equal(InfoUrl, error.GetProperty("detail").GetProperty("infoUrl").GetString());
    }

    // ── Management-plane import honours the cap ────────────────────────────────

    [Fact]
    public async Task Bulk_import_is_refused_at_the_cap_like_a_protocol_publish()
    {
        string orgId = await DefaultOrgIdAsync();
        await SetSnapshotAsync(orgId, billable: 5000, hostedVersions: 0, ociManifests: 0);

        Assert.Equal(UsagePostures.Normal, await CapAsync(orgId, UsageCapMeters.StorageBytes, 5001));
        string belowName = $"cap-imp-{Guid.NewGuid():N}"[..20];
        using (var below = await ImportNpmAsync(belowName))
        {
            Assert.Equal(HttpStatusCode.OK, below.StatusCode);
            using var doc = JsonDocument.Parse(await below.Content.ReadAsStringAsync());
            Assert.Equal(1, doc.RootElement.GetProperty("accepted").GetInt32());
        }
        Assert.Equal(1, await HostedVersionCountAsync(orgId, belowName));

        Assert.Equal(UsagePostures.UploadsRefused, await CapAsync(orgId, UsageCapMeters.StorageBytes, 5000));
        string atCapName = $"cap-imp-{Guid.NewGuid():N}"[..20];
        using var atCap = await ImportNpmAsync(atCapName);
        await AssertUsageCapRefusalAsync(atCap);
        Assert.Equal(0, await HostedVersionCountAsync(orgId, atCapName));
    }

    [Fact]
    public async Task Manifest_import_is_refused_at_the_cap()
    {
        string orgId = await DefaultOrgIdAsync();
        await SetSnapshotAsync(orgId, billable: 5000, hostedVersions: 0, ociManifests: 0);
        Assert.Equal(UsagePostures.UploadsRefused, await CapAsync(orgId, UsageCapMeters.StorageBytes, 5000));

        string name = $"cap-mfst-{Guid.NewGuid():N}"[..20];
        var (bytes, _, _) = NpmFixtures.BuildTarball(name, "1.0.0");
        string lockfile = $$"""
            {
              "name": "test", "version": "1.0.0", "lockfileVersion": 3,
              "packages": {
                "": { "name": "test", "version": "1.0.0" },
                "node_modules/{{name}}": { "version": "1.0.0" }
              }
            }
            """;

        using var client = _factory.CreateClientWithBearer(await _factory.CreateAdminJwt());
        using var content = new MultipartFormDataContent();
        var manifestPart = new ByteArrayContent(Encoding.UTF8.GetBytes(lockfile));
        manifestPart.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        content.Add(manifestPart, "manifest", "package-lock.json");
        content.Add(FilePart(bytes), "files", $"{name}-1.0.0.tgz");

        using var resp = await client.PostAsync("/api/v1/admin/import/manifest", content);
        await AssertUsageCapRefusalAsync(resp);
        Assert.Equal(0, await HostedVersionCountAsync(orgId, name));
    }

    // ── What the cap leaves alone ──────────────────────────────────────────────

    [Fact]
    public async Task Downloads_and_deletes_stay_admitted_at_the_cap()
    {
        string orgId = await DefaultOrgIdAsync();
        string id = $"CapKeep{Guid.NewGuid():N}"[..16];
        await _factory.PushNuGetPackage(id, "1.0.0");

        await SetEgressAsync(orgId, UsageCapMeters.EgressBytes, 1000);
        Assert.Equal(UsagePostures.UploadsRefused, await CapAsync(orgId, UsageCapMeters.EgressBytes, 1000));

        string lower = id.ToLowerInvariant();
        using (var pull = _factory.CreateClientWithBasic(await _factory.CreateToken("pull")))
        using (var download = await pull.GetAsync($"/nuget/flatcontainer/{lower}/1.0.0/{lower}.1.0.0.nupkg"))
        {
            Assert.Equal(HttpStatusCode.OK, download.StatusCode);
        }

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", await _factory.CreateToken("push"));
        using var unlist = await client.DeleteAsync($"/nuget/publish/{id}/1.0.0");
        Assert.Equal(HttpStatusCode.NoContent, unlist.StatusCode);
    }

    [Fact]
    public async Task An_npm_audit_query_is_admitted_at_the_cap_while_a_publish_is_refused()
    {
        string orgId = await DefaultOrgIdAsync();
        string token = await _factory.CreateToken("push");
        await SetEgressAsync(orgId, UsageCapMeters.EgressBytes, 1000);
        Assert.Equal(UsagePostures.UploadsRefused, await CapAsync(orgId, UsageCapMeters.EgressBytes, 1000));

        // npm install and npm audit POST the dependency tree to ask about advisories. An empty
        // tree is answered without an advisory lookup, so the test needs no OSV source.
        using var client = _factory.CreateClientWithBearer(token);
        using var audit = await client.PostAsync(
            "/npm/-/npm/v1/security/advisories/bulk",
            new StringContent("{}", Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.OK, audit.StatusCode);

        using var publish = await PublishNpmAsync(token);
        await AssertUsageCapRefusalAsync(publish);
    }

    [Fact]
    public async Task An_npm_unpublish_prune_is_admitted_at_the_cap_while_a_publish_is_refused()
    {
        string orgId = await DefaultOrgIdAsync();
        string token = await _factory.CreateToken("push");
        string name = $"cap-unpub-{Guid.NewGuid():N}"[..24];
        using var client = _factory.CreateClientWithBearer(token);
        foreach (string version in new[] { "1.0.0", "1.1.0" })
        {
            using var published = await client.PutAsync(
                $"/npm/{name}",
                new StringContent(NpmFixtures.BuildPublishBody(name, version), Encoding.UTF8, "application/json"));
            Assert.Equal(HttpStatusCode.OK, published.StatusCode);
        }

        await SetEgressAsync(orgId, UsageCapMeters.EgressBytes, 1000);
        Assert.Equal(UsagePostures.UploadsRefused, await CapAsync(orgId, UsageCapMeters.EgressBytes, 1000));

        // npm unpublish name@1.0.0: read the packument's _rev, PUT the packument pruned to the
        // versions to keep, then DELETE the removed version's tarball with the same rev.
        string rev;
        using (var packument = await client.GetAsync($"/npm/{name}"))
        {
            Assert.Equal(HttpStatusCode.OK, packument.StatusCode);
            using var doc = JsonDocument.Parse(await packument.Content.ReadAsStringAsync());
            rev = doc.RootElement.GetProperty("_rev").GetString()!;
        }

        string keep = JsonSerializer.Serialize(new
        {
            name,
            versions = new Dictionary<string, object> { ["1.1.0"] = new { name, version = "1.1.0" } },
        });
        using (var prune = await client.PutAsync(
            $"/npm/{name}/-rev/{rev}", new StringContent(keep, Encoding.UTF8, "application/json")))
        {
            Assert.Equal(HttpStatusCode.OK, prune.StatusCode);
            using var doc = JsonDocument.Parse(await prune.Content.ReadAsStringAsync());
            Assert.True(doc.RootElement.GetProperty("ok").GetBoolean());
        }

        using (var tarball = await client.DeleteAsync($"/npm/{name}/-/{name}-1.0.0.tgz/-rev/{rev}"))
        {
            Assert.Equal(HttpStatusCode.OK, tarball.StatusCode);
        }

        using (var after = await client.GetAsync($"/npm/{name}"))
        {
            Assert.Equal(HttpStatusCode.OK, after.StatusCode);
            using var doc = JsonDocument.Parse(await after.Content.ReadAsStringAsync());
            var versions = doc.RootElement.GetProperty("versions");
            Assert.False(versions.TryGetProperty("1.0.0", out _), "1.0.0 must be unpublished");
            Assert.True(versions.TryGetProperty("1.1.0", out _), "1.1.0 must be kept");
        }

        using var publish = await PublishNpmAsync(token);
        await AssertUsageCapRefusalAsync(publish);
    }

    private async Task<HttpResponseMessage> PostSamlAcsAsync()
    {
        using var client = _factory.CreateClient();
        return await client.PostAsync("/saml/acs", new FormUrlEncodedContent(
            new Dictionary<string, string> { ["SAMLResponse"] = "not-a-real-assertion" }));
    }

    [Fact]
    public async Task Saml_sign_in_reaches_its_controller_at_the_cap_while_a_publish_is_refused()
    {
        string orgId = await DefaultOrgIdAsync();
        string token = await _factory.CreateToken("push");
        await SetEgressAsync(orgId, UsageCapMeters.EgressBytes, 1000);
        Assert.Equal(UsagePostures.UploadsRefused, await CapAsync(orgId, UsageCapMeters.EgressBytes, 1000));

        // SAML is not configured here, so the controller rejects the assertion itself; what
        // matters is that the usage-cap gate did not answer for it.
        using var acs = await PostSamlAcsAsync();
        Assert.NotEqual(HttpStatusCode.PaymentRequired, acs.StatusCode);
        Assert.DoesNotContain("UsageCapReached", await acs.Content.ReadAsStringAsync(), StringComparison.Ordinal);

        using var publish = await PublishNpmAsync(token);
        await AssertUsageCapRefusalAsync(publish);
    }

    [Fact]
    public async Task Saml_sign_in_reaches_its_controller_under_read_only_while_a_publish_is_refused()
    {
        string token = await _factory.CreateToken("push");
        await _factory.SetOrgStatus("default", "read_only");

        using var acs = await PostSamlAcsAsync();
        Assert.NotEqual(HttpStatusCode.Locked, acs.StatusCode);
        Assert.DoesNotContain("ReadOnlyWrite", await acs.Content.ReadAsStringAsync(), StringComparison.Ordinal);

        using var publish = await PublishNpmAsync(token);
        Assert.Equal(HttpStatusCode.Locked, publish.StatusCode);
    }

    [Fact]
    public async Task Management_plane_writes_stay_admitted_at_the_cap()
    {
        string orgId = await DefaultOrgIdAsync();
        await SetEgressAsync(orgId, UsageCapMeters.EgressBytes, 5000);
        Assert.Equal(UsagePostures.DownloadsThrottled, await CapAsync(orgId, UsageCapMeters.EgressBytes, 1000));

        using var client = _factory.CreateClientWithBearer(await _factory.CreateAdminJwt());
        using var resp = await client.PostAsync(
            "/api/v1/tokens",
            new StringContent("""{"capabilities":["read:*"]}""", Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    // ── Pilot: no caps, never enforced ─────────────────────────────────────────

    [Fact]
    public async Task An_org_with_no_caps_is_metered_but_never_enforced()
    {
        string orgId = await DefaultOrgIdAsync();
        string token = await _factory.CreateToken("push");
        await SetEgressAsync(orgId, UsageCapMeters.EgressBytes, 1_000_000_000_000);
        await SetSnapshotAsync(orgId, billable: 1_000_000_000_000, hostedVersions: 100_000, ociManifests: 100_000);

        Assert.Equal(UsagePostures.Normal, await Postures.RecomputeForOrgAsync(orgId));
        await Postures.RecomputeAsync();
        Assert.Equal(UsagePostures.Normal, await Postures.GetPostureAsync(orgId));

        using var publish = await PublishNpmAsync(token);
        Assert.Equal(HttpStatusCode.OK, publish.StatusCode);
        Assert.Equal(0, await BurstOf429Async("/nuget/v3/index.json", 20));
    }

    [Fact]
    public async Task Clearing_the_cap_restores_uploads()
    {
        string orgId = await DefaultOrgIdAsync();
        string token = await _factory.CreateToken("push");
        await SetEgressAsync(orgId, UsageCapMeters.EgressBytes, 5000);
        Assert.Equal(UsagePostures.DownloadsThrottled, await CapAsync(orgId, UsageCapMeters.EgressBytes, 1000));
        using (var refused = await PublishNpmAsync(token))
        {
            Assert.Equal(HttpStatusCode.PaymentRequired, refused.StatusCode);
        }

        Assert.Equal(UsagePostures.Normal, await CapAsync(orgId, UsageCapMeters.EgressBytes, null));

        using (var restored = await PublishNpmAsync(token))
        {
            Assert.Equal(HttpStatusCode.OK, restored.StatusCode);
        }

        // The storage-layer gate the import path meets releases with the posture too.
        using var imported = await ImportNpmAsync($"cap-clr-{Guid.NewGuid():N}"[..20]);
        Assert.Equal(HttpStatusCode.OK, imported.StatusCode);
    }

    // ── Download throttling at 110 %, with its active twin ─────────────────────

    [Fact]
    public async Task At_110_percent_of_an_egress_cap_downloads_draw_on_the_throttled_budget()
    {
        string orgId = await DefaultOrgIdAsync();
        await SetEgressAsync(orgId, UsageCapMeters.EgressBytes, 1100);
        Assert.Equal(UsagePostures.DownloadsThrottled, await CapAsync(orgId, UsageCapMeters.EgressBytes, 1000));

        // Throttled, not refused: the first requests in the window are served.
        int throttled = await BurstOf429Async("/nuget/v3/index.json", 20);
        Assert.InRange(throttled, 1, 18);
    }

    [Fact]
    public async Task One_byte_under_110_percent_refuses_uploads_but_does_not_throttle()
    {
        string orgId = await DefaultOrgIdAsync();
        await SetEgressAsync(orgId, UsageCapMeters.EgressBytes, 1099);
        Assert.Equal(UsagePostures.UploadsRefused, await CapAsync(orgId, UsageCapMeters.EgressBytes, 1000));

        Assert.Equal(0, await BurstOf429Async("/nuget/v3/index.json", 20));
    }

    [Fact]
    public async Task A_storage_overage_never_throttles_downloads()
    {
        string orgId = await DefaultOrgIdAsync();
        await SetSnapshotAsync(orgId, billable: 1_000_000, hostedVersions: 0, ociManifests: 0);
        Assert.Equal(UsagePostures.UploadsRefused, await CapAsync(orgId, UsageCapMeters.StorageBytes, 1000));

        Assert.Equal(0, await BurstOf429Async("/nuget/v3/index.json", 20));
    }


    // ── The hourly rollup trips the posture ────────────────────────────────────

    [Fact]
    public async Task The_hourly_rollup_trips_an_egress_cap_from_raw_usage_events()
    {
        string orgId = await DefaultOrgIdAsync();
        string token = await _factory.CreateToken("push");
        Assert.Equal(UsagePostures.Normal, await CapAsync(orgId, UsageCapMeters.EgressBytes, 1000));

        var now = _factory.Services.GetRequiredService<TimeProvider>().GetUtcNow();
        await _factory.Services.GetRequiredService<UsageEventRepository>().InsertBatchAsync(
        [
            UsageEvent.Create(Guid.NewGuid(), orgId, UsageMeters.EgressBytes, UsageDelivery.Streamed, 600, "npm", null, now.AddSeconds(-2)),
            UsageEvent.Create(Guid.NewGuid(), orgId, UsageMeters.EgressBytes, UsageDelivery.Redirect, 450, "oci", "blob", now.AddSeconds(-1)),
        ]);

        var rollup = _factory.Services.GetServices<IHostedService>().OfType<UsageRollupHourlyService>().Single();
        await rollup.RunPassAsync(CancellationToken.None);

        Assert.Equal(UsagePostures.UploadsRefused, await Postures.GetPostureAsync(orgId));
        using var refused = await PublishNpmAsync(token);
        Assert.Equal(HttpStatusCode.PaymentRequired, refused.StatusCode);
    }

    private static string Digest(byte[] bytes) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}

/// <summary>
/// The per-tenant rate-limit budget (<c>TENANT_RATE_LIMIT_PERMITS</c>) end to end: when set, one
/// org's protocol traffic is bounded in aggregate whichever of its tokens sends it; when unset, the
/// same burst is never refused by the tenant dimension.
/// </summary>
[Trait("Category", "Integration")]
public sealed class TenantRateLimitBudgetTests
{
    private static async Task<int> BurstAcrossTokensAsync(DependablyFactory factory, int requests)
    {
        // Every request carries a different token, so no per-caller limit could be what refuses it.
        string[] tokens = await Task.WhenAll(Enumerable.Range(0, requests).Select(_ => factory.CreateToken("pull")));
        var clients = tokens.Select(factory.CreateClientWithBasic).ToList();
        try
        {
            var responses = await Task.WhenAll(clients.Select(c => c.GetAsync("/nuget/v3/index.json")));
            Assert.All(responses, r => Assert.True(
                r.StatusCode is HttpStatusCode.OK or HttpStatusCode.TooManyRequests,
                $"unexpected {(int)r.StatusCode}"));
            var limited = responses.Where(r => r.StatusCode == HttpStatusCode.TooManyRequests).ToList();
            Assert.All(limited, r => Assert.True(r.Headers.Contains("Retry-After")));
            return limited.Count;
        }
        finally
        {
            clients.ForEach(c => c.Dispose());
        }
    }

    [Fact]
    public async Task With_a_budget_one_orgs_callers_share_it()
    {
        var factory = new DependablyFactory
        {
            ExtraSettings = new Dictionary<string, string?>
            {
                ["TENANT_RATE_LIMIT_PERMITS"] = "3",
                ["TENANT_RATE_LIMIT_QUEUE"] = "0",
            },
        };
        try
        {
            await factory.InitializeAsync();
            Assert.InRange(await BurstAcrossTokensAsync(factory, 20), 1, 17);
        }
        finally
        {
            await factory.DisposeAsync();
        }
    }

    [Fact]
    public async Task Without_a_budget_the_same_burst_is_not_tenant_limited()
    {
        var factory = new DependablyFactory();
        try
        {
            await factory.InitializeAsync();
            Assert.Equal(0, await BurstAcrossTokensAsync(factory, 20));
        }
        finally
        {
            await factory.DisposeAsync();
        }
    }
}
