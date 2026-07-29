using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// #437 item 2 (end-to-end): an upstream_url embedding user:pass@ credentials — as a legacy row
/// written before save-time rejection existed can still hold — must never reach a read:packages
/// caller. The per-version projection strips the userinfo. Proven through the real HTTP pipeline
/// with a member-role principal: a helper unit test proves StripCredentials works, but only the
/// round-trip proves the strip is actually ON the response path a member hits — the exact
/// "correct-but-not-called" gap through which a real leak survives a green unit suite.
/// Twin: an admin still round-trips legitimate upstream config after the validator changes.
/// </summary>
[Trait("Category", "Integration")]
public sealed class UpstreamUrlCredentialLeakTests : IClassFixture<DependablyFactory>
{
    private readonly DependablyFactory _factory;
    public UpstreamUrlCredentialLeakTests(DependablyFactory factory) => _factory = factory;

    private IMetadataStore Db => _factory.Services.GetRequiredService<IMetadataStore>();

    private HttpClient BearerClient(string token)
    {
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return c;
    }

    // Seeds a proxy (cache_artifact) version through the real CacheAccessRecorder write path with
    // an upstream_url carrying user:pass@ — the shape a legacy row holds before save-time rejection.
    private async Task<string> SeedProxyVersionWithLeakyUpstreamAsync(string leakyUrl)
    {
        string orgId;
        await using (var conn = await Db.OpenAsync())
        {
            orgId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
                ?? throw new InvalidOperationException("Default org not found.");
        }

        string name = $"credleak-{Guid.NewGuid():N}"[..20].ToLowerInvariant();
        const string version = "1.0.0";
        string filename = $"{name}-{version}.tgz";
        byte[] bytes = [0x42, 0x42, 0x42, 0x42];
        string sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        string blobKey = BlobKeys.Proxy(sha256);
        await _factory.BlobStore.PutAsync(
            BlobKeys.StoreKey(blobKey), new MemoryStream(bytes), CancellationToken.None);

        await _factory.Services.GetRequiredService<CacheAccessRecorder>().RecordAccessAsync(
            new CacheAccess(orgId, "npm", name, version, filename,
                Sha256: sha256, SizeBytes: bytes.Length,
                BlobKey: $"{blobKey}/{filename}", UpstreamUrl: leakyUrl));
        await _factory.Services.GetRequiredService<PackageRepository>()
            .GetOrCreateAsync(orgId, "npm", name, name, isProxy: true, CancellationToken.None);
        return name;
    }

    [Fact]
    public async Task MemberReadingVersions_NeverReceivesEmbeddedUpstreamCredentials()
    {
        // A proxy version whose stored upstream_url still carries user:pass@ (save-time rejection
        // blocks new ones, but rows written before that gate existed must be redacted on read).
        const string secret = "s3cr3tPassw0rd";
        string pkg = await SeedProxyVersionWithLeakyUpstreamAsync(
            $"https://svcuser:{secret}@nexus.corp.internal/repository/npm/x/-/x-1.0.0.tgz");

        // Read as a member-role principal (read:packages is in the plain member grant).
        string email = $"member-{Guid.NewGuid():N}@example.test";
        string userId = await _factory.CreateUser(email, "Test1234!", role: "member");
        string jwt = await _factory.CreateUserJwt(userId, "member");
        using var client = BearerClient(jwt);

        var resp = await client.GetAsync($"/api/v1/packages/npm/{pkg}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();

        // The credential must be absent from the entire payload...
        Assert.DoesNotContain(secret, body);
        Assert.DoesNotContain("svcuser:", body);

        // ...while the upstream host survives (only the userinfo is stripped, not the origin link).
        using var doc = JsonDocument.Parse(body);
        var version = doc.RootElement.GetProperty("versions").EnumerateArray()
            .First(v => v.GetProperty("version").GetString() == "1.0.0");
        string? upstreamUrl = version.GetProperty("upstreamUrl").GetString();
        Assert.NotNull(upstreamUrl);
        Assert.Contains("nexus.corp.internal", upstreamUrl);
        Assert.DoesNotContain("@", upstreamUrl);
    }

    [Fact]
    public async Task AdminUpstreamConfig_StillRoundTrips()
    {
        // Adversarial twin: the save-time validator changes must not break the legitimate admin
        // config flow — an https upstream saves and lists back as designed.
        string email = $"owner-{Guid.NewGuid():N}@example.test";
        string userId = await _factory.CreateUser(email, "Test1234!", role: "owner");
        string jwt = await _factory.CreateUserJwt(userId, "owner");
        using var client = BearerClient(jwt);

        string mirror = $"https://mirror-{Guid.NewGuid():N}.example/npm";
        var create = await client.PostAsJsonAsync("/api/v1/upstream-registries",
            new { ecosystem = "npm", url = mirror });
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);

        var list = await client.GetAsync("/api/v1/upstream-registries");
        Assert.Equal(HttpStatusCode.OK, list.StatusCode);
        string listBody = await list.Content.ReadAsStringAsync();
        Assert.Contains(mirror, listBody);
    }
}
