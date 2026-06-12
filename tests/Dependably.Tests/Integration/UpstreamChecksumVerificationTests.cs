using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// Defence-in-depth: when public upstream registries advertise an integrity hash for an
/// artefact, we now verify the downloaded bytes against it on first-fetch and refuse the
/// response (502 + checksum_failure audit) on mismatch. Each ecosystem gets three cases:
/// match (200, row persisted), mismatch (502, no row, no audit-shaped artefact), missing
/// (200, fail-soft as before). Pairs with the test-partial-failure-scenarios rule.
///
/// Also pins the npm <c>dist.shasum</c> fix: the bug emitted SHA-256 into the SHA-1 field
/// of the packument we serve. Round-trip a publish and assert the field carries the proper
/// hex SHA-1 of the tarball bytes.
/// </summary>
[Trait("Category", "Integration")]
public sealed class UpstreamChecksumVerificationTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public UpstreamChecksumVerificationTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    // All package-row queries filter by (ecosystem, name, version) — the name is required
    // for isolation because SQLite's default created_at has 1-second resolution and the
    // IClassFixture pattern shares the metadata store across every test in this class. If
    // two tests insert rows with the same (ecosystem, version) inside the same wall-clock
    // second, ORDER BY created_at DESC LIMIT 1 returns either row non-deterministically.
    // That's what blew up in the post-merge main pipeline: the publish round-trip and the
    // npm integrity-match test both used version="1.0.0" and happened to race. Each test
    // already generates a Guid-suffixed name, so adding it to the WHERE clause is the
    // disambiguator with no extra coordination cost.

    private async Task<bool> VersionRowExistsAsync(string ecosystem, string name, string version)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        long hits = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.ecosystem = @ecosystem AND p.name = @name AND pv.version = @version
            """,
            new { ecosystem, name, version });
        return hits > 0;
    }

    private async Task<long> ChecksumFailureAuditCountAsync()
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'checksum_failure'");
    }

    private async Task<(string? Value, string? Algorithm, string? Sha1)> ReadUpstreamColumnsAsync(
        string ecosystem, string name, string version)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        var row = await conn.QuerySingleOrDefaultAsync<(string? Value, string? Algorithm, string? Sha1)>(
            """
            SELECT pv.upstream_integrity_value AS Value,
                   pv.upstream_integrity_algorithm AS Algorithm,
                   pv.checksum_sha1 AS Sha1
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.ecosystem = @ecosystem AND p.name = @name AND pv.version = @version
            ORDER BY pv.created_at DESC LIMIT 1
            """,
            new { ecosystem, name, version });
        return row;
    }

    // ── npm ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Npm_ProxyFirstFetch_PackumentIntegrityMatches_Succeeds()
    {
        string name = $"npmcok{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string version = "1.0.0";
        var (bytes, _, integrity) = NpmFixtures.BuildTarball(name, version);
        string filename = $"{name}-{version}.tgz";
        string shasum = Convert.ToHexString(SHA1.HashData(bytes)).ToLowerInvariant();

        string packument = $$"""
            {
              "name": "{{name}}",
              "versions": {
                "{{version}}": {
                  "name": "{{name}}", "version": "{{version}}",
                  "dist": { "integrity": "{{integrity}}", "shasum": "{{shasum}}" }
                }
              }
            }
            """;
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(packument));
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}/-/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(bytes));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/tarballs/{name}/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.True(await VersionRowExistsAsync("npm", name, version));

        // Upstream integrity stored verbatim (SRI form) + the legacy shasum stored for npm.
        var (value, algorithm, sha1) = await ReadUpstreamColumnsAsync("npm", name, version);
        Assert.Equal(integrity, value);
        Assert.Equal("sha512-sri", algorithm);
        Assert.Equal(shasum, sha1);
    }

    [Fact]
    public async Task Npm_ProxyFirstFetch_PackumentIntegrityMismatch_502_NoVersionRow_AuditLogged()
    {
        string name = $"npmbad{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string version = "1.1.0";
        var (bytes, _, _) = NpmFixtures.BuildTarball(name, version);
        string filename = $"{name}-{version}.tgz";

        // Integrity hash for *different* bytes — verification must reject the real tarball.
        var (_, _, wrongIntegrity) = NpmFixtures.BuildTarball(name, "9.9.9-poison");

        string packument = $$"""
            {
              "name": "{{name}}",
              "versions": {
                "{{version}}": {
                  "name": "{{name}}", "version": "{{version}}",
                  "dist": { "integrity": "{{wrongIntegrity}}" }
                }
              }
            }
            """;
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(packument));
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}/-/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(bytes));

        long before = await ChecksumFailureAuditCountAsync();
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/tarballs/{name}/{filename}");
        Assert.Equal(HttpStatusCode.BadGateway, resp.StatusCode);
        Assert.False(await VersionRowExistsAsync("npm", name, version));
        Assert.Equal(before + 1, await ChecksumFailureAuditCountAsync());
    }

    [Fact]
    public async Task Npm_ProxyFirstFetch_PackumentMissingIntegrity_Succeeds()
    {
        string name = $"npmnil{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string version = "1.2.0";
        var (bytes, _, _) = NpmFixtures.BuildTarball(name, version);
        string filename = $"{name}-{version}.tgz";

        // Packument carries no dist.integrity / shasum — fail-soft path: serve as before.
        string packument = $$"""
            {
              "name": "{{name}}",
              "versions": {
                "{{version}}": { "name": "{{name}}", "version": "{{version}}", "dist": {} }
              }
            }
            """;
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(packument));
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}/-/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(bytes));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/tarballs/{name}/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.True(await VersionRowExistsAsync("npm", name, version));

        // Fail-soft: no upstream integrity to surface, so the columns stay NULL.
        var (value, algorithm, _) = await ReadUpstreamColumnsAsync("npm", name, version);
        Assert.Null(value);
        Assert.Null(algorithm);
    }

    // ── NuGet ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task NuGet_ProxyFirstFetch_RegistrationPackageHashMatches_Succeeds()
    {
        string id = $"NuGetCok{Guid.NewGuid():N}"[..18];
        string version = "1.0.0";
        string lowerId = id.ToLowerInvariant();
        var (bytes, _) = NuGetFixtures.BuildNupkg(id, version);
        string filename = $"{lowerId}.{version}.nupkg";
        string b64 = Convert.ToBase64String(SHA512.HashData(bytes));

        string leaf = $$"""{ "packageHash": "{{b64}}", "packageHashAlgorithm": "SHA512", "listed": true }""";
        _factory.MockUpstream.Given(Request.Create()
                .WithPath($"/registration5-semver1/{lowerId}/{version}.json").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(leaf));
        _factory.MockUpstream.Given(Request.Create()
                .WithPath($"/flatcontainer/{lowerId}/{version}/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(bytes));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/nuget/flatcontainer/{lowerId}/{version}/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.True(await VersionRowExistsAsync("nuget", lowerId, version));

        var (value, algorithm, _) = await ReadUpstreamColumnsAsync("nuget", lowerId, version);
        Assert.Equal(b64, value);
        Assert.Equal("sha512-b64", algorithm);
    }

    [Fact]
    public async Task NuGet_ProxyFirstFetch_RegistrationPackageHashMismatch_502_NoVersionRow_AuditLogged()
    {
        string id = $"NuGetBad{Guid.NewGuid():N}"[..18];
        string version = "1.1.0";
        string lowerId = id.ToLowerInvariant();
        var (bytes, _) = NuGetFixtures.BuildNupkg(id, version);
        string filename = $"{lowerId}.{version}.nupkg";
        string wrongB64 = Convert.ToBase64String(SHA512.HashData(System.Text.Encoding.UTF8.GetBytes("not the bytes")));

        string leaf = $$"""{ "packageHash": "{{wrongB64}}", "packageHashAlgorithm": "SHA512", "listed": true }""";
        _factory.MockUpstream.Given(Request.Create()
                .WithPath($"/registration5-semver1/{lowerId}/{version}.json").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(leaf));
        _factory.MockUpstream.Given(Request.Create()
                .WithPath($"/flatcontainer/{lowerId}/{version}/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(bytes));

        long before = await ChecksumFailureAuditCountAsync();
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/nuget/flatcontainer/{lowerId}/{version}/{filename}");
        Assert.Equal(HttpStatusCode.BadGateway, resp.StatusCode);
        Assert.False(await VersionRowExistsAsync("nuget", lowerId, version));
        Assert.Equal(before + 1, await ChecksumFailureAuditCountAsync());
    }

    // ── PyPI ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task PyPi_ProxyFirstFetch_SimpleIndexHashMatches_Succeeds()
    {
        string name = $"pypicok{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string version = "1.0.0";
        string underscored = name.Replace('-', '_');
        string filename = $"{underscored}-{version}-py3-none-any.whl";
        var (wheelBytes, sha256) = PyPiFixtures.BuildWheel(name, version);
        string mockBase = _factory.MockUpstream.Urls[0];

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody($"<html><body><a href=\"{mockBase}/files/{filename}#sha256={sha256}\">{filename}</a></body></html>"));
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/files/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(wheelBytes));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/packages/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.True(await VersionRowExistsAsync("pypi", name, version));

        var (value, algorithm, _) = await ReadUpstreamColumnsAsync("pypi", name, version);
        Assert.Equal(sha256, value);
        Assert.Equal("sha256", algorithm);
    }

    [Fact]
    public async Task PyPi_ProxyFirstFetch_SimpleIndexHashMismatch_502_NoVersionRow_AuditLogged()
    {
        string name = $"pypibad{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string version = "1.1.0";
        string underscored = name.Replace('-', '_');
        string filename = $"{underscored}-{version}-py3-none-any.whl";
        var (wheelBytes, _) = PyPiFixtures.BuildWheel(name, version);
        string mockBase = _factory.MockUpstream.Urls[0];
        const string wrongHash = "0000000000000000000000000000000000000000000000000000000000000000";

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody($"<html><body><a href=\"{mockBase}/files/{filename}#sha256={wrongHash}\">{filename}</a></body></html>"));
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/files/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(wheelBytes));

        long before = await ChecksumFailureAuditCountAsync();
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/packages/{filename}");
        Assert.Equal(HttpStatusCode.BadGateway, resp.StatusCode);
        Assert.False(await VersionRowExistsAsync("pypi", name, version));
        Assert.Equal(before + 1, await ChecksumFailureAuditCountAsync());
    }

    [Fact]
    public async Task PyPi_ProxyFirstFetch_SimpleIndexNoFragment_Succeeds()
    {
        string name = $"pypinil{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string version = "1.2.0";
        string underscored = name.Replace('-', '_');
        string filename = $"{underscored}-{version}-py3-none-any.whl";
        var (wheelBytes, _) = PyPiFixtures.BuildWheel(name, version);
        string mockBase = _factory.MockUpstream.Urls[0];

        // No #sha256= fragment — fail-soft path: serve without first-fetch verification.
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody($"<html><body><a href=\"{mockBase}/files/{filename}\">{filename}</a></body></html>"));
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/files/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(wheelBytes));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/packages/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.True(await VersionRowExistsAsync("pypi", name, version));
    }

    // ── npm publish round-trip: dist.shasum is the correct SHA-1 ─────────────

    [Fact]
    public async Task NpmPublish_PackumentEmitsCorrectShasum()
    {
        string name = $"shasumok{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string version = "1.0.0";
        await _factory.PushNpmPackage(name, version);

        // NpmFixtures.BuildTarball isn't byte-deterministic across calls (PAX mtime header),
        // so re-hashing a fresh tarball would give the wrong expected value. Instead read the
        // SHA-1 the publish service stored against the actual bytes it received.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        string storedSha1;
        await using (var conn = await store.OpenAsync())
        {
            storedSha1 = await conn.ExecuteScalarAsync<string>(
                """
                SELECT pv.checksum_sha1 FROM package_versions pv
                JOIN packages p ON p.id = pv.package_id
                WHERE p.ecosystem = 'npm' AND p.name = @name AND pv.version = @version
                """,
                new { name, version }) ?? "";
        }
        Assert.False(string.IsNullOrEmpty(storedSha1), "publish should populate checksum_sha1 for npm");
        Assert.Matches("^[0-9a-f]{40}$", storedSha1);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        var resp = await client.GetAsync($"/npm/{name}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var dist = doc.RootElement.GetProperty("versions").GetProperty(version).GetProperty("dist");
        string? actualShasum = dist.GetProperty("shasum").GetString();
        Assert.Equal(storedSha1, actualShasum);
    }
}
