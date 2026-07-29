using System.Net;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace Dependably.Tests.Integration;

/// <summary>
/// What the OCI read surface answers when a manifest or blob is not present locally and the
/// upstream cannot be consulted.
///
/// <para>
/// The Distribution Spec has one answer for "this registry does not have that": 404 with
/// <c>MANIFEST_UNKNOWN</c> / <c>BLOB_UNKNOWN</c>. A 500 is a different claim — "the server
/// broke" — and a client cannot act on it: it cannot distinguish a transient fault it should
/// retry from a manifest that will never come back, so `docker pull` retries against a
/// permanently absent tag. That distinction is the whole point of the status code, which is why
/// these tests assert over HTTP rather than at the resolver layer where the exception is raised.
/// </para>
///
/// <para>
/// An air-gapped instance is the sharpest case: it is a supported, documented deployment where
/// EVERY local miss is permanent, and where the upstream is not merely unreachable but
/// deliberately absent. It must still speak the protocol.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class OciReadMissStatusTests
{
    // Well-formed digest for content this registry has never seen.
    private const string AbsentDigest =
        "sha256:0000000000000000000000000000000000000000000000000000000000000001";

    [Fact]
    public async Task ManifestGet_LocalMissWhileAirGapped_Returns404_NotServerError()
    {
        await using var factory = new AirGappedOciFactory();
        await factory.InitializeAsync();
        await factory.EnableAnonymousPullAsync();

        using var client = factory.CreateClient();
        var resp = await client.GetAsync($"/v2/library/nothing/manifests/{AbsentDigest}");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    /// <summary>
    /// The tag form takes a different route through the resolver (tag→digest resolution before
    /// the upstream call), so it gets its own assertion rather than riding on the digest one.
    /// </summary>
    [Fact]
    public async Task ManifestGetByTag_LocalMissWhileAirGapped_Returns404_NotServerError()
    {
        await using var factory = new AirGappedOciFactory();
        await factory.InitializeAsync();
        await factory.EnableAnonymousPullAsync();

        using var client = factory.CreateClient();
        var resp = await client.GetAsync("/v2/library/nothing/manifests/v1");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    /// <summary>HEAD must agree with GET — a client that probes before pulling gets the same answer.</summary>
    [Fact]
    public async Task ManifestHead_LocalMissWhileAirGapped_Returns404_NotServerError()
    {
        await using var factory = new AirGappedOciFactory();
        await factory.InitializeAsync();
        await factory.EnableAnonymousPullAsync();

        using var client = factory.CreateClient();
        using var req = new HttpRequestMessage(HttpMethod.Head, $"/v2/library/nothing/manifests/{AbsentDigest}");
        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task BlobGet_LocalMissWhileAirGapped_Returns404_NotServerError()
    {
        await using var factory = new AirGappedOciFactory();
        await factory.InitializeAsync();
        await factory.EnableAnonymousPullAsync();

        using var client = factory.CreateClient();
        var resp = await client.GetAsync($"/v2/library/nothing/blobs/{AbsentDigest}");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task BlobHead_LocalMissWhileAirGapped_Returns404_NotServerError()
    {
        await using var factory = new AirGappedOciFactory();
        await factory.InitializeAsync();
        await factory.EnableAnonymousPullAsync();

        using var client = factory.CreateClient();
        using var req = new HttpRequestMessage(HttpMethod.Head, $"/v2/library/nothing/blobs/{AbsentDigest}");
        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    /// <summary>
    /// The same miss on a NON-air-gapped instance with no upstream configured already answered 404
    /// before this change. Pinning it guards the fix from being written as "air-gap returns 404"
    /// when the property is "a local miss with no reachable upstream returns 404".
    /// </summary>
    [Fact]
    public async Task ManifestGet_LocalMissWithNoUpstreamConfigured_Returns404()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        await EnableAnonymousPullAsync(factory.Services.GetRequiredService<IMetadataStore>());

        using var client = factory.CreateClient();
        var resp = await client.GetAsync($"/v2/library/nothing/manifests/{AbsentDigest}");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    /// <summary>
    /// A configured upstream that cannot be reached is a different claim from "not here": the
    /// content may well exist, this instance just could not go and look right now. That is the one
    /// case where a retryable status is correct — and it must not be a bare 500, which tells the
    /// client nothing about whether retrying is worthwhile.
    /// </summary>
    [Fact]
    public async Task ManifestGet_UpstreamUnreachable_ReturnsRetryableStatus_NotServerError()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await EnableAnonymousPullAsync(store);
        await ConfigureUnreachableOciUpstreamAsync(store);

        using var client = factory.CreateClient();
        var resp = await client.GetAsync($"/v2/library/nothing/manifests/{AbsentDigest}");

        Assert.True(
            resp.StatusCode is HttpStatusCode.BadGateway or HttpStatusCode.ServiceUnavailable
                or HttpStatusCode.NotFound,
            $"an unreachable upstream must not surface as a server fault; got {(int)resp.StatusCode} {resp.StatusCode}");
        Assert.NotEqual(HttpStatusCode.InternalServerError, resp.StatusCode);
    }

    /// <summary>Blob twin of the manifest case — a layer pull must not surface as a server fault either.</summary>
    [Fact]
    public async Task BlobGet_UpstreamUnreachable_ReturnsRetryableStatus_NotServerError()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await EnableAnonymousPullAsync(store);
        await ConfigureUnreachableOciUpstreamAsync(store);

        using var client = factory.CreateClient();
        var resp = await client.GetAsync($"/v2/library/nothing/blobs/{AbsentDigest}");

        Assert.NotEqual(HttpStatusCode.InternalServerError, resp.StatusCode);
        Assert.True(
            resp.StatusCode is HttpStatusCode.BadGateway or HttpStatusCode.ServiceUnavailable
                or HttpStatusCode.NotFound,
            $"an unreachable upstream must not surface as a server fault; got {(int)resp.StatusCode} {resp.StatusCode}");
    }

    /// <summary>
    /// Points the org's OCI upstream at an address that cannot be routed, so the fetch fails at the
    /// transport layer rather than returning an HTTP status.
    /// </summary>
    private static async Task ConfigureUnreachableOciUpstreamAsync(IMetadataStore store)
    {
        await using var conn = await store.OpenAsync();
        await Dapper.SqlMapper.ExecuteAsync(conn,
            """
            INSERT INTO upstream_registry (id, org_id, ecosystem, url, position, auth_type, prefixes)
            SELECT lower(hex(randomblob(16))), id, 'oci', 'https://127.0.0.1:9', 0, 'anonymous', '[""]'
            FROM orgs
            """);
    }

    /// <summary>
    /// Turns on anonymous pull for the default org. The subject of these tests is what the read
    /// surface answers on a miss; the auth gate fires first and would otherwise mask it.
    /// </summary>
    private static async Task EnableAnonymousPullAsync(IMetadataStore store)
    {
        await using var conn = await store.OpenAsync();
        await Dapper.SqlMapper.ExecuteAsync(conn,
            """
            INSERT INTO org_settings (org_id, anonymous_pull)
            SELECT id, 1 FROM orgs
            WHERE true
            ON CONFLICT(org_id) DO UPDATE SET anonymous_pull = 1
            """);
    }

    // ── Private factory ───────────────────────────────────────────────────────

    /// <summary>Minimal air-gapped single-tenant host — the OCI surface is the subject.</summary>
    private sealed class AirGappedOciFactory : WebApplicationFactory<Program>, IAsyncLifetime
    {
        private readonly InMemoryBlobStore _blobStore = new();
        private readonly TestMetadataStore _metadataStore = new();

        protected override IHost CreateHost(IHostBuilder _)
        {
            var builder = WebApplication.CreateBuilder();

            // Pin single mode before ConfigureBuilder so it overrides any ambient DEPLOYMENT_MODE.
            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["DEPLOYMENT_MODE"] = "single",
            });

            Program.ConfigureBuilder(builder);

            builder.Services.RemoveAll<IBlobStore>();
            builder.Services.AddSingleton<IBlobStore>(_blobStore);
            builder.Services.RemoveAll<TieredBlobStorage>();
            builder.Services.AddSingleton(new TieredBlobStorage(_blobStore, _blobStore));
            builder.Services.RemoveAll<IMetadataStore>();
            builder.Services.AddSingleton<IMetadataStore>(_metadataStore);

            builder.WebHost.UseTestServer();
            builder.WebHost.UseSetting("AIR_GAPPED", "true");
            builder.WebHost.UseSetting("OSV_MODE", "local");
            builder.WebHost.UseSetting("DEFAULT_ORG_SLUG", "default");
            builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");
            builder.WebHost.UseSetting("ANON_RATE_LIMIT_PERMITS", "100000");
            builder.WebHost.UseSetting(
                "DISABLE_BACKGROUND_JOBS",
                "vuln-scan,vuln-rescan,threat-feed,deprecation-refresh,license-backfill");

            var app = builder.Build();
            Program.ConfigureApp(app);
            app.Start();
            return app;
        }

        public Task InitializeAsync()
        {
            _ = CreateClient();
            return Task.CompletedTask;
        }

        public Task EnableAnonymousPullAsync() => OciReadMissStatusTests.EnableAnonymousPullAsync(_metadataStore);

        public new async Task DisposeAsync()
        {
            await _metadataStore.DisposeAsync();
            await base.DisposeAsync();
        }
    }
}
