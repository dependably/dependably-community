using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
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
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end regression test for the PyPI <c>/packages/{file}</c> download path when the
/// org's configured upstream is SSRF-blocked: before the fix, the simple-index resolution
/// step (<c>PyPiProxyFetcher.ResolveUpstreamPyPiUrlAsync</c>) had no local catch for
/// <see cref="SsrfBlockedException"/>, so the exception escaped uncaught to the framework and
/// surfaced as an unhandled <c>500</c>. <see cref="SsrfBlockedExceptionMiddleware"/> now maps
/// it to a deterministic <c>502</c> problem-JSON response — the same clean-refusal contract
/// <c>/simple/</c> already gives (it swallows the same exception and falls back to a
/// local-only listing / 404).
///
/// This test fails on the pre-fix code (500, no middleware registered) and passes after the
/// fix (502, RFC 7807 problem+json body).
/// </summary>
[Trait("Category", "Integration")]
public sealed class SsrfBlockedDownloadPathTests : IAsyncLifetime
{
    private WireMockServer? _mock;
    private BlockingFactory? _factory;

    public Task InitializeAsync()
    {
        _mock = WireMockServer.Start();
        // The simple-index endpoint answers 404 whenever the validator lets a request through
        // (the "not blocked" control scenario) — an ordinary "package not found upstream"
        // outcome distinct from an SSRF refusal. PEP 503 normalizes the wheel's underscored
        // distribution name (ssrf_not_blocked_pkg) to hyphenated form for the index path.
        _mock.Given(Request.Create().WithPath("/simple/ssrf-not-blocked-pkg/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.NotFound));
        _factory = new BlockingFactory(_mock);
        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        if (_factory is not null)
        {
            await _factory.DisposeAsync();
        }
        _mock?.Stop();
        _mock?.Dispose();
    }

    [Fact]
    public async Task DownloadPackage_UpstreamSsrfBlocked_Returns502NotFive00()
    {
        using var bootClient = _factory!.CreateClient();
        await bootClient.GetAsync("/health");

        // Every URL the validator sees (the simple-index lookup that precedes the cached-blob
        // fetch) is treated as SSRF-blocked — simulating an org upstream that was reconfigured
        // (or DNS-rebound) to a private/link-local/metadata address.
        _factory.BlockingValidator.BlockAll = true;

        string token = await CreateTokenAsync("read:artifact", "read:metadata");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"user:{token}")));

        var resp = await client.GetAsync("/packages/ssrf_blocked_pkg-1.0.0-py3-none-any.whl");

        Assert.Equal(HttpStatusCode.BadGateway, resp.StatusCode);
        Assert.Equal("application/problem+json", resp.Content.Headers.ContentType?.MediaType);

        string body = await resp.Content.ReadAsStringAsync();
        Assert.Contains("Upstream fetch blocked", body);
    }

    [Fact]
    public async Task DownloadPackage_UpstreamNotBlocked_ProceedsPastResolution()
    {
        // Mixed partial-failure control: with the validator NOT blocking, the same request
        // proceeds past URL resolution (into an ordinary upstream-unreachable 404, since no
        // real upstream answers) — proving the 502 above is specific to the SSRF block, not a
        // side effect of the test harness itself.
        using var bootClient = _factory!.CreateClient();
        await bootClient.GetAsync("/health");

        _factory.BlockingValidator.BlockAll = false;

        string token = await CreateTokenAsync("read:artifact", "read:metadata");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"user:{token}")));

        var resp = await client.GetAsync("/packages/ssrf_not_blocked_pkg-1.0.0-py3-none-any.whl");

        // The simple-index lookup reaches WireMock (404: package unknown upstream), so
        // resolution returns null and the download handler answers a plain 404 — never the
        // 502/500 the blocked scenario produces.
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    private async Task<string> CreateTokenAsync(params string[] capabilities)
    {
        var db = _factory!.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        string orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");

        var tokens = _factory.Services.GetRequiredService<TokenRepository>();
        string capsJson = "[" + string.Join(",", capabilities.Select(c => $"\"{c}\"")) + "]";
        var (raw, _) = await tokens.CreateServiceTokenAsync(
            orgId, $"test-ssrf-{Guid.NewGuid():N}", capsJson, expiresAt: null);
        return raw;
    }

    // ── inner factory ─────────────────────────────────────────────────────────

    /// <summary>
    /// Minimal factory that wires the real production DI graph (matching
    /// <c>SsrfRedirectHandlerWiringTests.BlockingFactory</c>) but substitutes a
    /// <see cref="ToggleableBlockingValidator"/> so this test can force every upstream URL
    /// check to fail closed, driving <see cref="SsrfBlockedException"/> through the real
    /// PyPI proxy-fetch pipeline exactly as a live SSRF block would.
    /// </summary>
    private sealed class BlockingFactory : WebApplicationFactory<Program>
    {
        public ToggleableBlockingValidator BlockingValidator { get; } = new();

        private readonly WireMockServer _mock;

        public BlockingFactory(WireMockServer mock) => _mock = mock;

        protected override IHost CreateHost(IHostBuilder _)
        {
            var builder = WebApplication.CreateBuilder();

            // Pin single-org mode BEFORE ConfigureBuilder — an ambient DEPLOYMENT_MODE=multi
            // exported for a developer's local instance otherwise flips this host into multi-org
            // mode, which seeds no default org and makes every "default" org lookup below fail.
            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["DEPLOYMENT_MODE"] = "single",
            });

            Program.ConfigureBuilder(builder);

            var inMemBlob = new InMemoryBlobStore();
            builder.Services.RemoveAll<IBlobStore>();
            builder.Services.AddSingleton<IBlobStore>(inMemBlob);
            builder.Services.RemoveAll<TieredBlobStorage>();
            builder.Services.AddSingleton(new TieredBlobStorage(inMemBlob, inMemBlob));

            var metaStore = new TestMetadataStore();
            builder.Services.RemoveAll<IMetadataStore>();
            builder.Services.AddSingleton<IMetadataStore>(metaStore);

            builder.Services.RemoveAll<IUpstreamUrlValidator>();
            builder.Services.AddSingleton<IUpstreamUrlValidator>(BlockingValidator);

            // The connect-time callback is never reached in this test — the validator denies
            // every URL before any socket is opened — but is kept permissive to match the
            // real production wiring pattern used elsewhere for this style of test host.
            builder.Services.RemoveAll<SsrfConnectCallback>();
            builder.Services.AddSingleton(new SsrfConnectCallback(_ => false));

            builder.WebHost.UseTestServer();
            // Boots a real host via Program.ConfigureBuilder; disable the background jobs
            // that egress or mutate shared state at boot (see Infrastructure/DependablyFactory.cs
            // for the full rationale).
            builder.WebHost.UseSetting(
                "DISABLE_BACKGROUND_JOBS",
                "vuln-scan,vuln-rescan,threat-feed,deprecation-refresh,license-backfill");
            builder.WebHost.UseSetting("DEFAULT_ORG_SLUG", "default");
            builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");
            // UpstreamRegistrySeeder seeds this as the default org's pypi upstream_registry row
            // at first boot. When the validator blocks (BlockAll=true) it is never dereferenced;
            // when it doesn't, the simple-index request reaches this WireMock instance.
            builder.WebHost.UseSetting("PyPI:Upstream", _mock.Urls[0]);

            var app = builder.Build();
            Program.ConfigureApp(app);
            app.Start();
            return app;
        }
    }

    /// <summary>
    /// Validator whose block decision flips at runtime via <see cref="BlockAll"/> — lets one
    /// factory instance drive both the blocked and not-blocked halves of the mixed scenario
    /// without rebuilding the host.
    /// </summary>
    private sealed class ToggleableBlockingValidator : IUpstreamUrlValidator
    {
        public bool BlockAll { get; set; }

        public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId, CancellationToken ct = default) =>
            Task.FromResult(BlockAll ? UpstreamUrlBlock.BlockedRange : UpstreamUrlBlock.None);
    }
}
