extern alias edge;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using WireMock.Server;
using EdgeProgram = edge::Program;
using IApplicationBuilder = Microsoft.AspNetCore.Builder.IApplicationBuilder;
using IStartupFilter = Microsoft.AspNetCore.Hosting.IStartupFilter;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Integration-test host bound to the <c>Dependably.Edge</c> composition root's <c>Program</c> —
/// the headless cache-only image. Deliberately a separate factory from <see cref="DependablyFactory"/>
/// (which targets the full <c>Dependably</c> root): the two roots are different assemblies with
/// different DI graphs, and the whole point of the edge tests is to exercise the Edge assembly's
/// own <c>ConfigureBuilder</c>/<c>ConfigureApp</c>, not the full root's. The Edge <c>Program</c> is
/// reached through the <c>edge::</c> extern alias so the global <c>Program</c> type stays the full
/// root's (keeping <see cref="DependablyFactory"/> untouched).
///
/// <para>The edge root always runs in edge mode by construction, so this factory seeds the master
/// URL/token the same way <see cref="DependablyFactory"/> does for its <c>DeploymentMode=edge</c>
/// path, and points the master at this factory's own WireMock server.</para>
/// </summary>
public sealed class EdgeFactory : WebApplicationFactory<EdgeProgram>, IAsyncLifetime
{
    public WireMockServer MockUpstream { get; } = WireMockServer.Start();
    public InMemoryBlobStore BlobStore { get; } = new();

    private readonly TestMetadataStore _metadataStore = new();

    /// <summary>Reuses the full-root factory's default edge reader token so shared fixtures match.</summary>
    public const string DefaultEdgeToken = DependablyFactory.DefaultEdgeToken;

    /// <summary>
    /// The edge reader token presented to the master; seeded into the upstream rows. Defaults to
    /// <see cref="DefaultEdgeToken"/> when unset.
    /// </summary>
    public string? EdgeMasterToken { get; init; }

    /// <summary>
    /// Inbound edge client access token (<c>EDGE_ACCESS_TOKEN</c>). When set, first boot seeds it as
    /// a reader service token and disables anonymous pull; when null, the edge runs anonymous.
    /// </summary>
    public string? EdgeAccessToken { get; init; }

    /// <summary>
    /// Optional Serilog capture sink (registered as <c>ILogEventSink</c>) so a test can assert the
    /// edge anonymous-mode startup warning without a bespoke logging harness.
    /// </summary>
    public Serilog.Core.ILogEventSink? LogSink { get; init; }

    protected override IHost CreateHost(IHostBuilder _)
    {
        var builder = WebApplication.CreateBuilder();

        // The edge root reads DEPLOYMENT_MODE only to reject non-edge tenancy values; it does not
        // decide edginess from it. Pin it to "edge" here so an ambient DEPLOYMENT_MODE OS
        // environment variable (a documented local hazard) cannot trip the startup guard and
        // make the suite non-hermetic. Appended as a config source so it survives the provider
        // reload during Build().
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["DEPLOYMENT_MODE"] = "edge",
            ["EDGE_MASTER_URL"] = MockUpstream.Urls[0],
            ["EDGE_MASTER_TOKEN"] = EdgeMasterToken ?? DefaultEdgeToken,
            ["EDGE_ACCESS_TOKEN"] = EdgeAccessToken,
        });

        EdgeProgram.ConfigureBuilder(builder);

        if (LogSink is not null)
        {
            builder.Services.AddSingleton<Serilog.Core.ILogEventSink>(LogSink);
        }

        // In-memory store swaps, mirroring DependablyFactory: both the legacy IBlobStore and the
        // tiered wrapper must be replaced so tier-aware code lands on the in-memory store.
        builder.Services.RemoveAll<IBlobStore>();
        builder.Services.AddSingleton<IBlobStore>(BlobStore);
        builder.Services.RemoveAll<TieredBlobStorage>();
        builder.Services.AddSingleton(new TieredBlobStorage(BlobStore, BlobStore));

        builder.Services.RemoveAll<IMetadataStore>();
        builder.Services.AddSingleton<IMetadataStore>(_metadataStore);

        // Permissive SSRF wiring so the WireMock master on loopback is reachable (the edge SSRF
        // guard admits only the configured master host — WireMock's 127.0.0.1 would otherwise be
        // blocked at the URL layer; the connect callback would block it at the socket layer).
        builder.Services.RemoveAll<IUpstreamUrlValidator>();
        builder.Services.AddSingleton<IUpstreamUrlValidator, PermissiveUpstreamUrlValidator>();
        builder.Services.RemoveAll<SsrfConnectCallback>();
        builder.Services.AddSingleton(new SsrfConnectCallback(_ => false));

        // TestServer leaves Connection.RemoteIpAddress null; inject loopback so IP-gated endpoints
        // (/version, /metrics) admit the test client under the default allowlist.
        builder.Services.AddSingleton<IStartupFilter, LoopbackRemoteIpFilter>();

        builder.WebHost.UseTestServer();

        builder.WebHost.UseSetting("DEFAULT_ORG_SLUG", "default");
        builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");
        builder.WebHost.UseSetting("ANON_RATE_LIMIT_PERMITS", "100000");
        builder.WebHost.UseSetting("METADATA_RATE_LIMIT_PERMITS", "100000");
        builder.WebHost.UseSetting("DOWNLOAD_RATE_LIMIT_PERMITS", "1000000");

        var app = builder.Build();
        EdgeProgram.ConfigureApp(app);
        app.Start();
        return app;
    }

    public Task InitializeAsync()
    {
        _ = CreateClient();
        return Task.CompletedTask;
    }

    public new async Task DisposeAsync()
    {
        MockUpstream.Stop();
        MockUpstream.Dispose();
        await _metadataStore.DisposeAsync();
        await base.DisposeAsync();
    }

    // Test-fixture shorthand → canonical capabilities JSON (mirrors DependablyFactory).
    private static string CapabilitiesFor(string kind) => kind switch
    {
        "pull" => """["read:artifact","read:metadata"]""",
        "push" => """["publish:*","read:artifact","read:metadata","yank:*"]""",
        _ => throw new ArgumentException($"Unknown test token kind '{kind}'.", nameof(kind))
    };

    /// <summary>
    /// Creates a service token in the seeded edge org (slug <c>default</c>) with capabilities from
    /// the given shorthand (<c>pull</c> / <c>push</c>). A push token lets a request pass the
    /// per-endpoint capability gate and reach the edge publish guard, proving the guard — not an
    /// auth failure — is what returns 405.
    /// </summary>
    public async Task<string> CreateToken(string kind = "push", string org = "default")
    {
        var tokens = Services.GetRequiredService<TokenRepository>();
        var orgs = Services.GetRequiredService<OrgRepository>();
        var orgRecord = await orgs.GetBySlugAsync(org)
            ?? throw new InvalidOperationException($"Org '{org}' not found. Was the edge host started?");
        var (raw, _) = await tokens.CreateServiceTokenAsync(
            orgRecord.Id, $"test-{kind}-{Guid.NewGuid():N}", CapabilitiesFor(kind), expiresAt: null);
        return raw;
    }

    /// <summary>Returns an HttpClient with Bearer token auth pre-configured.</summary>
    public HttpClient CreateClientWithBearer(string token)
    {
        var client = CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    /// <summary>Returns an HttpClient with Basic (user:token) auth pre-configured.</summary>
    public HttpClient CreateClientWithBasic(string token)
    {
        var client = CreateClient();
        string credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"user:{token}"));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);
        return client;
    }

    private sealed class LoopbackRemoteIpFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
            => app =>
            {
                app.Use(async (ctx, n) => { ctx.Connection.RemoteIpAddress = IPAddress.Loopback; await n(); });
                next(app);
            };
    }
}
