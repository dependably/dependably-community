using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using IApplicationBuilder = Microsoft.AspNetCore.Builder.IApplicationBuilder;
using IStartupFilter = Microsoft.AspNetCore.Hosting.IStartupFilter;

namespace Dependably.Tests.Integration;

/// <summary>
/// Pins the <c>push</c> rate-limit policy's queueing behaviour.
///
/// <para>
/// A publish client bursts structurally rather than abusively: an OCI push spends three
/// push-policy requests per layer (POST to open the upload session, PATCH the chunk, PUT to
/// finalize) and runs several layers concurrently, so a routine multi-layer image crosses a
/// per-second permit ceiling without any client misbehaviour. With no queue, the first request
/// past the ceiling is rejected outright, and because OCI clients do not honour
/// <c>Retry-After</c> on a write, that single 429 aborts the entire push.
/// </para>
///
/// <para>
/// The two tests are a pair and only mean something together. The first asserts a burst past
/// the permit ceiling is absorbed by the queue; the second — the adversarial twin — asserts the
/// same burst against a zero queue really is rejected. Without the twin, the first test would
/// also pass if the burst never exceeded the ceiling at all, which would make it a test of
/// nothing.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class PushRateLimitQueueTests
{
    // Permit ceiling small enough that the burst below decisively exceeds it inside one
    // window, while staying large enough that the queued run drains in a few seconds.
    private const int PermitLimit = 10;

    // Burst size, in the shape a real push produces: three requests per "layer" across
    // several concurrent "layers".
    private const int BurstSize = 30;

    [Fact]
    public async Task PushBurstPastPermitCeiling_WithQueue_IsAbsorbedNotRejected()
    {
        await using var factory = new PushRateLimitFactory(new Dictionary<string, string>
        {
            ["PUSH_RATE_LIMIT_PERMITS"] = PermitLimit.ToString(),
            // PUSH_RATE_LIMIT_QUEUE deliberately unset — this asserts the shipped default
            // queues rather than that some explicitly-configured value does.
        });
        await factory.InitializeAsync();

        var statuses = await FirePushBurstAsync(factory);

        Assert.DoesNotContain(HttpStatusCode.TooManyRequests, statuses);
    }

    [Fact]
    public async Task PushBurstPastPermitCeiling_WithQueueDisabled_IsRejected()
    {
        // Adversarial twin: proves the burst above genuinely exceeds the permit ceiling, so
        // the absence of 429s in the first test is the queue working and not a burst that was
        // always under the limit.
        await using var factory = new PushRateLimitFactory(new Dictionary<string, string>
        {
            ["PUSH_RATE_LIMIT_PERMITS"] = PermitLimit.ToString(),
            ["PUSH_RATE_LIMIT_QUEUE"] = "0",
        });
        await factory.InitializeAsync();

        var statuses = await FirePushBurstAsync(factory);

        Assert.Contains(HttpStatusCode.TooManyRequests, statuses);
    }

    /// <summary>
    /// Fires <see cref="BurstSize"/> concurrent requests at a push-policy route and returns the
    /// status of each. The route is a manifest DELETE against a repository that does not exist:
    /// it carries <c>[EnableRateLimiting("push")]</c>, and it reaches its 404 without opening an
    /// upload session, so the burst exercises the limiter without touching the per-tenant
    /// session cap or leaving staged state behind. Only 429-vs-not is asserted, so the
    /// handler's own status is irrelevant.
    /// </summary>
    private static async Task<IReadOnlyList<HttpStatusCode>> FirePushBurstAsync(
        PushRateLimitFactory factory)
    {
        string token = await factory.CreatePushToken();
        using var client = factory.CreateClientWithBasic(token);

        var inFlight = Enumerable.Range(0, BurstSize)
            .Select(i => client.DeleteAsync($"/v2/itest/no-such-repo-{i}/manifests/v1"))
            .ToArray();

        var responses = await Task.WhenAll(inFlight);
        try
        {
            return responses.Select(r => r.StatusCode).ToArray();
        }
        finally
        {
            foreach (var response in responses)
            {
                response.Dispose();
            }
        }
    }

    // ── Private factory ───────────────────────────────────────────────────────

    /// <summary>
    /// Dedicated factory so the push limiter runs at a tight, test-controlled ceiling. The
    /// shared <see cref="DependablyFactory"/> raises <c>PUSH_RATE_LIMIT_PERMITS</c> to six
    /// figures to stop unrelated classes self-throttling, which makes it structurally unable to
    /// observe this behaviour.
    /// </summary>
    private sealed class PushRateLimitFactory : WebApplicationFactory<Program>, IAsyncLifetime
    {
        private readonly Dictionary<string, string> _settings;
        private readonly TestMetadataStore _metadataStore = new();
        private readonly InMemoryBlobStore _blobStore = new();

        public PushRateLimitFactory(Dictionary<string, string> settings) => _settings = settings;

        protected override IHost CreateHost(IHostBuilder _)
        {
            var builder = WebApplication.CreateBuilder();
            // Pin before ConfigureBuilder: the tenant resolver is selected from
            // DEPLOYMENT_MODE at service-registration time, so a UseSetting after this
            // line is inert. See TestHostEnv.
            TestHostEnv.PinAmbient(builder);
            Program.ConfigureBuilder(builder);

            builder.Services.RemoveAll<IBlobStore>();
            builder.Services.AddSingleton<IBlobStore>(_blobStore);
            builder.Services.RemoveAll<TieredBlobStorage>();
            builder.Services.AddSingleton(new TieredBlobStorage(_blobStore, _blobStore));
            builder.Services.RemoveAll<IMetadataStore>();
            builder.Services.AddSingleton<IMetadataStore>(_metadataStore);

            builder.Services.AddSingleton<IStartupFilter, LoopbackStartupFilter>();

            builder.WebHost.UseTestServer();
            // Boots a real host via Program.ConfigureBuilder; disable the background jobs
            // that egress or mutate shared state at boot (see Infrastructure/DependablyFactory.cs
            // for the full rationale).
            builder.WebHost.UseSetting(
                "DISABLE_BACKGROUND_JOBS",
                "vuln-scan,vuln-rescan,threat-feed,deprecation-refresh,license-backfill,oci-blob-sweep");
            builder.WebHost.UseSetting("DEFAULT_ORG_SLUG", "default");
            // Pinned rather than inherited: an ambient DEPLOYMENT_MODE=multi in the developer's
            // shell otherwise flips the host into subdomain routing, and the bare-host token
            // mint below fails to resolve the default org. What is under test here — the push
            // limiter's queue — is identical in both modes, so pinning removes a source of
            // local-only failure without narrowing coverage.
            builder.WebHost.UseSetting("DEPLOYMENT_MODE", "single");
            builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");
            // Keep every limiter except `push` out of the way.
            builder.WebHost.UseSetting("LOGIN_RATE_LIMIT_PERMITS", "100000");
            builder.WebHost.UseSetting("ANON_RATE_LIMIT_PERMITS", "100000");
            builder.WebHost.UseSetting("MANAGEMENT_RATE_LIMIT_PERMITS", "100000");
            builder.WebHost.UseSetting("METADATA_RATE_LIMIT_PERMITS", "100000");
            builder.WebHost.UseSetting("DOWNLOAD_RATE_LIMIT_PERMITS", "100000");

            foreach (var (key, value) in _settings)
            {
                builder.WebHost.UseSetting(key, value);
            }

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

        public new async Task DisposeAsync()
        {
            await _metadataStore.DisposeAsync();
            await base.DisposeAsync();
        }

        /// <summary>
        /// Mints a token carrying the capabilities an OCI publish client holds. The push
        /// limiter partitions on the validated <c>sub</c> claim, so every request in a burst
        /// from this token lands in one bucket — the same shape as one client pushing an image.
        /// </summary>
        public async Task<string> CreatePushToken()
        {
            var tokens = Services.GetRequiredService<TokenRepository>();
            var orgs = Services.GetRequiredService<OrgRepository>();
            var org = await orgs.GetBySlugAsync("default")
                ?? throw new InvalidOperationException("Default org not found.");
            var (raw, _) = await tokens.CreateServiceTokenAsync(
                org.Id,
                $"test-push-{Guid.NewGuid():N}",
                """["publish:*","read:artifact","read:metadata","yank:*"]""",
                expiresAt: null);
            return raw;
        }

        public HttpClient CreateClientWithBasic(string token)
        {
            var client = CreateClient();
            string encoded = Convert.ToBase64String(
                System.Text.Encoding.UTF8.GetBytes("api:" + token));
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", encoded);
            return client;
        }
    }

    private sealed class LoopbackStartupFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
            => app =>
            {
                app.Use(async (ctx, n) =>
                {
                    ctx.Connection.RemoteIpAddress ??= IPAddress.Loopback;
                    await n();
                });
                next(app);
            };
    }
}
