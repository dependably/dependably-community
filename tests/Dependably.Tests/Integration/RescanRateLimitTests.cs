using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
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
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using IApplicationBuilder = Microsoft.AspNetCore.Builder.IApplicationBuilder;
using IStartupFilter = Microsoft.AspNetCore.Hosting.IStartupFilter;

namespace Dependably.Tests.Integration;

/// <summary>
/// Pins the on-demand vulnerability rescan endpoint's per-caller rate-limit policy.
///
/// <para>
/// The endpoint's own cooldown (<c>RescanCooldown</c> on <c>VulnerabilityController</c>) is
/// per-package: it stops a caller re-scanning the SAME package/version inside an hour, but does
/// nothing to bound a caller fanning out across many DISTINCT packages. Without a dedicated
/// <c>[EnableRateLimiting]</c> policy, that fan-out was bounded only by the generic 300/min
/// management default — enough to drive a large volume of outbound OSV queries. This test fires
/// a burst across distinct packages (so the per-package cooldown never trips for any single
/// call) and asserts the tight per-caller "rescan" ceiling still catches it.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class RescanRateLimitTests
{
    private const int PermitLimit = 3;
    private const int BurstSize = 8;

    [Fact]
    public async Task RescanBurst_AcrossDistinctPackages_ExceedsPerCallerCeiling_Returns429()
    {
        await using var factory = new RescanRateLimitFactory(new Dictionary<string, string>
        {
            ["RESCAN_RATE_LIMIT_PERMITS"] = PermitLimit.ToString(),
        });
        await factory.InitializeAsync();

        for (int i = 0; i < BurstSize; i++)
        {
            await factory.PushNpmPackage($"rescan-rl-pkg-{i}", "1.0.0");
        }

        string jwt = await factory.CreateAdminJwtAsync();
        using var client = factory.CreateClientWithBearer(jwt);

        // Every call targets a DIFFERENT package/version, so the per-package cooldown never
        // trips for any single request — the only thing that can produce a 429 here is the
        // per-caller "rescan" policy.
        var statuses = new List<HttpStatusCode>();
        for (int i = 0; i < BurstSize; i++)
        {
            var resp = await client.PostAsync($"/api/v1/packages/npm/rescan-rl-pkg-{i}/1.0.0/rescan", content: null);
            statuses.Add(resp.StatusCode);
        }

        Assert.Contains(HttpStatusCode.TooManyRequests, statuses);
        // The burst is well past the ceiling and none of it shares a package, so most of the
        // calls before the ceiling trips must have succeeded — proving the 429s are the policy
        // catching a real fan-out, not every call failing for an unrelated reason.
        Assert.Contains(HttpStatusCode.OK, statuses);
    }

    [Fact]
    public async Task RescanBurst_UnderPerCallerCeiling_AcrossDistinctPackages_NeverThrottled()
    {
        // Adversarial twin: proves the 429s above are the ceiling catching a genuine fan-out and
        // not some unrelated failure — a burst that stays under the same ceiling must sail
        // through with no 429 at all.
        await using var factory = new RescanRateLimitFactory(new Dictionary<string, string>
        {
            ["RESCAN_RATE_LIMIT_PERMITS"] = PermitLimit.ToString(),
        });
        await factory.InitializeAsync();

        for (int i = 0; i < PermitLimit; i++)
        {
            await factory.PushNpmPackage($"rescan-rl-under-pkg-{i}", "1.0.0");
        }

        string jwt = await factory.CreateAdminJwtAsync();
        using var client = factory.CreateClientWithBearer(jwt);

        var statuses = new List<HttpStatusCode>();
        for (int i = 0; i < PermitLimit; i++)
        {
            var resp = await client.PostAsync($"/api/v1/packages/npm/rescan-rl-under-pkg-{i}/1.0.0/rescan", content: null);
            statuses.Add(resp.StatusCode);
        }

        Assert.DoesNotContain(HttpStatusCode.TooManyRequests, statuses);
    }

    // ── Private factory ───────────────────────────────────────────────────────

    /// <summary>
    /// Dedicated factory so the rescan limiter runs at a tight, test-controlled ceiling. The
    /// shared <see cref="DependablyFactory"/> raises <c>RESCAN_RATE_LIMIT_PERMITS</c> to six
    /// figures to stop unrelated classes self-throttling, which makes it structurally unable to
    /// observe this behaviour.
    /// </summary>
    private sealed class RescanRateLimitFactory : WebApplicationFactory<Program>, IAsyncLifetime
    {
        private readonly Dictionary<string, string> _settings;
        private readonly TestMetadataStore _metadataStore = new();
        private readonly InMemoryBlobStore _blobStore = new();

        public RescanRateLimitFactory(Dictionary<string, string> settings) => _settings = settings;

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

            // No advisories, always "reached" — the rescan call completes fast and
            // deterministically without ever touching the network.
            builder.Services.RemoveAll<IOsvSource>();
            builder.Services.AddSingleton(TestOsvSource.Create());

            builder.Services.AddSingleton<IStartupFilter, LoopbackStartupFilter>();

            builder.WebHost.UseTestServer();
            // Boots a real host via Program.ConfigureBuilder; disable the background jobs that
            // egress or mutate shared state at boot (see Infrastructure/DependablyFactory.cs for
            // the full rationale). vuln-rescan in particular would otherwise race this test's own
            // on-demand rescans.
            builder.WebHost.UseSetting(
                "DISABLE_BACKGROUND_JOBS",
                "vuln-scan,vuln-rescan,threat-feed,deprecation-refresh,license-backfill,oci-blob-sweep");
            builder.WebHost.UseSetting("DEFAULT_ORG_SLUG", "default");
            builder.WebHost.UseSetting("DEPLOYMENT_MODE", "single");
            builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");
            // Keep every limiter except `rescan` out of the way.
            builder.WebHost.UseSetting("LOGIN_RATE_LIMIT_PERMITS", "100000");
            builder.WebHost.UseSetting("ANON_RATE_LIMIT_PERMITS", "100000");
            builder.WebHost.UseSetting("MANAGEMENT_RATE_LIMIT_PERMITS", "100000");
            builder.WebHost.UseSetting("METADATA_RATE_LIMIT_PERMITS", "100000");
            builder.WebHost.UseSetting("DOWNLOAD_RATE_LIMIT_PERMITS", "100000");
            builder.WebHost.UseSetting("PUSH_RATE_LIMIT_PERMITS", "100000");
            builder.WebHost.UseSetting("IMPORT_RATE_LIMIT_PERMITS", "100000");

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

        public async Task PushNpmPackage(string name, string version)
        {
            var tokens = Services.GetRequiredService<TokenRepository>();
            var orgs = Services.GetRequiredService<OrgRepository>();
            var org = await orgs.GetBySlugAsync("default")
                ?? throw new InvalidOperationException("Default org not found.");
            var (raw, _) = await tokens.CreateServiceTokenAsync(
                org.Id, $"test-push-{Guid.NewGuid():N}",
                """["publish:*","read:artifact","read:metadata","yank:*"]""",
                expiresAt: null);

            using var client = CreateClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", raw);
            string body = NpmFixtures.BuildPublishBody(name, version);
            var resp = await client.PutAsync($"/npm/{name}",
                new StringContent(body, Encoding.UTF8, "application/json"));
            resp.EnsureSuccessStatusCode();

            // Hosted publish runs its own immediate scan and stamps vuln_checked_at
            // (PackagePublishService), which would otherwise trip the endpoint's per-package
            // cooldown on the very first rescan call below and mask the per-caller policy
            // this test targets. Clear it so every rescan call in this class is a fresh,
            // never-scanned version — isolating the per-caller ceiling as the only thing that
            // can produce a 429.
            await using var conn = await _metadataStore.OpenAsync();
            await conn.ExecuteAsync("""
                UPDATE package_versions SET vuln_checked_at = NULL
                WHERE id = (
                    SELECT pv.id FROM package_versions pv
                    JOIN packages p ON p.id = pv.package_id
                    WHERE p.name = @name AND pv.version = @version
                    LIMIT 1)
                """, new { name, version });
        }

        /// <summary>
        /// Mints a session JWT for the first-boot owner, mirroring
        /// <see cref="DependablyFactory.CreateAdminJwt"/> — that helper lives on a sealed class
        /// this test's dedicated host cannot reuse.
        /// </summary>
        public async Task<string> CreateAdminJwtAsync()
        {
            await using var conn = await _metadataStore.OpenAsync();

            string orgId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
                ?? throw new InvalidOperationException("Default org not found.");

            string adminId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM users WHERE tenant_id = @orgId AND role = 'owner' LIMIT 1",
                new { orgId })
                ?? throw new InvalidOperationException("Bootstrap owner not found.");

            await conn.ExecuteAsync(
                "UPDATE users SET must_change_password = 0 WHERE id = @adminId", new { adminId });

            long tokenVersion = await conn.ExecuteScalarAsync<long>(
                "SELECT token_version FROM users WHERE id = @adminId", new { adminId });

            string jwtSecret = await conn.ExecuteScalarAsync<string>(
                "SELECT value FROM instance_settings WHERE key = 'jwt_secret' LIMIT 1")
                ?? throw new InvalidOperationException("JWT secret not found.");

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            // now-ok: mints a JWT the host validates against its (default: real) clock.
            var now = DateTime.UtcNow;

            var token = new JwtSecurityToken(
                issuer: JwtTokenBinding.Issuer,
                audience: JwtTokenBinding.SessionAudience,
                claims:
                [
                    new Claim(JwtRegisteredClaimNames.Sub, adminId),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
                    new Claim("org_id", orgId),
                    new Claim("tid", orgId),
                    new Claim("role", "owner"),
                    new Claim("scope", "tenant"),
                    new Claim("tver", tokenVersion.ToString(System.Globalization.CultureInfo.InvariantCulture)),
                ],
                notBefore: now,
                expires: now.AddHours(8),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public HttpClient CreateClientWithBearer(string jwt)
        {
            var client = CreateClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
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
