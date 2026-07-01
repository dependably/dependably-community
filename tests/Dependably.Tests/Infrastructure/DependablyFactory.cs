using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using Dapper;
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
using Microsoft.IdentityModel.Tokens;
using WireMock.Server;
using IApplicationBuilder = Microsoft.AspNetCore.Builder.IApplicationBuilder;
using IStartupFilter = Microsoft.AspNetCore.Hosting.IStartupFilter;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Single entry point for all integration and compliance tests.
/// Wires up in-memory SQLite, an in-memory blob store, and a WireMock upstream server.
///
/// Overrides CreateHost() to build the WebApplication directly instead of going through
/// HostFactoryResolver, which silently swallows startup exceptions and prevents TestServer
/// from being initialised.
/// </summary>
public sealed class DependablyFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    public WireMockServer MockUpstream { get; } = WireMockServer.Start();
    public InMemoryBlobStore BlobStore { get; } = new();

    private readonly TestMetadataStore _metadataStore = new();

    /// <summary>
    /// Opt-in frozen host clock. The default stays the system clock because third-party
    /// validators inside the host (ITfoxtec SAML NotOnOrAfter, JwtBearer lifetime checks
    /// on externally minted tokens) compare against real time — freezing the whole host
    /// breaks those flows. Set before the first client is created; tests that freeze the
    /// host control time via this provider.
    /// </summary>
    public Microsoft.Extensions.Time.Testing.FakeTimeProvider? FrozenClock { get; init; }

    /// <summary>
    /// Opt-in override for PROXY_STAGING_PATH. When set, the host resolves staging files
    /// to this directory instead of the OS temp path. Tests that assert staging-file cleanup
    /// set this to a unique per-run directory so file-count checks are isolated.
    /// </summary>
    public string? StagingPath { get; init; }

    /// <summary>
    /// Deployment mode for the test host. Defaults to <c>single</c> so first-boot seeds the
    /// <c>default</c> org that the fixtures assume. Pinned explicitly because the host reads
    /// <c>DEPLOYMENT_MODE</c> from OS environment variables — a value exported for a local debug
    /// instance must not flip the suite into multi-mode (which seeds no default org). Multi-mode
    /// tests set this to <c>multi</c> or <c>header</c>.
    /// </summary>
    public string DeploymentMode { get; init; } = "single";

    /// <summary>
    /// When set (base64 32-byte key), configures <c>DEPENDABLY_MASTER_KEY</c> so instance and
    /// upstream secrets are envelope-encrypted at rest. Null (default) leaves the protector
    /// unconfigured — the standard keyless test host.
    /// </summary>
    public string? MasterKey { get; init; }

    protected override IHost CreateHost(IHostBuilder _)
    {
        var builder = WebApplication.CreateBuilder();

        // Pin the deployment mode BEFORE ConfigureBuilder so it overrides any ambient
        // DEPLOYMENT_MODE OS environment variable (e.g. one exported for a local debug instance).
        // Appended as a configuration source so it wins over the environment-variable provider and
        // survives the provider reload during Build(); a plain indexer set does not. It must precede
        // ConfigureBuilder because the tenant-resolver strategy is selected from DEPLOYMENT_MODE at
        // service-registration time — setting it afterwards leaves the resolver bound to the wrong
        // mode even though first-boot reads the corrected value. Keeps the test host hermetic
        // regardless of the developer's shell.
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["DEPLOYMENT_MODE"] = DeploymentMode,
            // Null entry is treated as absent by IConfiguration, so the protector stays
            // unconfigured unless a test opts in by setting MasterKey.
            ["DEPENDABLY_MASTER_KEY"] = MasterKey,
        });

        Program.ConfigureBuilder(builder);

        if (FrozenClock is not null)
        {
            builder.Services.RemoveAll<TimeProvider>();
            builder.Services.AddSingleton<TimeProvider>(FrozenClock);
        }

        if (StagingPath is not null)
        {
            builder.WebHost.UseSetting("PROXY_STAGING_PATH", StagingPath);
        }

        // Test overrides: replace real stores with in-memory equivalents. Both the legacy
        // IBlobStore registration AND the new TieredBlobStorage registration must be
        // replaced so tier-aware code (UpstreamClient, CacheEvictionService,
        // PackagePublishService) lands on the in-memory store rather than the real backend.
        builder.Services.RemoveAll<IBlobStore>();
        builder.Services.AddSingleton<IBlobStore>(BlobStore);
        builder.Services.RemoveAll<TieredBlobStorage>();
        builder.Services.AddSingleton(new TieredBlobStorage(BlobStore, BlobStore));

        // Remove the SqliteMetadataStore singleton registered inside ConfigureBuilder
        builder.Services.RemoveAll<IMetadataStore>();
        builder.Services.AddSingleton<IMetadataStore>(_metadataStore);

        // Tests point Upstream URLs at the WireMock server on localhost; the production
        // SSRF validator (UpstreamUrlValidator) blocks 127.0.0.0/8. Substitute a permissive
        // validator so MockUpstream is reachable. Production wiring is unaffected.
        builder.Services.RemoveAll<IUpstreamUrlValidator>();
        builder.Services.AddSingleton<IUpstreamUrlValidator, PermissiveUpstreamUrlValidator>();

        // The connect-time SSRF guard (SsrfConnectCallback) also blocks 127.0.0.0/8 at the
        // socket level, which would refuse WireMock on loopback. Swap in a permissive
        // predicate so integration tests connect; production keeps SsrfGuard.IsBlockedIp.
        builder.Services.RemoveAll<SsrfConnectCallback>();
        builder.Services.AddSingleton(new SsrfConnectCallback(_ => false));

        // TestServer does not set Connection.RemoteIpAddress — it stays null. The metrics
        // IP allowlist gate (used by /version, /metrics, and the management OpenAPI docs)
        // treats null as denied. Inject loopback so the default allowlist (127.0.0.1/::1)
        // permits the test client to reach IP-gated endpoints without extra configuration.
        builder.Services.AddSingleton<IStartupFilter, LoopbackRemoteIpFilter>();

        builder.WebHost.UseTestServer();

        builder.WebHost.UseSetting("PyPI:Upstream", MockUpstream.Urls[0]);
        builder.WebHost.UseSetting("Npm:Upstream", MockUpstream.Urls[0]);
        builder.WebHost.UseSetting("NuGet:Upstream", MockUpstream.Urls[0]);
        builder.WebHost.UseSetting("Go:Upstream", MockUpstream.Urls[0]);
        // Go checksum-database passthrough: point the single supported sumdb at the WireMock
        // host so /go/sumdb/{host}/... proxies to the mock. The requested sumdb name in tests is
        // the WireMock host (matched case-insensitively against this value's host).
        builder.WebHost.UseSetting("Go:SumDb", MockUpstream.Urls[0]);
        builder.WebHost.UseSetting("DEFAULT_ORG_SLUG", "default");
        builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");
        // Tests share the factory; the default 10/min login rate limit otherwise leaks
        // across unrelated test classes that exercise /auth/login. Bumping the budget
        // doesn't disable the limiter — tests that need it can still observe its 429.
        builder.WebHost.UseSetting("LOGIN_RATE_LIMIT_PERMITS", "100000");
        // Same for the anonymous-probe limiter: TestServer requests have no remote IP,
        // so every in-fixture request shares one "unknown" partition.
        builder.WebHost.UseSetting("ANON_RATE_LIMIT_PERMITS", "100000");
        // The management GlobalLimiter partitions per token-hash with IP fallback;
        // TestServer requests land in the same "unknown" bucket, so the shared fixture
        // needs a budget high enough for all /api/v1 calls across every test class.
        builder.WebHost.UseSetting("MANAGEMENT_RATE_LIMIT_PERMITS", "100000");
        // Metadata limiter (npm packument, PyPI simple index, NuGet registration GETs)
        // partitions by remote IP; TestServer requests all share the same "unknown" bucket.
        // Bump the budget so unrelated test classes do not exhaust each other's quota.
        // Tests that explicitly exercise the 429 behaviour create a dedicated factory
        // instance with a tight limit.
        builder.WebHost.UseSetting("METADATA_RATE_LIMIT_PERMITS", "100000");
        // Download, push, and import limiters partition by validated principal (sub claim)
        // with IP fallback. TestServer requests from the same authenticated user share one
        // bucket, and the parallel suite fires many requests from a single principal across
        // all test classes. Raise the budgets so the shared fixture does not self-throttle;
        // tests that explicitly exercise 429 behaviour create a dedicated factory instance.
        builder.WebHost.UseSetting("DOWNLOAD_RATE_LIMIT_PERMITS", "1000000");
        builder.WebHost.UseSetting("PUSH_RATE_LIMIT_PERMITS", "1000000");
        builder.WebHost.UseSetting("IMPORT_RATE_LIMIT_PERMITS", "1000000");

        var app = builder.Build();
        Program.ConfigureApp(app);

        app.Start();

        return app;
    }

    // ── IAsyncLifetime ────────────────────────────────────────────────────────

    public Task InitializeAsync()
    {
        // Trigger server startup (schema init + first-boot) eagerly
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

    // ── Token helpers ──────────────────────────────────────────────────────────

    // Test-fixture mapping from shorthand kind → canonical capabilities JSON. Production
    // code never sees these strings; the API requires explicit capability arrays. The
    // shorthand exists purely to keep the ~40 existing test call sites concise.
    private static string CapabilitiesFor(string kind) => kind switch
    {
        "pull" => """["read:artifact","read:metadata"]""",
        "push" => """["publish:*","read:artifact","read:metadata","yank:*"]""",
        "siem:read" => """["read:audit"]""",
        _ => throw new ArgumentException($"Unknown test token kind '{kind}'.", nameof(kind))
    };

    /// <summary>
    /// Creates a service token with capabilities derived from the given test-shorthand kind
    /// (<c>pull</c>, <c>push</c>, or <c>siem:read</c>). Returns the raw token string.
    /// </summary>
    public async Task<string> CreateToken(string kind = "push", string org = "default")
    {
        var tokens = Services.GetRequiredService<TokenRepository>();
        var orgs = Services.GetRequiredService<OrgRepository>();

        var orgRecord = await orgs.GetBySlugAsync(org)
            ?? throw new InvalidOperationException($"Org '{org}' not found. Was the server started?");

        var (raw, _) = await tokens.CreateServiceTokenAsync(
            orgRecord.Id, $"test-{kind}-{Guid.NewGuid():N}", CapabilitiesFor(kind), expiresAt: null);
        return raw;
    }

    /// <summary>
    /// Creates a user token for the seeded bootstrap user (role=owner of the default tenant).
    /// Returns the raw token string (Bearer value).
    /// </summary>
    public async Task<string> CreateAdminToken()
    {
        await using var conn = await _metadataStore.OpenAsync();

        string orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");

        string adminId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM users WHERE tenant_id = @orgId AND role = 'owner' LIMIT 1",
            new { orgId })
            ?? throw new InvalidOperationException("Bootstrap owner not found. Was first-boot run?");

        var tokens = Services.GetRequiredService<TokenRepository>();
        var (raw, _) = await tokens.CreateUserTokenAsync(orgId, adminId, CapabilitiesFor("push"), expiresAt: null);
        return raw;
    }

    /// <summary>
    /// Creates a user token (PAT) for the seeded bootstrap owner with an explicit capabilities
    /// JSON array. Use to exercise capability-gated admin routes under the ApiToken scheme
    /// (the owner role caps are a superset, so any subset narrows cleanly). Returns the raw token.
    /// </summary>
    public async Task<string> CreateAdminUserToken(string capabilitiesJson)
    {
        await using var conn = await _metadataStore.OpenAsync();

        string orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");

        string adminId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM users WHERE tenant_id = @orgId AND role = 'owner' LIMIT 1",
            new { orgId })
            ?? throw new InvalidOperationException("Bootstrap owner not found.");

        // The bootstrap owner is flagged must_change_password; clear it so PasswordRotationGuard
        // doesn't 403 every /api/v1 call this token makes (matches CreateAdminJwt).
        await conn.ExecuteAsync(
            "UPDATE users SET must_change_password = 0 WHERE id = @adminId", new { adminId });

        var tokens = Services.GetRequiredService<TokenRepository>();
        var (raw, _) = await tokens.CreateUserTokenAsync(orgId, adminId, capabilitiesJson, expiresAt: null);
        return raw;
    }

    /// <summary>
    /// Issues a JWT for the seeded bootstrap user (role=owner), suitable for management API calls.
    /// </summary>
    public async Task<string> CreateAdminJwt()
    {
        await using var conn = await _metadataStore.OpenAsync();

        string orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");

        string adminId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM users WHERE tenant_id = @orgId AND role = 'owner' LIMIT 1",
            new { orgId })
            ?? throw new InvalidOperationException("Bootstrap owner not found.");

        // The first-boot owner is flagged must_change_password; this helper hands out a session
        // for an *onboarded* admin, so clear it (PasswordRotationGuard would otherwise 403 every
        // non-allowlisted /api/v1 call made with this token).
        await conn.ExecuteAsync(
            "UPDATE users SET must_change_password = 0 WHERE id = @adminId", new { adminId });

        string jwtSecretStored = await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'jwt_secret' LIMIT 1")
            ?? throw new InvalidOperationException("JWT secret not found.");
        // With a master key configured the secret is envelope-encrypted at rest; decrypt it so the
        // signing key matches what the host validates with. Unprotect passes plaintext through.
        string jwtSecret = MasterKey is null
            ? jwtSecretStored
            : TestEnvelope.Configured(Convert.FromBase64String(MasterKey)).Unprotect(jwtSecretStored);

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        // now-ok: mints a JWT the host validates against its (default: real) clock.
        var now = DateTime.UtcNow;

        var token = new JwtSecurityToken(
            claims: new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, adminId),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
                new Claim("org_id", orgId),
                new Claim("tid", orgId),
                new Claim("role", "owner"),
                new Claim("scope", "tenant"),
            },
            notBefore: now,
            expires: now.AddHours(8),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>
    /// Issues a tenant JWT for an arbitrary <paramref name="userId"/> with the given role.
    /// Use after <see cref="CreateUser"/> to exercise role-specific authorization paths in
    /// management endpoints.
    /// </summary>
    public async Task<string> CreateUserJwt(string userId, string role)
    {
        await using var conn = await _metadataStore.OpenAsync();

        string orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT tenant_id FROM users WHERE id = @userId",
            new { userId })
            ?? throw new InvalidOperationException($"User '{userId}' not found.");

        string jwtSecretStored = await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'jwt_secret' LIMIT 1")
            ?? throw new InvalidOperationException("JWT secret not found.");
        // With a master key configured the secret is envelope-encrypted at rest; decrypt it so the
        // signing key matches what the host validates with. Unprotect passes plaintext through.
        string jwtSecret = MasterKey is null
            ? jwtSecretStored
            : TestEnvelope.Configured(Convert.FromBase64String(MasterKey)).Unprotect(jwtSecretStored);

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        // now-ok: mints a JWT the host validates against its (default: real) clock.
        var now = DateTime.UtcNow;

        var token = new JwtSecurityToken(
            claims: new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
                new Claim("org_id", orgId),
                new Claim("tid", orgId),
                new Claim("role", role),
                new Claim("scope", "tenant"),
            },
            notBefore: now,
            expires: now.AddHours(8),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>
    /// Creates a member user in the default tenant with the given email and password.
    /// Returns the user ID.
    /// </summary>
    public async Task<string> CreateUser(string email, string password, string role = "member")
    {
        string passwordHash = BCrypt.Net.BCrypt.HashPassword(password, workFactor: 4);
        string userId = Guid.NewGuid().ToString("N");

        await using var conn = await _metadataStore.OpenAsync();
        string orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");

        await conn.ExecuteAsync(
            """
            INSERT INTO users (id, tenant_id, email, password_hash, role)
            VALUES (@id, @tenantId, @email, @hash, @role)
            """,
            new { id = userId, tenantId = orgId, email, hash = passwordHash, role });

        return userId;
    }

    // ── Org / limit helpers ───────────────────────────────────────────────────

    public async Task SetInstanceLimit(string ecosystem, long bytes)
    {
        string key = ecosystem.ToLowerInvariant() switch
        {
            "pypi" => "max_upload_bytes_pypi",
            "npm" => "max_upload_bytes_npm",
            "nuget" => "max_upload_bytes_nuget",
            _ => "max_upload_bytes"
        };
        await using var conn = await _metadataStore.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT OR REPLACE INTO instance_settings (key, value) VALUES (@key, @value)",
            new { key, value = bytes.ToString() });
    }

    // bytes = null clears the column back to "no org-level limit" — the seeded state. Tests
    // must restore null (not a large value) or the org tier would shadow the instance tier
    // for every later test sharing the fixture.
    public async Task SetOrgLimit(string org, string ecosystem, long? bytes)
    {
        string col = ecosystem.ToLowerInvariant() switch
        {
            "pypi" => "max_upload_bytes_pypi",
            "npm" => "max_upload_bytes_npm",
            "nuget" => "max_upload_bytes_nuget",
            _ => "max_upload_bytes"
        };

        await using var conn = await _metadataStore.OpenAsync();
        string orgId = await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = @slug", new { slug = org })
            ?? throw new InvalidOperationException($"Org '{org}' not found.");

        await conn.ExecuteAsync(
            $"UPDATE org_settings SET {col} = @bytes WHERE org_id = @orgId",
            new { bytes, orgId });
        // Raw SQL bypass: evict the OrgRepository settings cache so the controller's next
        // read sees the new limit. Production paths go through OrgSettingsRepository which
        // already invalidates; the test helper does direct UPDATE for terseness.
        Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    // ── Package push helpers ──────────────────────────────────────────────────

    /// <summary>
    /// Pushes a synthetic PyPI wheel for the given name + version to the default org.
    /// Uses the twine-compatible multipart/form-data format.
    /// </summary>
    public async Task PushPyPiPackage(string name, string version, string org = "default")
    {
        string token = await CreateToken("push", org);
        var (bytes, sha256) = PyPiFixtures.BuildWheel(name, version);
        string filename = $"{name.Replace('-', '_')}-{version}-py3-none-any.whl";

        using var client = CreateClient();
        using var content = new MultipartFormDataContent();
        content.Add(new StringContent("file_upload"), ":action");
        content.Add(new StringContent("2.1"), "metadata_version");
        content.Add(new StringContent(name), "name");
        content.Add(new StringContent(version), "version");
        content.Add(new StringContent(sha256), "sha256_digest");

        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "content", filename);

        string credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"user:{token}"));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);

        var response = await client.PostAsync("/pypi/legacy/", content);
        response.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// Seeds an explicit 'mixed' claim for (org, ecosystem, name) — the operator opt-in that
    /// lets a hosted name keep merging upstream versions. Without it, a hosted name with no
    /// claim row resolves as implicit local_only (dependency-confusion guard), so tests that
    /// assert hosted+upstream merging must opt in like a real operator would. Pass the name
    /// exactly as the controller resolves it (nuget: lowercased id; pypi: PEP 503-normalized).
    /// </summary>
    public async Task SeedMixedClaim(string ecosystem, string name, string org = "default")
    {
        var orgs = Services.GetRequiredService<OrgRepository>();
        var orgRecord = await orgs.GetBySlugAsync(org)
            ?? throw new InvalidOperationException($"Org '{org}' not found. Was the server started?");
        var repo = Services.GetRequiredService<ClaimRepository>();
        await repo.ApplyTransitionAsync(new ClaimTransition
        {
            ClaimId = Guid.NewGuid().ToString(),
            HistoryId = Guid.NewGuid().ToString(),
            OrgId = orgRecord.Id,
            Ecosystem = ecosystem,
            Name = name,
            PriorState = null,
            NewState = ClaimStateMachine.Mixed,
            Reason = "test: opt in to upstream merging",
            // now-ok: claim-event provenance stamp; no test asserts on this instant.
            OccurredAt = DateTimeOffset.UtcNow,
        });
    }

    /// <summary>
    /// Pushes a synthetic npm package for the given name + version to the default org.
    /// </summary>
    public async Task PushNpmPackage(string name, string version, string org = "default")
    {
        string token = await CreateToken("push", org);
        string body = NpmFixtures.BuildPublishBody(name, version);

        using var client = CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        var response = await client.PutAsync($"/npm/{name}", content);
        response.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// Pushes a synthetic NuGet package for the given id + version to the default org.
    /// </summary>
    public async Task PushNuGetPackage(string id, string version, string org = "default")
    {
        string token = await CreateToken("push", org);
        var (bytes, _) = NuGetFixtures.BuildNupkg(id, version);
        string filename = $"{id}.{version}.nupkg";

        using var client = CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);

        using var content = new MultipartFormDataContent();
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "package", filename);

        var response = await client.PutAsync("/nuget/publish", content);
        response.EnsureSuccessStatusCode();
    }

    // ── Database helpers ──────────────────────────────────────────────────────

    /// <summary>Marks a specific package version as yanked (soft-delete) in the DB.</summary>
    public async Task SetVersionYanked(string org, string ecosystem, string name, string version, string? reason = null)
    {
        await using var conn = await _metadataStore.OpenAsync();
        string orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = @slug", new { slug = org })
            ?? throw new InvalidOperationException($"Org '{org}' not found.");

        await conn.ExecuteAsync(
            """
            UPDATE package_versions SET yanked = 1, yank_reason = @reason
            WHERE id = (
                SELECT pv.id FROM package_versions pv
                JOIN packages p ON p.id = pv.package_id
                WHERE p.org_id = @orgId AND p.ecosystem = @ecosystem
                  AND p.name = @name AND pv.version = @version
                LIMIT 1)
            """,
            new { orgId, ecosystem, name, version, reason });
    }

    /// <summary>
    /// Pushes a synthetic Maven artifact (a minimal JAR-shaped byte sequence) for the given
    /// groupId, artifactId, and version to the default org. Returns the artifact filename.
    /// </summary>
    public async Task<string> PushMavenArtifact(string groupId, string artifactId, string version, string org = "default")
    {
        string token = await CreateToken("push", org);
        // Minimal JAR: two bytes that satisfy the Maven controller (no format validation beyond path).
        byte[] bytes = [0x50, 0x4B]; // PK magic — not a real ZIP but sufficient for storage
        string filename = $"{artifactId}-{version}.jar";
        string groupPath = groupId.Replace('.', '/');
        string path = $"/maven/{groupPath}/{artifactId}/{version}/{filename}";

        using var client = CreateClient();
        string credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"user:{token}"));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);

        using var content = new ByteArrayContent(bytes);
        var response = await client.PutAsync(path, content);
        response.EnsureSuccessStatusCode();

        return filename;
    }

    /// <summary>
    /// Pushes a minimal synthetic RPM to the default org. Returns the NEVRA filename
    /// that the RPM controller stores, which can be used to download the package.
    /// </summary>
    public async Task<string> PushRpmPackage(string org = "default")
    {
        string token = await CreateToken("push", org);
        byte[] bytes = BuildMinimalRpm();

        using var client = CreateClient();
        string credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"user:{token}"));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);

        using var content = new ByteArrayContent(bytes);
        var response = await client.PutAsync("/rpm/upload", content);
        response.EnsureSuccessStatusCode();

        // The NEVRA filename is: {name}-{version}-{release}.{arch}.rpm
        return "testpkg-1.0-1.x86_64.rpm";
    }

    // Builds the minimum valid RPM binary that passes RpmArtifactValidator.Validate:
    // 96-byte lead + signature header intro + padding + main header with mandatory tags.
    private static byte[] BuildMinimalRpm()
    {
        // Lead: 96 bytes, magic at 0-3, major=3 at 4.
        byte[] lead = new byte[96];
        lead[0] = 0xED; lead[1] = 0xAB; lead[2] = 0xEE; lead[3] = 0xDB;
        lead[4] = 3;

        // Signature header intro: magic at 0-3, nindex=0, hsize=0.
        byte[] sig = new byte[16];
        sig[0] = 0x8E; sig[1] = 0xAD; sig[2] = 0xE8; sig[3] = 0x01;
        // nindex at bytes 8-11 = 0, hsize at 12-15 = 0 (already zero).

        // Pad signature header to 8-byte boundary.
        int sigEnd = lead.Length + sig.Length;
        byte[] pad = new byte[(8 - sigEnd % 8) % 8];

        // Main header: intro + mandatory string tags (name=testpkg, version=1.0, release=1, arch=x86_64).
        string[] values = ["testpkg", "1.0", "1", "x86_64"];
        int[] tagIds = [1000, 1001, 1002, 1022]; // NAME, VERSION, RELEASE, ARCH

        // Build the store (null-terminated strings) and index entries.
        var storeList = new List<byte>();
        var indexList = new List<byte>();
        foreach (int i in Enumerable.Range(0, tagIds.Length))
        {
            int offset = storeList.Count;
            byte[] strBytes = System.Text.Encoding.UTF8.GetBytes(values[i]);
            byte[] withNul = new byte[strBytes.Length + 1];
            Buffer.BlockCopy(strBytes, 0, withNul, 0, strBytes.Length);
            storeList.AddRange(withNul);

            // Index entry: tag (4B BE) + type=6 string (4B BE) + offset (4B BE) + count=1 (4B BE).
            byte[] entry = new byte[16];
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(entry.AsSpan(0, 4), tagIds[i]);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(entry.AsSpan(4, 4), 6);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(entry.AsSpan(8, 4), offset);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(entry.AsSpan(12, 4), 1);
            indexList.AddRange(entry);
        }

        byte[] store = storeList.ToArray();
        byte[] index = indexList.ToArray();
        byte[] mainIntro = new byte[16];
        mainIntro[0] = 0x8E; mainIntro[1] = 0xAD; mainIntro[2] = 0xE8; mainIntro[3] = 0x01;
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(mainIntro.AsSpan(8, 4), tagIds.Length);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(mainIntro.AsSpan(12, 4), store.Length);

        // Concatenate all parts.
        int totalLen = lead.Length + sig.Length + pad.Length + mainIntro.Length + index.Length + store.Length;
        byte[] rpm = new byte[totalLen];
        int pos = 0;
        foreach (byte[] part in new[] { lead, sig, pad, mainIntro, index, store })
        {
            Buffer.BlockCopy(part, 0, rpm, pos, part.Length);
            pos += part.Length;
        }
        return rpm;
    }

    // ── Auth header helpers ────────────────────────────────────────────────────

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

    // ── Startup filters ────────────────────────────────────────────────────────

    /// <summary>
    /// Sets <c>Connection.RemoteIpAddress</c> to loopback for every TestServer
    /// request. TestServer leaves it null, which IP-gated endpoints (metrics
    /// allowlist, management OpenAPI docs) treat as denied. Loopback matches the
    /// default allowlist (127.0.0.1/::1) so tests can reach those endpoints
    /// without additional configuration.
    /// </summary>
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
