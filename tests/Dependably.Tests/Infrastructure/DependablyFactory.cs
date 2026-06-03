using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using Dapper;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Storage;
using WireMock.Server;

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

    protected override IHost CreateHost(IHostBuilder _)
    {
        var builder = WebApplication.CreateBuilder();

        Program.ConfigureBuilder(builder);

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

        builder.WebHost.UseTestServer();

        builder.WebHost.UseSetting("PyPI:Upstream", MockUpstream.Urls[0]);
        builder.WebHost.UseSetting("Npm:Upstream", MockUpstream.Urls[0]);
        builder.WebHost.UseSetting("NuGet:Upstream", MockUpstream.Urls[0]);
        builder.WebHost.UseSetting("DEFAULT_ORG_SLUG", "default");
        builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");
        // Tests share the factory; the default 10/min login rate limit otherwise leaks
        // across unrelated test classes that exercise /auth/login. Bumping the budget
        // doesn't disable the limiter — tests that need it can still observe its 429.
        builder.WebHost.UseSetting("LOGIN_RATE_LIMIT_PERMITS", "100000");

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
        "pull"      => """["read:artifact","read:metadata"]""",
        "push"      => """["publish:*","read:artifact","read:metadata","yank:*"]""",
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

        var orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");

        var adminId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM users WHERE tenant_id = @orgId AND role = 'owner' LIMIT 1",
            new { orgId })
            ?? throw new InvalidOperationException("Bootstrap owner not found. Was first-boot run?");

        var tokens = Services.GetRequiredService<TokenRepository>();
        var (raw, _) = await tokens.CreateUserTokenAsync(orgId, adminId, CapabilitiesFor("push"), expiresAt: null);
        return raw;
    }

    /// <summary>
    /// Issues a JWT for the seeded bootstrap user (role=owner), suitable for management API calls.
    /// </summary>
    public async Task<string> CreateAdminJwt()
    {
        await using var conn = await _metadataStore.OpenAsync();

        var orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");

        var adminId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM users WHERE tenant_id = @orgId AND role = 'owner' LIMIT 1",
            new { orgId })
            ?? throw new InvalidOperationException("Bootstrap owner not found.");

        var jwtSecret = await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'jwt_secret' LIMIT 1")
            ?? throw new InvalidOperationException("JWT secret not found.");

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
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

        var orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT tenant_id FROM users WHERE id = @userId",
            new { userId })
            ?? throw new InvalidOperationException($"User '{userId}' not found.");

        var jwtSecret = await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'jwt_secret' LIMIT 1")
            ?? throw new InvalidOperationException("JWT secret not found.");

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
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
        var passwordHash = BCrypt.Net.BCrypt.HashPassword(password, workFactor: 4);
        var userId = Guid.NewGuid().ToString("N");

        await using var conn = await _metadataStore.OpenAsync();
        var orgId = await conn.ExecuteScalarAsync<string>(
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
        var key = ecosystem.ToLowerInvariant() switch
        {
            "pypi"  => "max_upload_bytes_pypi",
            "npm"   => "max_upload_bytes_npm",
            "nuget" => "max_upload_bytes_nuget",
            _       => "max_upload_bytes"
        };
        await using var conn = await _metadataStore.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT OR REPLACE INTO instance_settings (key, value) VALUES (@key, @value)",
            new { key, value = bytes.ToString() });
    }

    public async Task SetOrgLimit(string org, string ecosystem, long bytes)
    {
        var col = ecosystem.ToLowerInvariant() switch
        {
            "pypi"  => "max_upload_bytes_pypi",
            "npm"   => "max_upload_bytes_npm",
            "nuget" => "max_upload_bytes_nuget",
            _       => "max_upload_bytes"
        };

        await using var conn = await _metadataStore.OpenAsync();
        var orgId = await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = @slug", new { slug = org })
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
        var token = await CreateToken("push", org);
        var (bytes, sha256) = PyPiFixtures.BuildWheel(name, version);
        var filename = $"{name.Replace('-', '_')}-{version}-py3-none-any.whl";

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

        var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"user:{token}"));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);

        var response = await client.PostAsync("/pypi/legacy/", content);
        response.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// Pushes a synthetic npm package for the given name + version to the default org.
    /// </summary>
    public async Task PushNpmPackage(string name, string version, string org = "default")
    {
        var token = await CreateToken("push", org);
        var body = NpmFixtures.BuildPublishBody(name, version);

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
        var token = await CreateToken("push", org);
        var (bytes, _) = NuGetFixtures.BuildNupkg(id, version);
        var filename = $"{id}.{version}.nupkg";

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
        var orgId = await conn.ExecuteScalarAsync<string>(
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
        var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"user:{token}"));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);
        return client;
    }
}
