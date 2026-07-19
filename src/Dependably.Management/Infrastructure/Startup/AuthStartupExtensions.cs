using Dependably.Infrastructure.Health;
using Dependably.Infrastructure.Identity;
using Dependably.Infrastructure.Redis;
using Dependably.Security;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using StackExchange.Redis;

namespace Dependably.Infrastructure.Startup;

/// <summary>
/// Management-host authentication wiring layered on top of the Core ApiToken scheme: JWT Bearer
/// (cookie-session) registration with per-request revocation + token-version invalidation, plus the
/// Redis/Data Protection infrastructure for HA deployments. These pull in JwtBearer and the Redis
/// client — the assemblies the edge image excludes — so they live in Dependably.Management.
/// </summary>
public static class AuthStartupExtensions
{
    public static void AddDependablyJwt(this WebApplicationBuilder builder)
    {
        // Owns the live signing key. Singleton: the cache (and its refresh window) is per-process,
        // not per-request.
        builder.Services.AddSingleton<JwtSigningKeyProvider>();

        // Core registers the ApiToken scheme (npm/pypi/nuget clients), authorization, and the
        // capability policy provider/handler — everything a protocol-only host needs. Calling it
        // makes ApiToken the default scheme; the AddAuthentication call below re-asserts JwtBearer
        // as the default for the full management host, so the effective default scheme, challenge
        // behaviour, and [Authorize(AuthenticationSchemes = "Bearer,ApiToken")] semantics are
        // exactly as before the split — JWT (admin path) and API tokens (protocol clients) both
        // authenticate, and anonymous-pull endpoints keep their ResolveTokenAsync flow.
        builder.AddDependablyApiTokenAuth();

        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.Events = new JwtBearerEvents
                {
                    // Read JWT from cookie for UI sessions. An empty token here falls through to
                    // the Authorization header in the handler, which is how API clients present a
                    // session JWT.
                    OnMessageReceived = OnJwtMessageReceivedAsync,
                    // Reject revoked tokens (logged-out sessions) and tenant sessions whose
                    // token_version is stale (invalidated by a password change).
                    OnTokenValidated = OnJwtTokenValidatedAsync,
                };
                // Keep JWT claim names as-is (role, sub, org_id) without mapping to ClaimTypes URIs
                options.MapInboundClaims = false;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero,
                    ValidateIssuerSigningKey = true,
                    // Explicit algorithm allow-list so only HS256 tokens are accepted, matching issuance in LoginService
                    ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
                };
            });

        builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            // Resolve the signing key per validation from JwtSigningKeyProvider instead of copying
            // a fixed key into TokenValidationParameters at startup. Two consequences, both
            // wanted: an operator-rotated jwt_secret is honoured by the running process without a
            // restart (a key captured once at startup would reject every session the login path
            // minted under the new secret, since minting reads the row live); and there is no
            // placeholder key, so a host that has not loaded the secret yet fails validation
            // closed rather than trusting known bytes.
            .Configure<JwtSigningKeyProvider>((options, keys) =>
                options.TokenValidationParameters.IssuerSigningKeyResolver =
                    (_, _, _, _) => keys.CurrentKeys)
            // The bearer handler reads its clock from the same DI TimeProvider that LoginService
            // issues tokens with, so a substituted clock can never split issue and validation time.
            .Configure<TimeProvider>((options, time) => options.TimeProvider = time);

        // Global RouteScopeFilter rejects any /api/v1/ request whose JWT lacks a
        // `scope` claim and pins each scope to its realm: tenant routes require
        // scope=tenant + matching tid, system routes require scope=system + apex.
        builder.Services.AddScoped<RouteScopeFilter>();
        // Forces a user holding a temporary password to rotate it before using the API.
        builder.Services.AddScoped<PasswordRotationGuard>();
        // Forces a user to complete MFA enrollment when the policy requires it.
        builder.Services.AddScoped<MfaEnrollmentGuard>();
    }

    // Sources the session JWT from the UI cookie, then gives the signing-key provider its chance
    // to pick up a secret rotated on another replica before the signature is checked. The refresh
    // is TTL-gated inside the provider, so this costs one DB read per refresh interval per
    // process, not one per request. Skipped when no token is presented: anonymous traffic that
    // trips the handler must not drive DB reads.
    private static async Task OnJwtMessageReceivedAsync(MessageReceivedContext ctx)
    {
        ctx.Token = ctx.Request.Cookies["dependably_session"];

        bool hasToken = !string.IsNullOrEmpty(ctx.Token)
            || !string.IsNullOrEmpty(ctx.Request.Headers.Authorization.ToString());
        if (!hasToken)
        {
            return;
        }

        var keys = ctx.HttpContext.RequestServices.GetRequiredService<JwtSigningKeyProvider>();
        await keys.RefreshIfStaleAsync(ctx.HttpContext.RequestAborted);
    }

    // Validates a JWT after signature verification: checks the jti against the revocation
    // store, then verifies the token_version claim for both tenant and system scope sessions
    // so a password change immediately invalidates all outstanding sessions regardless of
    // which surface issued them.
    private static async Task OnJwtTokenValidatedAsync(TokenValidatedContext ctx)
    {
        string? jti = ctx.Principal?.FindFirst(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti)?.Value;
        if (jti is not null)
        {
            var revocations = ctx.HttpContext.RequestServices.GetRequiredService<JwtRevocationRepository>();
            if (await revocations.IsRevokedAsync(jti))
            {
                ctx.Fail("Token has been revoked.");
                return;
            }
        }

        string? scope = ctx.Principal?.FindFirst("scope")?.Value;
        string? sub = ctx.Principal?.FindFirst(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub)?.Value;

        if (sub is null || (scope != "tenant" && scope != "system"))
        {
            return;
        }

        // Both tenant and system sessions snapshot the issuing user's token_version in the
        // `tver` claim (absent → 1, matching the column default). A password change bumps the
        // stored version, staling every previously issued session. System JWTs carry the tver
        // claim too, defaulting to 1 when absent for back-compat with sessions minted before it existed.
        long claimVersion = long.TryParse(ctx.Principal?.FindFirst("tver")?.Value, out long v) ? v : 1;

        long? current;
        if (scope == "tenant")
        {
            var versions = ctx.HttpContext.RequestServices.GetRequiredService<UserTokenVersionStore>();
            current = await versions.GetCurrentVersionAsync(sub);
        }
        else
        {
            var versions = ctx.HttpContext.RequestServices.GetRequiredService<Dependably.Infrastructure.Identity.SystemAdminTokenVersionStore>();
            current = await versions.GetCurrentVersionAsync(sub);
        }

        if (current is null || claimVersion < current.Value)
        {
            ctx.Fail("Session has been invalidated.");
        }
    }

    // Adds the Redis-backed login / invite / token-create rate-limit policies when a Redis
    // connection string is configured. RedisRateLimitPolicy (which injects IRedisClient) lives in
    // this assembly, so its registration cannot sit in the Core rate-limiter method — Core skips
    // those three policies in Redis mode and this hook supplies them. No-op when Redis is absent
    // (Core registers the in-process variants instead). Uses Configure<RateLimiterOptions> so it
    // adds to the same options instance AddRateLimiter created, after that call has run.
    public static void AddDependablyRedisRateLimitPolicies(this WebApplicationBuilder builder)
    {
        if (string.IsNullOrWhiteSpace(builder.Configuration["REDIS_CONNECTION_STRING"]))
        {
            return;
        }

        builder.Services.Configure<Microsoft.AspNetCore.RateLimiting.RateLimiterOptions>(o =>
        {
            o.AddPolicy<string, RedisRateLimitPolicy>("login");
            o.AddPolicy<string, RedisRateLimitPolicy>("invite");
            o.AddPolicy<string, RedisRateLimitPolicy>("token-create");
        });
    }

    public static void AddDependablyRedisAndDataProtection(this WebApplicationBuilder builder)
    {
        builder.Services.Configure<RedisOptions>(opts =>
        {
            opts.ConnectionString = builder.Configuration["REDIS_CONNECTION_STRING"];
            opts.Password = builder.Configuration["REDIS_PASSWORD"];
            opts.Ssl = bool.TryParse(builder.Configuration["REDIS_SSL"], out bool ssl) && ssl;
            opts.Database = int.TryParse(builder.Configuration["REDIS_DATABASE"], out int db) ? db : 0;
            opts.KeyPrefix = builder.Configuration["REDIS_KEY_PREFIX"] ?? "dependably:";
        });

        string deploymentMode = (builder.Configuration["DEPENDABLY_DEPLOYMENT_MODE"] ?? "standalone").ToLowerInvariant();
        string? redisConnStr = builder.Configuration["REDIS_CONNECTION_STRING"];

        if (deploymentMode == "ha" && string.IsNullOrWhiteSpace(redisConnStr))
        {
            throw new InvalidOperationException(
                "DEPENDABLY_DEPLOYMENT_MODE=ha requires REDIS_CONNECTION_STRING to be set.");
        }

        // HA is multi-replica: SQLite cannot be shared across replicas (its file locking is
        // unsupported over NFS/CIFS and produces write-lock corruption, WAL divergence, and silent
        // data loss). Fail closed here — mirroring the Redis check — rather than boot into the
        // documented-forbidden SQLite+HA configuration with no error. DB_PROVIDER defaults to
        // sqlite when unset, so an operator who sets ha + Redis but leaves the default provider is
        // caught here.
        string dbProvider = (builder.Configuration["DB_PROVIDER"] ?? "sqlite").ToLowerInvariant();
        if (deploymentMode == "ha" && dbProvider != "postgres")
        {
            throw new InvalidOperationException(
                $"DEPENDABLY_DEPLOYMENT_MODE=ha requires DB_PROVIDER=postgres (got "
                + $"'{(string.IsNullOrWhiteSpace(dbProvider) ? "sqlite (default)" : dbProvider)}'). "
                + "SQLite does not support multi-instance access — sharing one database file across "
                + "replicas causes write-lock corruption, WAL divergence, and silent data loss. "
                + "See CONTRIBUTING.md -> High-availability deployment.");
        }

        if (string.IsNullOrWhiteSpace(redisConnStr))
        {
            // Standalone path: in-process distributed lock and SQLite-backed lockout store.
            builder.Services.AddSingleton<IDistributedLock, InProcessDistributedLock>();
            builder.Services.AddSingleton<ILockoutStore, SqliteLockoutStore>();
        }
        else
        {
            ConfigureHaRedisInfra(builder);
            return;
        }

        // Always configure a durable DB-backed DataProtection key ring for standalone deployments
        // so encrypted values (SAML test cookies, future uses) survive process restarts. The ring
        // is cached in-memory by KeyRingProvider once loaded; the DB is written only on key rotation.
        // Security posture: when DEPENDABLY_MASTER_KEY is configured, newly generated key elements
        // are AES-256-GCM-encrypted by EnvelopeXmlEncryptor before storage; pre-existing plaintext
        // elements load unchanged (DataProtection mixed-ring support). Without a KEK the ring is
        // stored as plaintext XML.
        //
        // EnvelopeXmlDecryptor is registered in DI so the DataProtection DI-backed activator
        // can resolve it by type when loading encrypted key elements from the ring.
        builder.Services.AddSingleton<DbXmlRepository>();
        builder.Services.AddTransient<EnvelopeXmlDecryptor>();
        builder.Services.AddDataProtection()
            .SetApplicationName("dependably");
        builder.Services.AddSingleton<IConfigureOptions<KeyManagementOptions>>(sp =>
            new ConfigureOptions<KeyManagementOptions>(opts =>
            {
                opts.XmlRepository = sp.GetRequiredService<DbXmlRepository>();
                var kek = sp.GetRequiredService<IMasterKeyProvider>();
                if (kek.IsConfigured)
                {
                    opts.XmlEncryptor = new EnvelopeXmlEncryptor(kek);
                }
            }));
    }

    // HA path: Redis-backed distributed lock, rate-limit state, and lockout store, plus a
    // Redis-persisted DataProtection key ring (in place of the standalone DB-backed ring).
    private static void ConfigureHaRedisInfra(WebApplicationBuilder builder)
    {
        // Capture the mux reference so Data Protection can use it without BuildServiceProvider().
        ConnectionMultiplexer? capturedMux = null;
        builder.Services.AddSingleton<IConnectionMultiplexer>(sp =>
        {
            var opts = sp.GetRequiredService<IOptions<RedisOptions>>().Value;
            var logger = sp.GetRequiredService<ILogger<IConnectionMultiplexer>>();
            var mux = ConnectionMultiplexer.Connect(opts.BuildConfigurationOptions());
            mux.ConnectionFailed += (_, e) =>
                logger.LogWarning("Redis connection failed: {Endpoint} {FailureType}", e.EndPoint, e.FailureType);
            mux.ConnectionRestored += (_, e) =>
                logger.LogInformation("Redis connection restored: {Endpoint}", e.EndPoint);
            capturedMux = mux;
            return mux;
        });
        builder.Services.AddSingleton<RedisClient>();
        builder.Services.AddSingleton<IRedisClient>(sp => sp.GetRequiredService<RedisClient>());
        // Core's ReadinessAggregator resolves the StackExchange-free IRedisHealthProbe; the same
        // RedisClient singleton implements it, so /ready pings the configured Redis endpoint.
        builder.Services.AddSingleton<IRedisHealthProbe>(sp => sp.GetRequiredService<RedisClient>());
        builder.Services.AddSingleton<IDistributedLock, RedisDistributedLock>();
        builder.Services.AddSingleton<ILockoutStore, RedisLockoutStore>();

        // Func<IDatabase> defers resolution until after DI is built.
        builder.Services.AddDataProtection()
            .SetApplicationName("dependably")
            .PersistKeysToStackExchangeRedis(
                () => capturedMux?.GetDatabase()
                    ?? throw new InvalidOperationException("Redis multiplexer not yet initialized."),
                "DataProtection-Keys");

        // Encrypt newly generated key-ring elements at rest when a KEK is configured.
        // Pre-existing plaintext elements load unchanged (DataProtection mixed-ring support).
        // EnvelopeXmlDecryptor is registered in DI so the DataProtection DI-backed activator
        // can resolve it by type when loading encrypted key elements from the ring.
        builder.Services.AddTransient<EnvelopeXmlDecryptor>();
        builder.Services.AddSingleton<IConfigureOptions<KeyManagementOptions>>(sp =>
            new ConfigureOptions<KeyManagementOptions>(opts =>
            {
                var kek = sp.GetRequiredService<IMasterKeyProvider>();
                if (kek.IsConfigured)
                {
                    opts.XmlEncryptor = new EnvelopeXmlEncryptor(kek);
                }
            }));
    }
}
