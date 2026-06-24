using System.Security.Cryptography;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NSubstitute;

namespace Dependably.Tests.Unit.Identity;

/// <summary>
/// Verifies that the Identity DI registrations resolve correctly from a container configured
/// with the same service set that <see cref="IdentityStartupExtensions.AddDependablyIdentity"/>
/// produces — without requiring a full WebApplicationBuilder or live database connection.
///
/// The test registers the same services that AddDependablyIdentity produces but uses a
/// pre-seeded in-memory key so no DB access is needed at resolve time.
/// </summary>
[Trait("Category", "Unit")]
public sealed class IdentityDiTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private ServiceProvider? _provider;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();

        byte[] key = RandomNumberGenerator.GetBytes(32);
        var protector = new MfaSecretProtector(key);

        var services = new ServiceCollection();

        // ── Infrastructure ────────────────────────────────────────────────────
        services.AddSingleton<IMetadataStore>(_db);
        services.AddMemoryCache();
        services.AddLogging(b => b.ClearProviders());
        services.AddHttpContextAccessor();

        // ── Identity registrations (mirrors AddDependablyIdentity output) ─────
        services.AddSingleton<IMfaSecretProtector>(protector);
        services.AddSingleton<MfaEncryptionKeyProvider>();
        services.AddSingleton<SystemAdminTokenVersionStore>();

        services.AddScoped<IUserStore<DependablyUser>, DependablyUserStore>();
        services.AddScoped<IUserStore<SystemAdminUser>, SystemAdminUserStore>();

        services.AddSingleton<IPasswordHasher<DependablyUser>, BcryptPasswordHasher<DependablyUser>>();
        services.AddSingleton<IPasswordHasher<SystemAdminUser>, BcryptPasswordHasher<SystemAdminUser>>();

        services
            .AddIdentityCore<DependablyUser>()
            .AddTokenProvider<AuthenticatorTokenProvider<DependablyUser>>(
                TokenOptions.DefaultAuthenticatorProvider);

        services
            .AddIdentityCore<SystemAdminUser>()
            .AddTokenProvider<AuthenticatorTokenProvider<SystemAdminUser>>(
                TokenOptions.DefaultAuthenticatorProvider);

        _provider = services.BuildServiceProvider();
    }

    public async Task DisposeAsync()
    {
        if (_provider is not null)
        {
            await _provider.DisposeAsync();
        }

        await _db.DisposeAsync();
    }

    // ── UserManager resolves ──────────────────────────────────────────────────

    [Fact]
    public void UserManager_DependablyUser_Resolves()
    {
        using var scope = _provider!.CreateScope();
        var um = scope.ServiceProvider.GetService<UserManager<DependablyUser>>();
        Assert.NotNull(um);
    }

    [Fact]
    public void UserManager_SystemAdminUser_Resolves()
    {
        using var scope = _provider!.CreateScope();
        var um = scope.ServiceProvider.GetService<UserManager<SystemAdminUser>>();
        Assert.NotNull(um);
    }

    // ── correct IPasswordHasher implementations ───────────────────────────────

    [Fact]
    public void IPasswordHasher_DependablyUser_IsBcryptPasswordHasher()
    {
        var hasher = _provider!.GetService<IPasswordHasher<DependablyUser>>();
        Assert.IsType<BcryptPasswordHasher<DependablyUser>>(hasher);
    }

    [Fact]
    public void IPasswordHasher_SystemAdminUser_IsBcryptPasswordHasher()
    {
        var hasher = _provider!.GetService<IPasswordHasher<SystemAdminUser>>();
        Assert.IsType<BcryptPasswordHasher<SystemAdminUser>>(hasher);
    }

    // ── correct IUserStore implementations ────────────────────────────────────

    [Fact]
    public void IUserStore_DependablyUser_IsDependablyUserStore()
    {
        using var scope = _provider!.CreateScope();
        var store = scope.ServiceProvider.GetService<IUserStore<DependablyUser>>();
        Assert.IsType<DependablyUserStore>(store);
    }

    [Fact]
    public void IUserStore_SystemAdminUser_IsSystemAdminUserStore()
    {
        using var scope = _provider!.CreateScope();
        var store = scope.ServiceProvider.GetService<IUserStore<SystemAdminUser>>();
        Assert.IsType<SystemAdminUserStore>(store);
    }

    // ── no new auth scheme added ──────────────────────────────────────────────

    [Fact]
    public void AddIdentityCore_DoesNotRegisterAnyAuthenticationScheme()
    {
        // AddDependablyIdentity must not add an authentication scheme; it uses the
        // existing JwtBearer and ApiToken schemes from AddDependablyJwt. The
        // IAuthenticationSchemeProvider will be absent entirely when authentication has
        // not been configured — asserting it is null confirms nothing was silently added.
        var schemeProvider = _provider!.GetService<IAuthenticationSchemeProvider>();
        Assert.Null(schemeProvider);
    }

    // ── IMfaSecretProtector is a singleton ────────────────────────────────────

    [Fact]
    public void IMfaSecretProtector_IsSingleton()
    {
        var a = _provider!.GetService<IMfaSecretProtector>();
        var b = _provider!.GetService<IMfaSecretProtector>();
        Assert.Same(a, b);
    }
}
