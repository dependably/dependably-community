using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Startup-time JWT key handling. The JwtBearer options ship with an all-zero
/// placeholder signing key; <see cref="StartupService"/> must replace it from
/// instance_settings and must refuse to start (fail closed) when the secret is
/// missing on an already-bootstrapped instance — serving with the placeholder
/// would accept session tokens forged against 32 known zero bytes.
/// </summary>
[Trait("Category", "Unit")]
public sealed class StartupServiceTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly StubJwtOptionsMonitor _jwtOptions = new();

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private StartupService BuildService(IConfiguration? config = null)
    {
        config ??= new ConfigurationBuilder().Build();
        return new StartupService(
            new SchemaInitializer(_db),
            new FirstBootService(_db, config, NullLogger<FirstBootService>.Instance),
            new OrgRepository(_db),
            _jwtOptions,
            config,
            NullLogger<StartupService>.Instance);
    }

    [Fact]
    public async Task StartAsync_FirstBoot_LoadsGeneratedJwtSecretIntoOptions()
    {
        await BuildService().StartAsync(CancellationToken.None);

        var key = _jwtOptions.Get(JwtBearerDefaults.AuthenticationScheme)
            .TokenValidationParameters.IssuerSigningKey;
        var symmetric = Assert.IsType<SymmetricSecurityKey>(key);
        Assert.NotEqual(new byte[32], symmetric.Key);
    }

    [Fact]
    public async Task StartAsync_BootstrappedButJwtSecretMissing_Throws()
    {
        // First boot seeds org + user + jwt_secret …
        await BuildService().StartAsync(CancellationToken.None);

        // … then simulate a partial DB restore: tenant state survives, the
        // instance_settings row carrying the signing secret does not.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("DELETE FROM instance_settings WHERE key = 'jwt_secret'");
        }

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => BuildService().StartAsync(CancellationToken.None));
        Assert.Contains("jwt_secret", ex.Message);
    }

    private sealed class StubJwtOptionsMonitor : IOptionsMonitor<JwtBearerOptions>
    {
        public JwtBearerOptions CurrentValue { get; } = new()
        {
            TokenValidationParameters = new TokenValidationParameters
            {
                // Same all-zero placeholder Program.cs seeds before startup runs.
                IssuerSigningKey = new SymmetricSecurityKey(new byte[32]),
            },
        };

        public JwtBearerOptions Get(string? name) => CurrentValue;

        public IDisposable? OnChange(Action<JwtBearerOptions, string?> listener) => null;
    }
}
