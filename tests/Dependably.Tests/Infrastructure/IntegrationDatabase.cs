using Dependably.Infrastructure;
using Dependably.Infrastructure.RowLevelSecurity;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Http;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// The metadata database behind one integration test host, chosen by <c>TEST_INTEGRATION_DB</c>
/// (<see cref="DependablyFactory.IntegrationDatabase"/>): an in-memory SQLite store, or a throwaway
/// Postgres database (<see cref="PostgresTestDatabase"/>) with row-level security off or enforced.
/// Every test host factory wires its database through this one type, so no host can quietly stay
/// on SQLite while the suite claims to run on Postgres.
///
/// <para>Use it in three steps around the host build: <see cref="ConfigureBefore"/> before
/// <c>Program.ConfigureBuilder</c>, <see cref="ConfigureServices"/> after it, and
/// <see cref="Start"/> in place of <c>app.Start()</c>. <see cref="HarnessStore"/> is the
/// unrestricted store for the factory's own seeding helpers.</para>
///
/// <para>Being the one seam every host passes through, it also stops the timers that would keep
/// a disposed host reachable — the HttpClient handler expiry and ASP.NET Core's endpoint rate
/// limiter. Without that the suite retains every host it has built and outgrows a CI runner's
/// memory; <c>DependablyFactoryReleaseTests</c> pins it.</para>
/// </summary>
public sealed class IntegrationDatabase(string? mode = null) : IAsyncDisposable
{
    private TestMetadataStore? _sqlite;
    private PostgresTestDatabase? _postgres;
    private IServer? _server;

    public string Mode { get; } = mode ?? DependablyFactory.IntegrationDatabase;

    public bool OnPostgres => Mode != "sqlite";

    /// <summary>Unrestricted store for seeding; available once <see cref="ConfigureBefore"/> has run.</summary>
    public IMetadataStore HarnessStore { get; private set; } = null!;

    /// <summary>Creates the database and points the host's configuration at it.</summary>
    public void ConfigureBefore(WebApplicationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        if (!OnPostgres)
        {
            _sqlite = new TestMetadataStore();
            HarnessStore = _sqlite;
            return;
        }

        _postgres = PostgresTestDatabase.CreateAsync().GetAwaiter().GetResult();
        HarnessStore = new NpgsqlMetadataStore(_postgres.OwnerConnectionString);
        // Appended as a source rather than set through the indexer, so it survives the provider
        // reload during Build() and wins over any ambient environment variable.
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["DB_PROVIDER"] = "postgres",
            ["DB_CONNECTION_STRING"] = _postgres.OwnerConnectionString,
            ["DB_ROW_LEVEL_SECURITY"] = Mode == "postgres-rls" ? "enforce" : "off",
            ["DB_ROW_LEVEL_SECURITY_ROLE"] = _postgres.RlsRole,
        });
    }

    /// <summary>
    /// Replaces the SQLite store the host registered, or on Postgres keeps the production
    /// <see cref="NpgsqlMetadataStore"/> and swaps only the ambient tenant so test-harness access
    /// outside a request is not read as a missing tenant.
    /// </summary>
    public void ConfigureServices(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        // A finite handler lifetime arms an expiry timer per client handler, and the expired
        // handler's cleanup keeps rescheduling while a singleton in the stopped host still holds
        // its HttpClient — rooting the whole host in the timer queue. Test hosts never live long
        // enough for handler rotation to matter.
        services.PostConfigureAll<HttpClientFactoryOptions>(o => o.HandlerLifetime = Timeout.InfiniteTimeSpan);
        if (OnPostgres)
        {
            services.RemoveAll<IAmbientTenantScope>();
            services.AddSingleton<IAmbientTenantScope, HarnessAmbientTenantScope>();
        }
        else
        {
            services.RemoveAll<IMetadataStore>();
            services.AddSingleton<IMetadataStore>(_sqlite!);
        }
    }

    /// <summary>
    /// Starts the host with the test-harness flag cleared: hosted services capture the starting
    /// flow's execution context, and must meet row-level security as they do in production.
    /// </summary>
    public void Start(WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);
        bool harness = TestHarnessDbScope.IsActive;
        TestHarnessDbScope.Clear();
        try
        {
            app.Start();
            _server = app.Services.GetRequiredService<IServer>();
        }
        finally
        {
            if (harness)
            {
                TestHarnessDbScope.Enter();
            }
        }
    }

    /// <summary>
    /// Drops the database and releases the host's endpoint rate limiter
    /// (<see cref="EndpointRateLimiterRelease"/>). Call after the host itself has been disposed.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (_server is not null)
        {
            EndpointRateLimiterRelease.Release(_server);
            _server = null;
        }

        if (_sqlite is not null)
        {
            await _sqlite.DisposeAsync();
        }

        if (_postgres is not null)
        {
            await _postgres.DisposeAsync();
        }
    }
}
