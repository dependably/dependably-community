using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Integration;

/// <summary>
/// Proves the DB_PROVIDER=postgres boot path actually boots against a LIVE Postgres server.
/// <see cref="FirstBootService.RunAsync"/> used to open its serialising transaction with the
/// SQLite-only <c>BEGIN IMMEDIATE</c> statement unconditionally, before checking whether the
/// instance is already bootstrapped. PostgreSQL's <c>BEGIN</c> grammar rejects the IMMEDIATE
/// keyword with a 42601 syntax error, so first boot (and therefore every boot, since
/// StartupService calls this with no catch) never completed on Postgres. This test would fail
/// with a PostgresException on the pre-fix code and passes once the transaction-open path is
/// provider-branched via <see cref="MetadataTransactionExtensions.BeginSerializedAsync"/>.
///
/// Tagged <c>Category=SchemaPostgres</c> like the other live-Postgres suites so it runs only in
/// the dedicated schema-integrity CI job / against a local docker postgres with
/// <c>TEST_POSTGRES_CONNECTION</c> set.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class FirstBootServicePostgresBootTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    private static async Task<NpgsqlMetadataStore> FreshPostgresAsync()
    {
        var store = new NpgsqlMetadataStore(ConnectionString);
        await using var conn = await store.OpenAsync();
        // Pristine slate: drop everything from a prior run so the apply starts from zero.
        await conn.ExecuteAsync("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
        return store;
    }

    private static EnvelopeProtector UnconfiguredEnvelope() =>
        new(new EnvFileMasterKeyProvider(new ConfigurationBuilder().Build()));

    [Fact]
    public async Task RunAsync_LivePostgres_SingleMode_CompletesWithoutSyntaxError()
    {
        var store = await FreshPostgresAsync();
        await new SchemaInitializer(store).InitializeAsync();

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["DEPLOYMENT_MODE"] = "single",
                ["DEFAULT_TENANT_SLUG"] = "pg-boot-test",
                ["FIRST_BOOT_ADMIN_EMAIL"] = "owner@pg-boot.test",
                ["FIRST_BOOT_ADMIN_PASSWORD"] = "BootstrapPass12345",
            })
            .Build();

        var sut = new FirstBootService(
            store, config, NullLogger<FirstBootService>.Instance, UnconfiguredEnvelope(),
            new AdminBootstrapper());

        // Pre-fix: this throws PostgresException (42601 syntax error at or near "IMMEDIATE")
        // because RunAsync opens its serializing transaction with SQLite's BEGIN IMMEDIATE
        // unconditionally, before the "already bootstrapped" check ever runs.
        var ex = await Record.ExceptionAsync(() => sut.RunAsync());
        Assert.Null(ex);

        await using var conn = await store.OpenAsync();
        string? orgSlug = await conn.ExecuteScalarAsync<string>("SELECT slug FROM orgs LIMIT 1");
        Assert.Equal("pg-boot-test", orgSlug);

        long userCount = await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM users");
        Assert.Equal(1, userCount);
    }

    [Fact]
    public async Task RunAsync_LivePostgres_SecondCall_IsNoOpAndDoesNotThrow()
    {
        var store = await FreshPostgresAsync();
        await new SchemaInitializer(store).InitializeAsync();

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["DEPLOYMENT_MODE"] = "single",
            })
            .Build();

        var sut = new FirstBootService(
            store, config, NullLogger<FirstBootService>.Instance, UnconfiguredEnvelope(),
            new AdminBootstrapper());

        await sut.RunAsync();

        // Second call: the instance is already bootstrapped, so RunAsync must roll back and
        // return without reseeding — also exercised through the provider-aware transaction open.
        var ex = await Record.ExceptionAsync(() => sut.RunAsync());
        Assert.Null(ex);

        await using var conn = await store.OpenAsync();
        long orgCount = await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM orgs");
        Assert.Equal(1, orgCount);
    }

    [Fact]
    public async Task BeginSerializedAsync_LivePostgres_OpensTransactionAndCommits()
    {
        // Direct proof for the shared helper used at all three former BEGIN-IMMEDIATE sites
        // (FirstBootService, StartupService's two secret-migration paths, SystemController's
        // tenant-create): on Postgres it must open a plain transaction plus an advisory lock,
        // never the SQLite-only BEGIN IMMEDIATE syntax.
        var store = await FreshPostgresAsync();
        await new SchemaInitializer(store).InitializeAsync();

        await using var conn = await store.OpenAsync();
        var ex = await Record.ExceptionAsync(async () =>
        {
            await conn.BeginSerializedAsync(store.Provider);
            await conn.ExecuteAsync(
                "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
                new { id = "pg-tx-test", slug = "pg-tx-test" });
            await conn.ExecuteAsync("COMMIT");
        });
        Assert.Null(ex);

        long orgCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM orgs WHERE id = @id", new { id = "pg-tx-test" });
        Assert.Equal(1, orgCount);
    }
}
