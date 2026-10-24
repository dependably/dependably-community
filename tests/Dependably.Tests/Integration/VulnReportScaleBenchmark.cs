using Xunit.Abstractions;

namespace Dependably.Tests.Integration;

/// <summary>
/// The Postgres half of <see cref="VulnReportScaleTests"/>: seeds about 100,000
/// <c>package_version_vulns</c> rows into live Postgres and prints the report, count and summary
/// timings and query plans. A measurement, not a gate, and it needs a live server, so the
/// <c>Category=Benchmark</c> trait keeps it out of the CI integration jobs. Run it with
/// <c>dotnet test --filter "FullyQualifiedName~VulnReportScaleBenchmark"</c> and
/// <c>TEST_POSTGRES_CONNECTION</c> set.
/// </summary>
[Trait("Category", "Integration")]
[Trait("Category", "Benchmark")]
[Collection("LivePostgres")]
public sealed class VulnReportScaleBenchmark(ITestOutputHelper output)
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException("TEST_POSTGRES_CONNECTION must be set to run the Postgres scale case.");

    [Fact]
    public async Task Postgres_ReportCostAtScale()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new Dependably.Infrastructure.SchemaInitializer(pg.Store).InitializeAsync();
        await new VulnReportScaleTests(output).RunAsync("postgres", pg.Store);
    }
}
