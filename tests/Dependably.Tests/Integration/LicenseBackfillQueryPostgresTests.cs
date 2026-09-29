using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// The license-backfill keyset query against a live Postgres server. Its first page is read with
/// no cursor, so the timestamp parameter is null; a null <see cref="DateTimeOffset"/> reaches
/// Npgsql untyped, because Dapper binds nulls itself rather than through the registered
/// <c>DateTimeOffsetHandler</c>, and Postgres cannot type a bare <c>$1 IS NULL</c>. It answers
/// <c>42P08: could not determine data type of parameter $1</c>, and on a real host that fault
/// escaped the pass and stopped the application on every boot.
///
/// The SQLite suite cannot see this: SQLite does not type parameters. The integration factories
/// also unregister <c>LicenseBackfillService</c>, so no Postgres run exercised the query before.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class LicenseBackfillQueryPostgresTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    [Fact]
    public async Task First_page_without_a_cursor_and_the_next_page_with_one_both_read()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        var repo = new CacheArtifactRepository(pg.Store);

        var t = TestTime.KnownNow;
        await repo.InsertAsync(Sample("a", t.AddDays(-5)));
        await repo.InsertAsync(Sample("b", t.AddDays(-4)));
        await repo.InsertAsync(Sample("c", t.AddDays(-3)));

        var page1 = await repo.ListNeedingLicenseBackfillAsync(limit: 2);
        Assert.Equal(new[] { "a", "b" }, page1.Select(r => r.Name).ToList());

        var last = page1[^1];
        var page2 = await repo.ListNeedingLicenseBackfillAsync(
            limit: 2, afterFirstCachedAt: last.FirstCachedAt, afterId: last.Id);
        Assert.Equal(new[] { "c" }, page2.Select(r => r.Name).ToList());
    }

    private static CacheArtifact Sample(string name, DateTimeOffset cached) => new()
    {
        Id = Guid.NewGuid().ToString("D"),
        Ecosystem = "npm",
        Name = name,
        Version = "1.0.0",
        Filename = $"{name}-1.0.0.tgz",
        BlobKey = $"proxy/{Guid.NewGuid():N}",
        ContentHash = "sha256:abc",
        SizeBytes = 100,
        FirstCachedAt = cached,
        LastAccessedAt = cached
    };
}
