using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Covers <see cref="QuarantineRepository.UpsertPendingAsync"/>'s
/// <see cref="QuarantineUpsertResult"/> return value: the three UPSERT outcomes (fresh insert,
/// conflict-refresh of an existing pending row, and a no-op against an already-decided row) each
/// resolve to the correct <c>RowId</c>/<c>Inserted</c> pair. This is what
/// <see cref="Dependably.Protocol.BlockGateService"/> uses to decide whether to raise a
/// quarantine_new alert — only a true fresh insert must raise.
/// </summary>
[Trait("Category", "Unit")]
public sealed class QuarantineUpsertResultTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly QuarantineRepository _repo;

    public QuarantineUpsertResultTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _repo = new QuarantineRepository(_fixture.Store, TimeProvider.System);
    }

    [Fact]
    public async Task FreshInsert_InsertedTrue_RowIdIsNewRow()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"qur-a-{Guid.NewGuid():N}");
        string purl = $"pkg:npm/qur-fresh-{Guid.NewGuid():N}@1.0.0";

        var result = await _repo.UpsertPendingAsync(orgId, "npm", purl, "kev", null, null);

        Assert.True(result.Inserted);
        var entry = await _repo.GetByIdAsync(orgId, result.RowId);
        Assert.NotNull(entry);
        Assert.Equal(purl, entry!.Purl);
        Assert.Equal("pending", entry.State);
    }

    /// <summary>A repeat block on the same purl while still pending refreshes the row — same id, Inserted=false.</summary>
    [Fact]
    public async Task ConflictRefresh_OfPendingRow_InsertedFalse_SameRowId()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"qur-b-{Guid.NewGuid():N}");
        string purl = $"pkg:npm/qur-refresh-{Guid.NewGuid():N}@1.0.0";

        var first = await _repo.UpsertPendingAsync(orgId, "npm", purl, "kev", null, null);
        var second = await _repo.UpsertPendingAsync(orgId, "npm", purl, "malicious", "{\"x\":1}", null);

        Assert.True(first.Inserted);
        Assert.False(second.Inserted);
        Assert.Equal(first.RowId, second.RowId);

        var entry = await _repo.GetByIdAsync(orgId, second.RowId);
        Assert.Equal("malicious", entry!.Gate);
        Assert.Equal("{\"x\":1}", entry.Detail);
    }

    /// <summary>
    /// A block on an already-decided purl is a WHERE-guarded no-op — RETURNING produces zero
    /// rows, so the repository falls back to a direct lookup. Inserted is false; RowId still
    /// resolves to the (untouched, decided) row.
    /// </summary>
    [Fact]
    public async Task NoOp_AgainstDecidedRow_InsertedFalse_ResolvesExistingRowId()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"qur-c-{Guid.NewGuid():N}");
        string purl = $"pkg:npm/qur-decided-{Guid.NewGuid():N}@1.0.0";

        var first = await _repo.UpsertPendingAsync(orgId, "npm", purl, "kev", null, null);
        Assert.True(await _repo.DecideAsync(orgId, first.RowId, "denied", null, null));

        var second = await _repo.UpsertPendingAsync(orgId, "npm", purl, "kev", null, null);

        Assert.False(second.Inserted);
        Assert.Equal(first.RowId, second.RowId);
        var entry = await _repo.GetByIdAsync(orgId, second.RowId);
        Assert.Equal("denied", entry!.State);
    }

    /// <summary>
    /// Purge-then-reblock: deleting the decided row (as PurgeAgedReleaseHoldsAsync does for
    /// release_age) frees the UNIQUE(org_id, purl) slot, so the next block is a genuine fresh
    /// insert with a new row id — Inserted is true again.
    /// </summary>
    [Fact]
    public async Task PurgeThenReblock_ProducesNewRowId_InsertedTrue()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"qur-d-{Guid.NewGuid():N}");
        string purl = $"pkg:npm/qur-purge-{Guid.NewGuid():N}@1.0.0";

        var first = await _repo.UpsertPendingAsync(orgId, "npm", purl, "release_age", null, null);
        // Policy off (null hours) means any pending release_age row is a phantom — deletes it.
        int deleted = await _repo.PurgeAgedReleaseHoldsAsync(orgId, null);
        Assert.Equal(1, deleted);

        var second = await _repo.UpsertPendingAsync(orgId, "npm", purl, "release_age", null, null);

        Assert.True(second.Inserted);
        Assert.NotEqual(first.RowId, second.RowId);
    }
}
