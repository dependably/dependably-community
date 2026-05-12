using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class ClaimRepositoryTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static ClaimTransition Create(string orgId, string ecosystem, string name, string state, string reason) => new()
    {
        ClaimId = Guid.NewGuid().ToString("D"),
        HistoryId = Guid.NewGuid().ToString("D"),
        OrgId = orgId,
        Ecosystem = ecosystem,
        Name = name,
        PriorState = null,
        NewState = state,
        Reason = reason,
        OccurredAt = DateTimeOffset.UtcNow
    };

    [Fact]
    public async Task ApplyTransition_Create_InsertsClaimAndHistory()
    {
        var repo = new ClaimRepository(_db);
        var tx = Create("o1", "npm", "lodash", ClaimStateMachine.LocalOnly, "internal package");
        await repo.ApplyTransitionAsync(tx);

        var c = await repo.GetAsync("o1", "npm", "lodash");
        Assert.NotNull(c);
        Assert.Equal(ClaimStateMachine.LocalOnly, c!.State);

        await using var conn = await _db.OpenAsync();
        var historyCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM claim_history WHERE claim_id = @id",
            new { id = tx.ClaimId });
        Assert.Equal(1, historyCount);
    }

    [Fact]
    public async Task ApplyTransition_StateChange_UpdatesClaimAndAppendsHistory()
    {
        var repo = new ClaimRepository(_db);
        var create = Create("o1", "npm", "lodash", ClaimStateMachine.LocalOnly, "init");
        await repo.ApplyTransitionAsync(create);

        await repo.ApplyTransitionAsync(new ClaimTransition
        {
            ClaimId = create.ClaimId,
            HistoryId = Guid.NewGuid().ToString("D"),
            OrgId = "o1",
            Ecosystem = "npm",
            Name = "lodash",
            PriorState = ClaimStateMachine.LocalOnly,
            NewState = ClaimStateMachine.Mixed,
            Reason = "want proxy fallback",
            OccurredAt = DateTimeOffset.UtcNow
        });

        var c = await repo.GetAsync("o1", "npm", "lodash");
        Assert.Equal(ClaimStateMachine.Mixed, c!.State);

        await using var conn = await _db.OpenAsync();
        var historyCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM claim_history WHERE claim_id = @id",
            new { id = create.ClaimId });
        Assert.Equal(2, historyCount);
    }

    [Fact]
    public async Task ApplyTransition_Release_SoftDeletesClaim_ButHistoryRemains()
    {
        var repo = new ClaimRepository(_db);
        var create = Create("o1", "npm", "lodash", ClaimStateMachine.LocalOnly, "init");
        await repo.ApplyTransitionAsync(create);

        await repo.ApplyTransitionAsync(new ClaimTransition
        {
            ClaimId = create.ClaimId,
            HistoryId = Guid.NewGuid().ToString("D"),
            OrgId = "o1",
            Ecosystem = "npm",
            Name = "lodash",
            PriorState = ClaimStateMachine.LocalOnly,
            NewState = null,
            Reason = "release",
            OccurredAt = DateTimeOffset.UtcNow
        });

        Assert.Null(await repo.GetAsync("o1", "npm", "lodash"));

        await using var conn = await _db.OpenAsync();
        var historyCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM claim_history WHERE claim_id = @id",
            new { id = create.ClaimId });
        Assert.Equal(2, historyCount);
    }

    [Fact]
    public async Task List_FiltersByEcosystemAndState()
    {
        var repo = new ClaimRepository(_db);
        await repo.ApplyTransitionAsync(Create("o1", "npm", "lodash", ClaimStateMachine.LocalOnly, "n1"));
        await repo.ApplyTransitionAsync(Create("o1", "npm", "react",  ClaimStateMachine.Mixed,     "n2"));
        await repo.ApplyTransitionAsync(Create("o1", "pypi","numpy",  ClaimStateMachine.LocalOnly, "n3"));

        var npmLocal = await repo.ListAsync("o1", ecosystem: "npm", state: ClaimStateMachine.LocalOnly);
        Assert.Single(npmLocal);
        Assert.Equal("lodash", npmLocal[0].Name);
    }

    [Fact]
    public async Task CountLocalVersions_OnlyCountsUploaded()
    {
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO packages (id, org_id, ecosystem, name, purl_name) VALUES ('pk1','o1','npm','lodash','lodash')");
            await conn.ExecuteAsync(
                "INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin) " +
                "VALUES ('pv1','pk1','1.0.0','pkg:npm/lodash@1.0.0','b','proxy')");
            await conn.ExecuteAsync(
                "INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin) " +
                "VALUES ('pv2','pk1','2.0.0','pkg:npm/lodash@2.0.0','b','uploaded')");
            await conn.ExecuteAsync(
                "INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin) " +
                "VALUES ('pv3','pk1','3.0.0','pkg:npm/lodash@3.0.0','b','uploaded')");
        }

        var repo = new ClaimRepository(_db);
        Assert.Equal(2, await repo.CountLocalVersionsAsync("o1", "npm", "lodash"));
    }
}
