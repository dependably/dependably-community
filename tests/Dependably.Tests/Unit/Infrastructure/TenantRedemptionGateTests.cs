using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Redeeming a one-shot credential (accepting an invite, consuming a password-reset link,
/// consuming an email-change link) is the other half of the mint: it is what turns the credential
/// into a user, a password, or an address. A suspension deletes only the pending rows, so a
/// redemption that consumed its row just before the suspension's revoke, and wrote the user-side
/// change just after, would leave that change in place when the tenant is restored. Each
/// redemption therefore re-reads the tenant's status inside the transaction that consumes the
/// row, through <see cref="TenantMintGate"/>, and a refused redemption leaves the credential
/// unconsumed. The tenant is suspended directly in the database after the credential is minted,
/// which is the state a request admitted by the status middleware sees when it reaches the
/// redemption.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TenantRedemptionGateTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public TenantRedemptionGateTests(InMemoryDbFixture fixture) => _fixture = fixture;

    internal sealed record Tenant(string OrgId, string UserId);

    /// <param name="Mint">Issues the credential while the tenant is active and returns its raw token.</param>
    /// <param name="Redeem">Consumes the raw token; true when it was redeemed.</param>
    /// <param name="PendingSql">Counts the tenant's still-unconsumed credentials of this kind.</param>
    internal sealed record Redemption(
        string Name,
        string PendingSql,
        Func<IMetadataStore, Tenant, Task<string>> Mint,
        Func<IMetadataStore, string, Task<bool>> Redeem);

    internal static IReadOnlyList<Redemption> Redemptions { get; } =
    [
        new("invite",
            "SELECT COUNT(*) FROM invites WHERE org_id = @OrgId AND accepted_at IS NULL",
            async (db, t) => (await new InviteRepository(db, TestTime.Frozen())
                .CreateAsync(t.OrgId, $"joiner-{Guid.NewGuid():N}@x.test", t.UserId))!.RawToken,
            async (db, raw) => await new InviteRepository(db, TestTime.Frozen()).AcceptAsync(raw) is not null),
        new("password reset link",
            "SELECT COUNT(*) FROM password_reset_tokens WHERE org_id = @OrgId AND consumed_at IS NULL",
            (db, t) => new PasswordResetTokenRepository(db, TestTime.Frozen()).IssueAsync(t.UserId, t.OrgId),
            async (db, raw) => await new PasswordResetTokenRepository(db, TestTime.Frozen()).ConsumeAsync(raw) is not null),
        new("email change link",
            "SELECT COUNT(*) FROM email_change_tokens WHERE org_id = @OrgId AND consumed_at IS NULL",
            (db, t) => new EmailChangeTokenRepository(db, TestTime.Frozen())
                .IssueAsync(t.UserId, t.OrgId, $"moved-{Guid.NewGuid():N}@x.test"),
            async (db, raw) => await new EmailChangeTokenRepository(db, TestTime.Frozen()).ConsumeAsync(raw) is not null),
    ];

    public static TheoryData<string> RedemptionNames()
    {
        var data = new TheoryData<string>();
        foreach (var r in Redemptions)
        {
            data.Add(r.Name);
        }

        return data;
    }

    private async Task<Tenant> SeedAsync()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"redeem-{Guid.NewGuid():N}");
        string userId = await UserSeeder.InsertAsync(_fixture.Store, orgId, $"u-{Guid.NewGuid():N}@x.test", role: "admin");
        return new Tenant(orgId, userId);
    }

    private async Task SetStatusAsync(string orgId, string status)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync("UPDATE orgs SET status = @status WHERE id = @orgId", new { orgId, status });
    }

    private async Task<long> PendingAsync(Redemption r, Tenant t)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(r.PendingSql, new { t.OrgId });
    }

    [Theory]
    [MemberData(nameof(RedemptionNames))]
    public async Task SuspendedTenant_RefusesTheRedemption_AndLeavesTheCredentialUnconsumed(string name)
    {
        var r = Redemptions.Single(x => x.Name == name);
        var tenant = await SeedAsync();
        string raw = await r.Mint(_fixture.Store, tenant);
        await SetStatusAsync(tenant.OrgId, "suspended");

        var ex = await Assert.ThrowsAsync<TenantNotReadyException>(() => r.Redeem(_fixture.Store, raw));

        Assert.Equal(TenantNotReadyReason.StatusInactive, ex.Reason);
        Assert.Equal(1, await PendingAsync(r, tenant));
    }

    [Theory]
    [MemberData(nameof(RedemptionNames))]
    public async Task ActiveTenant_StillRedeems(string name)
    {
        var r = Redemptions.Single(x => x.Name == name);
        var tenant = await SeedAsync();
        string raw = await r.Mint(_fixture.Store, tenant);

        Assert.True(await r.Redeem(_fixture.Store, raw));
        Assert.Equal(0, await PendingAsync(r, tenant));
    }

    [Theory]
    [MemberData(nameof(RedemptionNames))]
    public async Task ReadOnlyTenant_StillRedeems(string name)
    {
        var r = Redemptions.Single(x => x.Name == name);
        var tenant = await SeedAsync();
        string raw = await r.Mint(_fixture.Store, tenant);
        await SetStatusAsync(tenant.OrgId, "read_only");

        Assert.True(await r.Redeem(_fixture.Store, raw));
        Assert.Equal(0, await PendingAsync(r, tenant));
    }

    [Theory]
    [MemberData(nameof(RedemptionNames))]
    public async Task UnknownToken_IsStillJustNotRedeemed(string name)
    {
        var r = Redemptions.Single(x => x.Name == name);

        Assert.False(await r.Redeem(_fixture.Store, "no-such-token"));
    }

    [Fact]
    public async Task SuspensionOfOneTenant_DoesNotRefuseAnotherTenantsRedemption()
    {
        var r = Redemptions[0];
        var suspended = await SeedAsync();
        var other = await SeedAsync();
        string raw = await r.Mint(_fixture.Store, other);
        await SetStatusAsync(suspended.OrgId, "suspended");

        Assert.True(await r.Redeem(_fixture.Store, raw));
    }
}
