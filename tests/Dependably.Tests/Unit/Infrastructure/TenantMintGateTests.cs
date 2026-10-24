using Dapper;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// A credential mint that was admitted by the request-start status check but commits after a
/// suspension has already revoked the tenant's credentials would survive the revoke and work again
/// on restore. Each mint re-reads the tenant's status inside its own transaction
/// (<see cref="TenantMintGate"/>) and refuses with the same <see cref="TenantNotReadyException"/>
/// the lockout response is built from. The tenant is suspended directly in the database here, after
/// the repositories are constructed, which is the state a request that passed the middleware sees
/// when it reaches its INSERT.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TenantMintGateTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public TenantMintGateTests(InMemoryDbFixture fixture) => _fixture = fixture;

    internal sealed record Tenant(string OrgId, string UserId);

    internal sealed record Mint(string Name, string CountSql, Func<IMetadataStore, Tenant, Task> Run);

    internal static IReadOnlyList<Mint> Mints { get; } =
    [
        new("user token", "SELECT COUNT(*) FROM user_tokens WHERE org_id = @OrgId", (db, t) =>
            new TokenRepository(db, TestTime.Frozen()).CreateUserTokenAsync(
                t.OrgId, t.UserId, Capabilities.ReaderCapsCanonicalJson, expiresAt: null)),
        new("service token", "SELECT COUNT(*) FROM service_tokens WHERE org_id = @OrgId", (db, t) =>
            new TokenRepository(db, TestTime.Frozen()).CreateServiceTokenAsync(
                t.OrgId, "ci", Capabilities.ReaderCapsCanonicalJson, expiresAt: null)),
        new("invite", "SELECT COUNT(*) FROM invites WHERE org_id = @OrgId", (db, t) =>
            new InviteRepository(db, TestTime.Frozen()).CreateAsync(t.OrgId, "new@x.test", t.UserId)),
        new("password reset link", "SELECT COUNT(*) FROM password_reset_tokens WHERE org_id = @OrgId", (db, t) =>
            new PasswordResetTokenRepository(db, TestTime.Frozen()).IssueAsync(t.UserId, t.OrgId)),
        new("email change link", "SELECT COUNT(*) FROM email_change_tokens WHERE org_id = @OrgId", (db, t) =>
            new EmailChangeTokenRepository(db, TestTime.Frozen()).IssueAsync(t.UserId, t.OrgId, "moved@x.test")),
        new("trusted device", "SELECT COUNT(*) FROM mfa_trusted_devices WHERE tenant_id = @OrgId", (db, t) =>
            new TrustedDeviceService(db, TestTime.Frozen(), new ConfigurationBuilder().Build())
                .CreateAsync(t.UserId, "tenant", t.OrgId, "agent")),
    ];

    public static TheoryData<string> MintNames()
    {
        var data = new TheoryData<string>();
        foreach (var m in Mints)
        {
            data.Add(m.Name);
        }

        return data;
    }

    private async Task<Tenant> SeedAsync()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"mint-{Guid.NewGuid():N}");
        string userId = await UserSeeder.InsertAsync(_fixture.Store, orgId, $"u-{Guid.NewGuid():N}@x.test", role: "admin");
        return new Tenant(orgId, userId);
    }

    private async Task SetStatusAsync(string orgId, string status)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync("UPDATE orgs SET status = @status WHERE id = @orgId", new { orgId, status });
    }

    private async Task<long> CountAsync(Mint mint, Tenant t)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(mint.CountSql, new { t.OrgId });
    }

    [Theory]
    [MemberData(nameof(MintNames))]
    public async Task SuspendedTenant_RefusesTheMint_AndWritesNothing(string name)
    {
        var mint = Mints.Single(m => m.Name == name);
        var tenant = await SeedAsync();
        await SetStatusAsync(tenant.OrgId, "suspended");

        var ex = await Assert.ThrowsAsync<TenantNotReadyException>(() => mint.Run(_fixture.Store, tenant));

        Assert.Equal(TenantNotReadyReason.StatusInactive, ex.Reason);
        Assert.Equal(0, await CountAsync(mint, tenant));
    }

    [Theory]
    [MemberData(nameof(MintNames))]
    public async Task ActiveTenant_StillMints(string name)
    {
        var mint = Mints.Single(m => m.Name == name);
        var tenant = await SeedAsync();

        await mint.Run(_fixture.Store, tenant);

        Assert.Equal(1, await CountAsync(mint, tenant));
    }

    [Theory]
    [MemberData(nameof(MintNames))]
    public async Task ReadOnlyTenant_StillMints(string name)
    {
        var mint = Mints.Single(m => m.Name == name);
        var tenant = await SeedAsync();
        await SetStatusAsync(tenant.OrgId, "read_only");

        await mint.Run(_fixture.Store, tenant);

        Assert.Equal(1, await CountAsync(mint, tenant));
    }

    [Fact]
    public async Task SoftDeletedTenant_RefusesTheMint_AsNotFound()
    {
        var tenant = await SeedAsync();
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE orgs SET deleted_at = '2026-01-01T00:00:00Z' WHERE id = @orgId", new { orgId = tenant.OrgId });
        }

        var ex = await Assert.ThrowsAsync<TenantNotReadyException>(() => Mints[0].Run(_fixture.Store, tenant));

        Assert.Equal(TenantNotReadyReason.NotFound, ex.Reason);
    }

    [Fact]
    public async Task SuspensionOfOneTenant_DoesNotRefuseAnotherTenantsMint()
    {
        var suspended = await SeedAsync();
        var other = await SeedAsync();
        await SetStatusAsync(suspended.OrgId, "suspended");

        await Mints[0].Run(_fixture.Store, other);

        Assert.Equal(1, await CountAsync(Mints[0], other));
    }
}
