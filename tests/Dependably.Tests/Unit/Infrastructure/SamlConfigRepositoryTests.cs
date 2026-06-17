using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.Infrastructure;

[Trait("Category", "Unit")]
public sealed class SamlConfigRepositoryTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly SamlConfigRepository _repo;

    public SamlConfigRepositoryTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _repo = new SamlConfigRepository(_fixture.Store, TestTime.Frozen());
    }

    [Fact]
    public async Task GetAsync_NoConfig_ReturnsNull()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        Assert.Null(await _repo.GetAsync(orgId));
    }

    [Fact]
    public async Task UpsertSettingsAsync_FirstCall_Inserts_SecondCall_Updates_AndDoesNotTouchIdpMetadata()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");

        // Seed metadata first.
        await _repo.UpsertMetadataAsync(orgId, "idp-1", "https://idp/sso", "cert-base64", "<EntityDescriptor/>");

        await _repo.UpsertSettingsAsync(new SamlSettingsUpdate(
            OrgId: orgId, Enabled: true, FormsLoginEnabled: false,
            SpEntityId: "sp-1", NameIdFormat: "emailAddress",
            EmailAttribute: "mail", ButtonLabel: "SSO",
            RoleAttribute: null, RoleMapping: null, DefaultRole: "member"));

        var cfg = (await _repo.GetAsync(orgId))!;
        Assert.True(cfg.Enabled);
        Assert.Equal("sp-1", cfg.SpEntityId);
        // IDP metadata must survive the settings upsert — settings and metadata are written
        // by independent upsert statements with disjoint column sets.
        Assert.Equal("idp-1", cfg.IdpEntityId);
        Assert.Equal("<EntityDescriptor/>", cfg.MetadataXml);
    }

    [Fact]
    public async Task UpsertMetadataAsync_OnConflict_UpdatesAllMetadataFields()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");

        await _repo.UpsertMetadataAsync(orgId, "idp-1", "https://old/sso", "cert-1", "<v1/>");
        await _repo.UpsertMetadataAsync(orgId, "idp-2", "https://new/sso", "cert-2", "<v2/>");

        var cfg = (await _repo.GetAsync(orgId))!;
        Assert.Equal("idp-2", cfg.IdpEntityId);
        Assert.Equal("https://new/sso", cfg.IdpSsoUrl);
        Assert.Equal("cert-2", cfg.IdpSigningCert);
        Assert.Equal("<v2/>", cfg.MetadataXml);
    }

    [Fact]
    public async Task RecordTestSuccessAsync_OnlyUpdatesExistingRow()
    {
        // Existing row case: rows updated to last_test_*; absent case is silently no-op.
        string withConfig = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string withoutConfig = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");

        await _repo.UpsertMetadataAsync(withConfig, "idp", "https://idp", "c", "<x/>");
        await _repo.RecordTestSuccessAsync(withConfig, "admin@example.com", claimsJson: null);
        await _repo.RecordTestSuccessAsync(withoutConfig, "ghost@example.com", claimsJson: null); // safe no-op

        var cfg = (await _repo.GetAsync(withConfig))!;
        Assert.Equal("admin@example.com", cfg.LastTestEmail);
        Assert.NotNull(cfg.LastTestAt);

        Assert.Null(await _repo.GetAsync(withoutConfig));
    }

    [Fact]
    public async Task TestRun_IssueThenConsume_OneShot()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string cid = Guid.NewGuid().ToString("N");

        await _repo.IssueTestRunAsync(cid, orgId, actorId: "actor-1",
            expiresAt: TestTime.KnownNow.AddMinutes(10));

        Assert.True(await _repo.TryConsumeTestRunAsync(cid, orgId));   // first consume succeeds
        Assert.False(await _repo.TryConsumeTestRunAsync(cid, orgId));  // replay rejected
    }

    [Fact]
    public async Task TestRun_ExpiredOrWrongTenant_ConsumeFails()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string otherOrgId = await OrgSeeder.InsertAsync(_fixture.Store, $"other-{Guid.NewGuid():N}");
        string cid = Guid.NewGuid().ToString("N");

        await _repo.IssueTestRunAsync(cid, orgId, null, expiresAt: TestTime.KnownNow.AddMinutes(-1));
        Assert.False(await _repo.TryConsumeTestRunAsync(cid, orgId));      // expired
        Assert.False(await _repo.TryConsumeTestRunAsync(cid, otherOrgId)); // wrong tenant
    }

    [Fact]
    public async Task DeleteAsync_Idempotent()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        await _repo.UpsertMetadataAsync(orgId, "i", "https://i", "c", "<x/>");
        await _repo.DeleteAsync(orgId);
        await _repo.DeleteAsync(orgId);   // no throw on absent row
        Assert.Null(await _repo.GetAsync(orgId));
    }
}
