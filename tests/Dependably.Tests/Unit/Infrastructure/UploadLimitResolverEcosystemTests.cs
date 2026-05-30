using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Exercises the per-ecosystem resolution arms for the three ecosystems wired in #101
/// (maven, rpm, oci). The existing pypi/npm/nuget arms are covered indirectly through
/// the controllers; this file is intentionally narrow — one assertion per fallback
/// step, run against each new ecosystem.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UploadLimitResolverEcosystemTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly OrgRepository _orgs;
    private readonly OrgSettingsRepository _settings;

    public UploadLimitResolverEcosystemTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _orgs = new OrgRepository(_fixture.Store);
        _settings = new OrgSettingsRepository(_fixture.Store, _orgs);
    }

    private UploadLimitResolver Resolver(long? instanceDefault = null)
    {
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["MAX_UPLOAD_BYTES"] = instanceDefault?.ToString(),
            })
            .Build();
        return new UploadLimitResolver(_orgs, cfg);
    }

    public static TheoryData<string> NewEcosystems => new()
    {
        "maven",
        "rpm",
        "oci",
    };

    [Theory]
    [MemberData(nameof(NewEcosystems))]
    public async Task PerEcoOrgLimit_TakesPrecedence(string ecosystem)
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"per-eco-{ecosystem}-{Guid.NewGuid():N}");
        await _settings.UpsertSettingsAsync(new OrgSettingsUpdate(
            orgId, AnonymousPull: false, AllowlistMode: false,
            MaxUploadBytes: 999_000L,
            MaxUploadBytesPyPi: null, MaxUploadBytesNpm: null, MaxUploadBytesNuGet: null,
            InstanceMaxUploadBytes: null, DefaultLanguage: null,
            MaxUploadBytesMaven: ecosystem == "maven" ? 111L : null,
            MaxUploadBytesRpm:   ecosystem == "rpm"   ? 111L : null,
            MaxUploadBytesOci:   ecosystem == "oci"   ? 111L : null));

        var limit = await Resolver(instanceDefault: 9_999_999L).ResolveAsync(orgId, ecosystem);
        Assert.Equal(111L, limit);
    }

    [Theory]
    [MemberData(nameof(NewEcosystems))]
    public async Task OrgGlobalLimit_FallsThroughWhenPerEcoNull(string ecosystem)
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-global-{ecosystem}-{Guid.NewGuid():N}");
        await _settings.UpsertSettingsAsync(new OrgSettingsUpdate(
            orgId, AnonymousPull: false, AllowlistMode: false,
            MaxUploadBytes: 222L,
            MaxUploadBytesPyPi: null, MaxUploadBytesNpm: null, MaxUploadBytesNuGet: null,
            InstanceMaxUploadBytes: null, DefaultLanguage: null));

        // Instance default higher than org global; Math.Min picks org.
        var limit = await Resolver(instanceDefault: 9_999_999L).ResolveAsync(orgId, ecosystem);
        Assert.Equal(222L, limit);
    }

    [Theory]
    [MemberData(nameof(NewEcosystems))]
    public async Task InstanceDefault_AppliesWhenOrgHasNoLimit(string ecosystem)
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"instance-only-{ecosystem}-{Guid.NewGuid():N}");
        // Seeded settings row exists but has no upload caps set.
        var limit = await Resolver(instanceDefault: 333L).ResolveAsync(orgId, ecosystem);
        Assert.Equal(333L, limit);
    }

    [Theory]
    [MemberData(nameof(NewEcosystems))]
    public async Task Unlimited_WhenNeitherOrgNorInstanceConfigured(string ecosystem)
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"unlimited-{ecosystem}-{Guid.NewGuid():N}");
        var limit = await Resolver(instanceDefault: null).ResolveAsync(orgId, ecosystem);
        Assert.Null(limit);
    }

    [Theory]
    [MemberData(nameof(NewEcosystems))]
    public async Task InstanceCap_TakesMinAgainstOrg(string ecosystem)
    {
        // Org configures a generous global; instance ceiling is lower; resolver picks instance.
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"min-{ecosystem}-{Guid.NewGuid():N}");
        await _settings.UpsertSettingsAsync(new OrgSettingsUpdate(
            orgId, AnonymousPull: false, AllowlistMode: false,
            MaxUploadBytes: 9_999_999L,
            MaxUploadBytesPyPi: null, MaxUploadBytesNpm: null, MaxUploadBytesNuGet: null,
            // UpsertSettingsAsync clamps to InstanceMaxUploadBytes at write time, so we pass null
            // here and rely on the resolver's runtime Math.Min between org global and instance.
            InstanceMaxUploadBytes: null, DefaultLanguage: null));

        var limit = await Resolver(instanceDefault: 500L).ResolveAsync(orgId, ecosystem);
        Assert.Equal(500L, limit);
    }
}
