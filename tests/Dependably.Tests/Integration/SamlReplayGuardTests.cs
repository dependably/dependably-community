using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Covers the SAML production-login hardening primitives: the assertion replay guard
/// (<see cref="SamlConfigRepository.TryConsumeAssertionAsync"/>) and the SP-initiated
/// request binding used for InResponseTo (<see cref="SamlConfigRepository.IssuePendingRequestAsync"/>
/// + <see cref="SamlConfigRepository.TryConsumePendingRequestAsync"/>).
///
/// These guards are exercised at the repository layer rather than over HTTP because the
/// controller invokes them only after ITfoxtec has validated the signature/audience/timing —
/// and the suite has no signed-assertion fixture (every ACS test uses garbage payloads that
/// fail validation first). The repository tests pin the one-shot + tenant-isolation semantics
/// the controller relies on; the existing garbage-payload ACS tests cover the wiring regression.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SamlReplayGuardTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public SamlReplayGuardTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private SamlConfigRepository Repo => _factory.Services.GetRequiredService<SamlConfigRepository>();

    private static string NewId() => "_" + Guid.NewGuid().ToString("N");
    private static DateTimeOffset SoonExpiry => DateTimeOffset.UtcNow.AddMinutes(5);

    private async Task<string> DefaultOrgIdAsync()
    {
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        return await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("default org not found");
    }

    private async Task<string> CreateOrgAsync()
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id, slug = "replay-guard-" + id[..8] });
        return id;
    }

    // ── Assertion replay guard ────────────────────────────────────────────────

    [Fact]
    public async Task TryConsumeAssertion_FirstTimeAccepts_ReplayRejected()
    {
        string org = await DefaultOrgIdAsync();
        string assertionId = NewId();

        Assert.True(await Repo.TryConsumeAssertionAsync(org, "https://idp/x", assertionId, SoonExpiry));
        Assert.False(await Repo.TryConsumeAssertionAsync(org, "https://idp/x", assertionId, SoonExpiry));
    }

    [Fact]
    public async Task TryConsumeAssertion_DistinctIds_BothAccepted()
    {
        string org = await DefaultOrgIdAsync();
        Assert.True(await Repo.TryConsumeAssertionAsync(org, null, NewId(), SoonExpiry));
        Assert.True(await Repo.TryConsumeAssertionAsync(org, null, NewId(), SoonExpiry));
    }

    [Fact]
    public async Task TryConsumeAssertion_SameIdDifferentTenant_IndependentlyAccepted()
    {
        string orgA = await DefaultOrgIdAsync();
        string orgB = await CreateOrgAsync();
        string assertionId = NewId();

        Assert.True(await Repo.TryConsumeAssertionAsync(orgA, "idp", assertionId, SoonExpiry));
        // Same assertion id under a different tenant is a different key — accepted.
        Assert.True(await Repo.TryConsumeAssertionAsync(orgB, "idp", assertionId, SoonExpiry));
        // ...but still one-shot within the original tenant.
        Assert.False(await Repo.TryConsumeAssertionAsync(orgA, "idp", assertionId, SoonExpiry));
    }

    [Fact]
    public async Task TryConsumeAssertion_ExpiredEntry_PrunedOnWrite()
    {
        string org = await DefaultOrgIdAsync();
        string assertionId = NewId();

        // Record with an already-past expiry. The next write prunes expired rows before the
        // conflict check, so the id is consumable again — proving the cache self-trims rather
        // than growing unbounded. (Production never reaches here: an assertion past its
        // NotOnOrAfter is rejected by the SAML library before the guard runs.)
        Assert.True(await Repo.TryConsumeAssertionAsync(org, "idp", assertionId, DateTimeOffset.UtcNow.AddSeconds(-1)));
        Assert.True(await Repo.TryConsumeAssertionAsync(org, "idp", assertionId, SoonExpiry));
    }

    // ── SP-initiated request binding (InResponseTo) ───────────────────────────

    [Fact]
    public async Task PendingRequest_IssueThenConsume_OnceOnly()
    {
        string org = await DefaultOrgIdAsync();
        string reqId = NewId();
        await Repo.IssuePendingRequestAsync(reqId, org, DateTimeOffset.UtcNow.AddMinutes(10));

        Assert.True(await Repo.TryConsumePendingRequestAsync(reqId, org));
        Assert.False(await Repo.TryConsumePendingRequestAsync(reqId, org));
    }

    [Fact]
    public async Task PendingRequest_UnknownId_Rejected()
    {
        // Unsolicited / forged InResponseTo: no row was ever issued for it.
        string org = await DefaultOrgIdAsync();
        Assert.False(await Repo.TryConsumePendingRequestAsync(NewId(), org));
    }

    [Fact]
    public async Task PendingRequest_WrongTenant_Rejected()
    {
        string orgA = await DefaultOrgIdAsync();
        string orgB = await CreateOrgAsync();
        string reqId = NewId();
        await Repo.IssuePendingRequestAsync(reqId, orgA, DateTimeOffset.UtcNow.AddMinutes(10));

        Assert.False(await Repo.TryConsumePendingRequestAsync(reqId, orgB));
        Assert.True(await Repo.TryConsumePendingRequestAsync(reqId, orgA));
    }

    [Fact]
    public async Task PendingRequest_Expired_Rejected()
    {
        string org = await DefaultOrgIdAsync();
        string reqId = NewId();
        await Repo.IssuePendingRequestAsync(reqId, org, DateTimeOffset.UtcNow.AddSeconds(-1));
        Assert.False(await Repo.TryConsumePendingRequestAsync(reqId, org));
    }
}
