using System.Security.Claims;
using System.Security.Cryptography;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;
using Dependably.Infrastructure.Sbom;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// <c>GET /api/v1/sbom-signing-key</c> carries the three-value <c>dependably:signature-state</c>
/// vocabulary through to the Settings surface (ADR-sbom-author-signature, "Publishing the
/// verification key" — "the settings surface says whether the org has a signing key at all"),
/// so the panel can tell "this org has never had a key" from "this org has a key this replica
/// cannot read right now" instead of collapsing both into one empty panel.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomSigningKeyControllerTests : IAsyncLifetime
{
    private readonly InMemoryDbFixture _fixture = new();
    private readonly Microsoft.Extensions.Time.Testing.FakeTimeProvider _clock = TestTime.Frozen();

    private string _orgId = "";
    private string _ownerId = "";

    public async Task InitializeAsync()
    {
        await _fixture.InitializeAsync();
        _orgId = await OrgSeeder.InsertAsync(_fixture.Store, "acme");
        _ownerId = await UserSeeder.InsertAsync(_fixture.Store, _orgId, "owner@acme.test", "owner");
    }

    public async Task DisposeAsync() => await _fixture.DisposeAsync();

    [Fact]
    public async Task Get_WithAMasterKey_ReturnsSignedStateAndTheActiveKey()
    {
        var controller = Build(Repo(configured: true));

        var result = await controller.Get(CancellationToken.None);

        var view = Assert.IsType<SbomSigningKeyController.SbomActiveKeyView>(Assert.IsType<OkObjectResult>(result).Value);
        Assert.Equal(SbomAuthorSigner.SignedState, view.State);
        Assert.True(view.CanSign);
        Assert.True(view.Exists);
        Assert.NotNull(view.KeyId);
        Assert.NotNull(view.PublicKeyPem);
    }

    [Fact]
    public async Task Get_NoMasterKeyEverConfigured_ReturnsUnsignedNoMasterKeyState()
    {
        var controller = Build(Repo(configured: false));

        var result = await controller.Get(CancellationToken.None);

        var view = Assert.IsType<SbomSigningKeyController.SbomActiveKeyView>(Assert.IsType<OkObjectResult>(result).Value);
        Assert.Equal(SbomAuthorSigner.UnsignedNoMasterKeyState, view.State);
        Assert.False(view.CanSign);
        Assert.False(view.Exists);
    }

    /// <summary>
    /// The mixed-fleet case: another replica (a configured repository sharing the same database)
    /// already minted the org's active key, but THIS replica's repository has no master key. The
    /// view must say <c>unsigned-key-unavailable</c>, never <c>unsigned-no-master-key</c> — the
    /// latter is false here and is exactly the statement the ADR's backend fix removed from the
    /// exported document; the Settings panel must not reintroduce it.
    ///
    /// Mutant: revert <see cref="SbomSigningKeyController.Get"/> to call
    /// <c>_keys.GetOrCreateAsync</c> directly and short-circuit on <c>_keys.CanSign</c> alone
    /// (the pre-fix shape) — this test goes red because that shape returns
    /// <c>unsigned-no-master-key</c> here whether or not the org has an active key elsewhere.
    /// </summary>
    [Fact]
    public async Task Get_OrgHasAnActiveKeyOnAnotherReplica_ReturnsUnsignedKeyUnavailableState()
    {
        var otherReplicaKeys = Repo(configured: true);
        var (seededKey, seededState, _) = await new SbomAuthorSigner(otherReplicaKeys).ResolveAsync(_orgId, CancellationToken.None);
        using (seededKey)
        {
            Assert.Equal(SbomAuthorSigner.SignedState, seededState);
        }

        var controller = Build(Repo(configured: false));

        var result = await controller.Get(CancellationToken.None);

        var view = Assert.IsType<SbomSigningKeyController.SbomActiveKeyView>(Assert.IsType<OkObjectResult>(result).Value);
        Assert.Equal(SbomAuthorSigner.UnsignedKeyUnavailableState, view.State);
        Assert.False(view.CanSign);
        Assert.False(view.Exists);
    }

    private SbomSigningKeyRepository Repo(bool configured)
    {
        var builder = new ConfigurationBuilder();
        if (configured)
        {
            builder.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["DEPENDABLY_MASTER_KEY"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            });
        }

        var protector = new EnvelopeProtector(new EnvFileMasterKeyProvider(builder.Build()));
        return new SbomSigningKeyRepository(_fixture.Store, protector, _clock, TestEdgeMode.Disabled());
    }

    private SbomSigningKeyController Build(SbomSigningKeyRepository keys)
    {
        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("acme.example.test");
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(_orgId, "acme");
        http.User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, _ownerId),
                new Claim("sub", _ownerId),
                new Claim("org_id", _orgId),
                new Claim("tid", _orgId),
                new Claim("role", "owner"),
                new Claim("scope", "tenant"),
            ],
            authenticationType: "test"));

        return new SbomSigningKeyController(
            keys, new SbomAuthorSigner(keys), new OrgAccessGuard(_fixture.Store, TestProblems.Create()), new AuditRepository(_fixture.Store, time: _clock))
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }
}
