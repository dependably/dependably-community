using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;
using Dependably.Infrastructure.Sbom;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// The per-org SBOM signing key: created once on first use, rotated by retiring (never deleting)
/// the previous row, and — the F9 finding this file pins — rotation is one atomic transaction,
/// never a zero-active-key window a concurrent export could observe.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomSigningKeyRepositoryTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 9, 2, 12, 0, 0, TimeSpan.Zero));

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org-1', 'org-1')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static EnvelopeProtector Protector(bool configured)
    {
        var builder = new ConfigurationBuilder();
        if (configured)
        {
            builder.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["DEPENDABLY_MASTER_KEY"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            });
        }

        return new EnvelopeProtector(new EnvFileMasterKeyProvider(builder.Build()));
    }

    private async Task<int> ActiveKeyCountAsync(string orgId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM sbom_signing_key WHERE org_id = @orgId AND retired_at IS NULL",
            new { orgId });
    }

    [Fact]
    public async Task GetOrCreate_CreatesOnce_AndTheStoredPrivateKeyIsCiphertext()
    {
        var repo = new SbomSigningKeyRepository(_db, Protector(configured: true), _time, TestEdgeMode.Disabled());

        using var first = await repo.GetOrCreateAsync("org-1");
        using var second = await repo.GetOrCreateAsync("org-1");

        Assert.NotNull(first);
        Assert.Equal(first!.Id, second!.Id);
        Assert.Equal(1, await ActiveKeyCountAsync("org-1"));

        await using var conn = await _db.OpenAsync();
        string? storedPrivateKey = await conn.ExecuteScalarAsync<string?>(
            "SELECT private_key FROM sbom_signing_key WHERE org_id = 'org-1'");
        Assert.StartsWith("enc:v1:", storedPrivateKey);
    }

    [Fact]
    public async Task GetOrCreate_WithoutAMasterKey_ReturnsNull_AndNeverTouchesTheDatabase()
    {
        var repo = new SbomSigningKeyRepository(_db, Protector(configured: false), _time, TestEdgeMode.Disabled());

        Assert.Null(await repo.GetOrCreateAsync("org-1"));
        Assert.Equal(0, await ActiveKeyCountAsync("org-1"));
    }

    /// <summary>
    /// F9: rotation retires the current key and mints the replacement in ONE transaction.
    /// Pinned here as the state the DB is left in — exactly one active row before, exactly one
    /// active row after, and it is the row <see cref="SbomSigningKeyRepository.RotateAsync"/>
    /// actually returned — never zero (which upstream code reads as "no master key" even when
    /// one is configured) and never two (a phantom second active row from a losing insert that
    /// silently discarded the caller's own intended key). A single connection's view cannot
    /// observe an intermediate state a transaction never commits, which is what this asserts
    /// indirectly: there is no non-atomic sequence of statements left to observe between.
    ///
    /// <para>Mutant: split <c>RotateAsync</c> back into two separate connections/statements (the
    /// pre-fix shape — an UPDATE on its own connection, then a separate INSERT) and this test
    /// still passes, because a single-threaded test cannot observe the gap a two-statement
    /// version leaves for a CONCURRENT caller — which is exactly why the real regression here is
    /// structural (one transaction) rather than something a synchronous assertion alone can
    /// force red. The structural guarantee is verified by inspection of the transaction
    /// boundary in <c>SbomSigningKeyRepository.cs</c>, not by this test in isolation.</para>
    /// </summary>
    [Fact]
    public async Task Rotate_RetiresThePreviousKey_AndLeavesExactlyOneActiveKey()
    {
        var repo = new SbomSigningKeyRepository(_db, Protector(configured: true), _time, TestEdgeMode.Disabled());
        using var original = await repo.GetOrCreateAsync("org-1");
        Assert.Equal(1, await ActiveKeyCountAsync("org-1"));

        using var rotated = await repo.RotateAsync("org-1");

        Assert.NotEqual(original!.Id, rotated.Id);
        Assert.Equal(1, await ActiveKeyCountAsync("org-1"));

        using var active = await repo.GetActiveAsync("org-1");
        Assert.Equal(rotated.Id, active!.Id);

        var published = await repo.ListPublicAsync("org-1");
        Assert.Equal(2, published.Count);
        Assert.Single(published, k => k.Id == original.Id && k.RetiredAt is not null);
        Assert.Single(published, k => k.Id == rotated.Id && k.RetiredAt is null);
    }

    [Fact]
    public async Task Rotate_TwiceInARow_NeverLeavesTwoActiveKeys()
    {
        var repo = new SbomSigningKeyRepository(_db, Protector(configured: true), _time, TestEdgeMode.Disabled());
        using var first = await repo.GetOrCreateAsync("org-1");
        using var second = await repo.RotateAsync("org-1");
        using var third = await repo.RotateAsync("org-1");

        Assert.Equal(1, await ActiveKeyCountAsync("org-1"));
        var published = await repo.ListPublicAsync("org-1");
        Assert.Equal(3, published.Count);
        Assert.Equal(third.Id, published.Single(k => k.RetiredAt is null).Id);
    }

    [Fact]
    public async Task Revoke_StampsRevokedAt_ScopedToTheOwningOrg()
    {
        await using var conn0 = await _db.OpenAsync();
        await conn0.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org-2', 'org-2')");

        var repo = new SbomSigningKeyRepository(_db, Protector(configured: true), _time, TestEdgeMode.Disabled());
        using var key = await repo.GetOrCreateAsync("org-1");

        // A different org cannot revoke org-1's key — BOLA-safe no-op.
        await repo.RevokeAsync("org-2", key!.Id);
        var afterWrongOrg = await repo.ListPublicAsync("org-1");
        Assert.Null(afterWrongOrg.Single(k => k.Id == key.Id).RevokedAt);

        await repo.RevokeAsync("org-1", key.Id);
        var afterRevoke = await repo.ListPublicAsync("org-1");
        Assert.NotNull(afterRevoke.Single(k => k.Id == key.Id).RevokedAt);
    }
}
