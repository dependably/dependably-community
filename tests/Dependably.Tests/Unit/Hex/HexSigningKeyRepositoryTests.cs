using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Hex;
using Dependably.Infrastructure.Identity;
using Dependably.Protocol.Hex;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Hex;

/// <summary>
/// The per-org signing key: created once, stored only as envelope ciphertext, readable back
/// into a working RSA key, replaced wholesale on rotation, and impossible without a master key.
/// </summary>
[Trait("Category", "Unit")]
public sealed class HexSigningKeyRepositoryTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 9, 2, 12, 0, 0, TimeSpan.Zero));

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org-1', 'org-1')");
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org-2', 'org-2')");
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

    [Fact]
    public async Task GetOrCreate_CreatesOnce_AndTheStoredPrivateKeyIsCiphertext()
    {
        var repo = new HexSigningKeyRepository(_db, Protector(configured: true), _time, TestEdgeMode.Disabled());

        using var first = await repo.GetOrCreateAsync("org-1");
        using var second = await repo.GetOrCreateAsync("org-1");

        Assert.NotNull(first);
        Assert.Equal(first!.PublicKeyPem, second!.PublicKeyPem);
        Assert.Equal(first.Fingerprint, second.Fingerprint);
        Assert.Equal(HexRegistrySigner.GeneratedKeyBits, first.PrivateKey.KeySize);
        Assert.Equal(_time.GetUtcNow(), first.CreatedAt);

        await using var conn = await _db.OpenAsync();
        string stored = await conn.ExecuteScalarAsync<string>("SELECT private_key FROM hex_signing_key WHERE org_id = 'org-1'") ?? "";
        Assert.DoesNotContain("PRIVATE KEY", stored);
        Assert.True(EnvelopeProtector.IsEncrypted(stored));
    }

    [Fact]
    public async Task TheReturnedKeySigns_AndThePublicPemVerifies()
    {
        var repo = new HexSigningKeyRepository(_db, Protector(configured: true), _time, TestEdgeMode.Disabled());
        using var key = await repo.GetOrCreateAsync("org-1");
        byte[] payload = "payload"u8.ToArray();

        byte[] resource = HexRegistrySigner.BuildResource(payload, key!.PrivateKey);

        using var pub = HexRegistrySigner.ParsePublicKeyPem(key.PublicKeyPem);
        Assert.Equal(payload, HexRegistrySigner.OpenResource(resource, pub));
        Assert.Equal(HexSigningKeyRepository.ComputeFingerprint(pub), key.Fingerprint);
    }

    [Fact]
    public async Task KeysAreIsolatedPerOrg()
    {
        var repo = new HexSigningKeyRepository(_db, Protector(configured: true), _time, TestEdgeMode.Disabled());
        using var one = await repo.GetOrCreateAsync("org-1");
        using var two = await repo.GetOrCreateAsync("org-2");

        Assert.NotEqual(one!.PublicKeyPem, two!.PublicKeyPem);
        Assert.Null(await repo.GetAsync("org-3"));
    }

    [Fact]
    public async Task Rotate_ReplacesTheKey_AndTheOldPublicKeyNoLongerVerifies()
    {
        var repo = new HexSigningKeyRepository(_db, Protector(configured: true), _time, TestEdgeMode.Disabled());
        using var before = await repo.GetOrCreateAsync("org-1");

        using var rotated = await repo.RotateAsync("org-1");
        using var after = await repo.GetAsync("org-1");

        Assert.NotEqual(before!.PublicKeyPem, rotated.PublicKeyPem);
        Assert.Equal(rotated.PublicKeyPem, after!.PublicKeyPem);
        byte[] resource = HexRegistrySigner.BuildResource("x"u8.ToArray(), after.PrivateKey);
        using var oldPub = HexRegistrySigner.ParsePublicKeyPem(before.PublicKeyPem);
        Assert.Throws<HexProtocolException>(() => HexRegistrySigner.OpenResource(resource, oldPub));
    }

    [Fact]
    public async Task WithoutAMasterKey_NothingIsCreatedOrReturned()
    {
        var repo = new HexSigningKeyRepository(_db, Protector(configured: false), _time, TestEdgeMode.Disabled());

        Assert.False(repo.CanSign);
        Assert.Null(await repo.GetOrCreateAsync("org-1"));
        await Assert.ThrowsAsync<InvalidOperationException>(() => repo.RotateAsync("org-1"));
        await using var conn = await _db.OpenAsync();
        Assert.Equal(0, await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM hex_signing_key"));
    }

    [Fact]
    public async Task GetPublic_ReadsWithoutTheMasterKey()
    {
        var configured = new HexSigningKeyRepository(_db, Protector(configured: true), _time, TestEdgeMode.Disabled());
        using var created = await configured.GetOrCreateAsync("org-1");

        var unconfigured = new HexSigningKeyRepository(_db, Protector(configured: false), _time, TestEdgeMode.Disabled());
        var publicOnly = await unconfigured.GetPublicAsync("org-1");

        Assert.Equal(created!.PublicKeyPem, publicOnly!.Value.PublicKeyPem);
        Assert.Equal(created.Fingerprint, publicOnly.Value.Fingerprint);
    }
}
