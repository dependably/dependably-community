using System.Security.Cryptography;
using System.Xml.Linq;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Dependably.Tests.Unit.Identity;

/// <summary>
/// Unit tests for <see cref="EnvelopeXmlEncryptor"/> and <see cref="EnvelopeXmlDecryptor"/>.
/// Verifies the AES-GCM XML envelope round-trip, mixed-ring back-compat, and the no-KEK
/// passthrough wiring gate.
///
/// Uses in-memory SQLite (<see cref="TestMetadataStore"/>) and a deterministic 32-byte KEK
/// so no wall-clock or external I/O is required.
/// </summary>
[Trait("Category", "Unit")]
public sealed class EnvelopeXmlEncryptorTests : IAsyncLifetime
{
    // Known 32-byte KEK: deterministic, never persisted outside tests.
    private static readonly byte[] KnownKey = RandomNumberGenerator.GetBytes(32);

    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
    }

    public async Task DisposeAsync()
    {
        await _db.DisposeAsync();
    }

    // ── Build helpers ─────────────────────────────────────────────────────────

    private static EnvFileMasterKeyProvider ConfiguredProvider(byte[] key)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["DEPENDABLY_MASTER_KEY"] = Convert.ToBase64String(key),
            })
            .Build();
        return new EnvFileMasterKeyProvider(config);
    }

    private static EnvFileMasterKeyProvider UnconfiguredProvider()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>())
            .Build();
        return new EnvFileMasterKeyProvider(config);
    }

    private DbXmlRepository Repository() =>
        new(_db, NullLogger<DbXmlRepository>.Instance);

    private static IDataProtectionProvider BuildEncryptedProvider(
        DbXmlRepository repo, EnvFileMasterKeyProvider kek)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IMasterKeyProvider>(kek);
        // Register EnvelopeXmlDecryptor so the DataProtection DI-backed activator resolves
        // it by type (GetService lookup) when loading encrypted key elements from the ring.
        services.AddTransient<EnvelopeXmlDecryptor>();
        services.AddDataProtection()
            .SetApplicationName("dependably")
            .AddKeyManagementOptions(opts =>
            {
                opts.XmlRepository = repo;
                if (kek.IsConfigured)
                {
                    opts.XmlEncryptor = new EnvelopeXmlEncryptor(kek);
                }
            });
        return services.BuildServiceProvider().GetRequiredService<IDataProtectionProvider>();
    }

    private static IDataProtectionProvider BuildPlaintextProvider(DbXmlRepository repo)
    {
        var services = new ServiceCollection();
        services.AddDataProtection()
            .SetApplicationName("dependably")
            .AddKeyManagementOptions(opts => opts.XmlRepository = repo);
        return services.BuildServiceProvider().GetRequiredService<IDataProtectionProvider>();
    }

    // ── Encryptor: round-trip at the element level ────────────────────────────

    private static EnvelopeXmlDecryptor BuildDecryptor(IMasterKeyProvider kek)
    {
        var sp = new ServiceCollection()
            .AddSingleton(kek)
            .BuildServiceProvider();
        return new EnvelopeXmlDecryptor(sp);
    }

    [Fact]
    public void Encrypt_ThenDecrypt_RoundTripsXmlElement()
    {
        var kek = ConfiguredProvider(KnownKey);
        var encryptor = new EnvelopeXmlEncryptor(kek);
        var decryptor = BuildDecryptor(kek);

        var original = new XElement("key",
            new XAttribute("id", "test-round-trip"),
            new XElement("descriptor", "some-sensitive-material"));

        var info = encryptor.Encrypt(original);

        // The returned element must be the envelope shape, not the plaintext.
        Assert.Equal("encryptedKey", info.EncryptedElement.Name.LocalName);
        var valueEl = info.EncryptedElement.Element("value");
        Assert.NotNull(valueEl);

        // The decryptor type must name EnvelopeXmlDecryptor.
        Assert.Equal(typeof(EnvelopeXmlDecryptor), info.DecryptorType);

        // Decrypt and verify round-trip.
        var recovered = decryptor.Decrypt(info.EncryptedElement);
        Assert.Equal(
            original.ToString(SaveOptions.DisableFormatting),
            recovered.ToString(SaveOptions.DisableFormatting));
    }

    // ── Envelope content: ciphertext is opaque (no plaintext key material) ────

    [Fact]
    public void Encrypt_EnvelopeElement_ContainsNoCleartextDescriptor()
    {
        var kek = ConfiguredProvider(KnownKey);
        var encryptor = new EnvelopeXmlEncryptor(kek);

        var original = new XElement("key",
            new XElement("descriptor", "masterKey-abc123"));

        var info = encryptor.Encrypt(original);

        string serialized = info.EncryptedElement.ToString(SaveOptions.DisableFormatting);
        Assert.DoesNotContain("masterKey-abc123", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("<descriptor>", serialized, StringComparison.Ordinal);
    }

    // ── Encrypted-at-rest full round-trip via DataProtection provider ─────────

    [Fact]
    public async Task EncryptedProvider_ProtectUnprotect_RoundTrips()
    {
        var kek = ConfiguredProvider(KnownKey);
        var repo = Repository();

        var provider = BuildEncryptedProvider(repo, kek);
        var protector = provider.CreateProtector("encrypted-dp-test.v1");

        string ciphertext = protector.Protect("secret-payload");

        // Verify the persisted xml column carries our encryptedKey envelope.
        await using var conn = await _db.OpenAsync();
        var rows = (await conn.QueryAsync<string>(
            "SELECT xml FROM data_protection_keys")).ToList();

        Assert.NotEmpty(rows);
        // At least one key must contain the encrypted envelope wrapping the secret.
        // DataProtection wraps our encryptedKey in <encryptedSecret decryptorType="...">.
        Assert.Contains(rows, xml => xml.Contains("encryptedSecret", StringComparison.Ordinal));
        // The raw AES key material (<masterKey>) must not appear in plaintext in any row.
        // The outer descriptor frame (<descriptor deserializerType="...">) stays plaintext —
        // only the inner secret is encrypted.
        Assert.DoesNotContain(rows, xml => xml.Contains("<masterKey", StringComparison.Ordinal));

        // Unprotect succeeds using the same provider.
        Assert.Equal("secret-payload", protector.Unprotect(ciphertext));
    }

    // ── Cross-instance round-trip: new provider over same KEK + same DB ───────

    [Fact]
    public async Task EncryptedProvider_SecondInstance_CanUnprotectCiphertextFromFirst()
    {
        var kek1 = ConfiguredProvider(KnownKey);

        string ciphertext;
        {
            var repo1 = Repository();
            var provider1 = BuildEncryptedProvider(repo1, kek1);
            ciphertext = provider1.CreateProtector("cross-instance.v1").Protect("hello");
        }

        // Second provider instance reads from the same in-memory DB via a new repository.
        var kek2 = ConfiguredProvider(KnownKey);
        var repo2 = new DbXmlRepository(_db, NullLogger<DbXmlRepository>.Instance);
        var services2 = new ServiceCollection();
        services2.AddSingleton<IMasterKeyProvider>(kek2);
        // Register EnvelopeXmlDecryptor so the DataProtection DI-backed activator resolves
        // it by type (GetService lookup) when loading encrypted key elements from the ring.
        services2.AddTransient<EnvelopeXmlDecryptor>();
        services2.AddDataProtection()
            .SetApplicationName("dependably")
            .AddKeyManagementOptions(opts =>
            {
                opts.XmlRepository = repo2;
                if (kek2.IsConfigured)
                {
                    opts.XmlEncryptor = new EnvelopeXmlEncryptor(kek2);
                }
            });
        var provider2 = services2.BuildServiceProvider()
            .GetRequiredService<IDataProtectionProvider>();

        string plaintext = provider2.CreateProtector("cross-instance.v1").Unprotect(ciphertext);
        Assert.Equal("hello", plaintext);

        // Await completes trivially; method is async to allow await using in callers.
        await Task.CompletedTask;
    }

    // ── Mixed ring back-compat: plaintext key pre-existing + encrypted new key ─

    [Fact]
    public async Task EncryptedProvider_MixedRing_LoadsPlaintextKeyAlongsideEncryptedKey()
    {
        // Seed a plaintext key element directly into the DB, simulating a pre-existing
        // ring entry written before encryption was configured.
        var plaintextElement = new XElement("key",
            new XAttribute("id", "6789abcd-0000-0000-0000-000000000001"),
            new XAttribute("version", "1"),
            new XElement("creationDate", "2026-01-01T00:00:00Z"),
            new XElement("activationDate", "2026-01-01T00:00:00Z"),
            new XElement("expirationDate", "2027-01-01T00:00:00Z"),
            new XElement("descriptor",
                new XAttribute("deserializerType",
                    "Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel.AuthenticatedEncryptorDescriptorDeserializer, Microsoft.AspNetCore.DataProtection"),
                new XElement("encryption",
                    new XAttribute("algorithm", "AES_256_CBC")),
                new XElement("validation",
                    new XAttribute("algorithm", "HMACSHA256")),
                new XElement("masterKey",
                    new XAttribute("{http://schemas.asp.net/2015/03/dataProtection}requiresEncryption", "true"),
                    new XElement("value", Convert.ToBase64String(RandomNumberGenerator.GetBytes(48))))));

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO data_protection_keys (friendly_name, xml) VALUES (@name, @xml)",
                new { name = "plaintext-key-1", xml = plaintextElement.ToString(SaveOptions.DisableFormatting) });
        }

        // Build a KEK-configured provider; it must load the plaintext element without error.
        var kek = ConfiguredProvider(KnownKey);
        var repo = Repository();
        var provider = BuildEncryptedProvider(repo, kek);

        // The provider must be able to create a protector (ring loaded successfully).
        var protector = provider.CreateProtector("mixed-ring-test.v1");
        Assert.NotNull(protector);

        // A newly generated key gets encrypted and the plaintext row stays unchanged.
        string ciphertext = protector.Protect("mixed-ring-value");
        Assert.NotEmpty(ciphertext);

        await using (var conn = await _db.OpenAsync())
        {
            var rows = (await conn.QueryAsync<string>(
                "SELECT xml FROM data_protection_keys")).ToList();

            // The original plaintext row must still be present with its unencrypted masterKey.
            Assert.Contains(rows, xml => xml.Contains("<masterKey", StringComparison.Ordinal));
            // The newly generated key must be encrypted (the plaintext row was not re-encrypted).
            Assert.Contains(rows, xml => xml.Contains("encryptedSecret", StringComparison.Ordinal));
        }
    }

    // ── No-KEK gate: without a master key no encryptor is set ────────────────

    [Fact]
    public async Task NoKek_Provider_PersistsPlaintextKeys()
    {
        var repo = Repository();
        var provider = BuildPlaintextProvider(repo);
        var protector = provider.CreateProtector("no-kek-test.v1");

        string ciphertext = protector.Protect("open-payload");

        // Plaintext provider must be able to unprotect its own ciphertext.
        Assert.Equal("open-payload", protector.Unprotect(ciphertext));

        // Rows must not contain the encrypted envelope (plaintext ring).
        await using var conn = await _db.OpenAsync();
        var rows = (await conn.QueryAsync<string>(
            "SELECT xml FROM data_protection_keys")).ToList();

        Assert.NotEmpty(rows);
        Assert.DoesNotContain(rows, xml => xml.Contains("encryptedSecret", StringComparison.Ordinal));
    }

    // ── Decryptor: throws clearly when KEK absent ─────────────────────────────

    [Fact]
    public void Decrypt_WhenKekAbsent_ThrowsInvalidOperationException()
    {
        // Encrypt an element using the configured provider.
        var kek = ConfiguredProvider(KnownKey);
        var encryptor = new EnvelopeXmlEncryptor(kek);
        var original = new XElement("key", new XElement("descriptor", "material"));
        var info = encryptor.Encrypt(original);

        // Decryptor backed by an unconfigured provider must fail closed with a clear message.
        var noKekServices = new ServiceCollection();
        noKekServices.AddSingleton<IMasterKeyProvider>(UnconfiguredProvider());
        var sp = noKekServices.BuildServiceProvider();
        var decryptor = new EnvelopeXmlDecryptor(sp);

        var ex = Assert.Throws<InvalidOperationException>(() =>
            decryptor.Decrypt(info.EncryptedElement));

        Assert.Contains("DEPENDABLY_MASTER_KEY", ex.Message, StringComparison.Ordinal);
    }

    // ── Encryptor: constructor rejects unconfigured provider ──────────────────

    [Fact]
    public void EnvelopeXmlEncryptor_UnconfiguredKek_ThrowsOnConstruction()
    {
        var noKek = UnconfiguredProvider();
        Assert.Throws<InvalidOperationException>(() => new EnvelopeXmlEncryptor(noKek));
    }

    // ── Mixed partial-failure: encrypted and corrupt rows in same ring ─────────

    [Fact]
    public async Task GetAllElements_MixedEncryptedAndCorrupt_SkipsCorruptRow()
    {
        // Seed a correctly encrypted element.
        var kek = ConfiguredProvider(KnownKey);
        var encryptor = new EnvelopeXmlEncryptor(kek);
        var good = new XElement("key", new XAttribute("id", "good-enc"));
        var info = encryptor.Encrypt(good);
        string encryptedXml = new XElement("key",
            new XAttribute("id", "wrapped"),
            info.EncryptedElement).ToString(SaveOptions.DisableFormatting);

        // Seed a row with malformed (non-parseable) XML alongside the valid encrypted row.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO data_protection_keys (friendly_name, xml) VALUES ('corrupt', 'NOT XML <<<<')");
            await conn.ExecuteAsync(
                "INSERT INTO data_protection_keys (friendly_name, xml) VALUES ('good', @xml)",
                new { xml = encryptedXml });
        }

        var repo = Repository();

        // The repository skips the corrupt row and returns the parseable row.
        var elements = repo.GetAllElements();
        Assert.Single(elements);
    }
}
