using System.Security.Cryptography;
using Dependably.Infrastructure.Identity;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Test factories for <see cref="EnvelopeProtector"/>. <see cref="Unconfigured"/> builds a
/// protector with no master key (legacy-plaintext pass-through on read, throws on
/// <see cref="EnvelopeProtector.Protect"/>) — the default for tests that don't exercise
/// secret-at-rest. <see cref="Configured"/> builds one backed by a random AES-256 key so
/// encrypt/decrypt round-trips work.
/// </summary>
public static class TestEnvelope
{
    public static EnvelopeProtector Unconfigured() =>
        new(new EnvFileMasterKeyProvider(
            new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>()).Build()));

    public static EnvelopeProtector Configured(byte[]? key = null)
    {
        byte[] material = key ?? RandomNumberGenerator.GetBytes(32);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["DEPENDABLY_MASTER_KEY"] = Convert.ToBase64String(material),
            })
            .Build();
        return new EnvelopeProtector(new EnvFileMasterKeyProvider(config));
    }
}
