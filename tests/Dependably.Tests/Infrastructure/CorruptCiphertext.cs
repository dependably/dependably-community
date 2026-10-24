using System.Xml.Linq;
using Dependably.Infrastructure.Identity;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Builds stored secrets shaped like the ones the unsynchronized shared <c>AesGcm</c> could write
/// on Linux: a well-formed <c>base64(nonce || tag || ciphertext)</c> whose parts come from two
/// different encryptions, so it parses, carries the envelope prefix, and never authenticates.
/// </summary>
public static class CorruptCiphertext
{
    private const int NonceSize = 12;

    /// <summary>
    /// Splices the nonce of one ciphertext onto the tag and body of another. Both must be raw
    /// <c>base64(nonce || tag || ciphertext)</c> values without the envelope prefix.
    /// </summary>
    public static string Splice(string nonceFrom, string rest)
    {
        byte[] a = Convert.FromBase64String(nonceFrom);
        byte[] b = Convert.FromBase64String(rest);
        a[..NonceSize].CopyTo(b, 0);
        return Convert.ToBase64String(b);
    }

    /// <summary>Flips one bit of the authentication tag of a raw ciphertext.</summary>
    public static string FlipTagBit(string raw)
    {
        byte[] bytes = Convert.FromBase64String(raw);
        bytes[NonceSize] ^= 0x01;
        return Convert.ToBase64String(bytes);
    }

    /// <summary>An <c>enc:v1:</c> value for <paramref name="plaintext"/> that fails authentication.</summary>
    public static string Envelope(EnvelopeProtector envelope, string plaintext)
    {
        const string prefix = "enc:v1:";
        string first = envelope.Protect(plaintext)[prefix.Length..];
        string second = envelope.Protect(plaintext)[prefix.Length..];
        return prefix + Splice(first, second);
    }

    /// <summary>A TOTP-column value for <paramref name="plaintext"/> that fails authentication.</summary>
    internal static string Totp(MfaSecretProtector protector, string plaintext) =>
        Splice(protector.Protect(plaintext), protector.Protect(plaintext));

    /// <summary>
    /// A DataProtection key element in the shape the key manager stores once
    /// <see cref="EnvelopeXmlEncryptor"/> is configured: the key material replaced by an
    /// <c>encryptedSecret</c> naming the decryptor and holding the encryptor's output.
    /// <paramref name="mutateCipher"/> lets a test swap the ciphertext for a corrupt one.
    /// </summary>
    internal static string KeyRingElement(byte[] masterKey, Func<string, string>? mutateCipher = null)
    {
        var provider = new EnvFileMasterKeyProvider(
            new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["DEPENDABLY_MASTER_KEY"] = Convert.ToBase64String(masterKey),
                })
                .Build());
        using var encryptor = new EnvelopeXmlEncryptor(provider);
        var info = encryptor.Encrypt(new XElement("masterKey", new XElement("value", "a2V5LW1hdGVyaWFs")));
        var value = info.EncryptedElement.Element("value")!;
        if (mutateCipher is not null)
        {
            value.Value = mutateCipher(value.Value);
        }

        XNamespace ns = "http://schemas.asp.net/2015/03/dataProtection";
        var root = new XElement("key",
            new XAttribute("id", Guid.NewGuid()),
            new XAttribute("version", 1),
            new XElement("descriptor",
                new XElement("descriptor",
                    new XElement("masterKey",
                        new XElement(ns + "encryptedSecret",
                            new XAttribute("decryptorType", info.DecryptorType.AssemblyQualifiedName!),
                            info.EncryptedElement)))));
        return root.ToString(SaveOptions.DisableFormatting);
    }
}
