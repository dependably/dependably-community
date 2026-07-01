using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;

namespace Dependably.Infrastructure.Identity;

/// <summary>
/// Encrypts DataProtection key-ring XML elements at rest using AES-256-GCM via the operator
/// master key-encryption key (KEK). Implements the ASP.NET Core <see cref="IXmlEncryptor"/>
/// seam: the DataProtection runtime calls <see cref="Encrypt"/> before handing the element to
/// the <see cref="DbXmlRepository"/>, wrapping the result in an envelope that names
/// <see cref="EnvelopeXmlDecryptor"/> as the complementary decryptor type.
///
/// Only wired when <see cref="IMasterKeyProvider.IsConfigured"/> is true. Pre-existing
/// plaintext key elements in the ring load without modification; only newly generated or
/// rotated keys receive the encrypted envelope.
/// </summary>
internal sealed class EnvelopeXmlEncryptor : IXmlEncryptor, IDisposable
{
    private readonly MfaSecretProtector _protector;

    public EnvelopeXmlEncryptor(IMasterKeyProvider masterKeyProvider)
    {
        if (!masterKeyProvider.IsConfigured)
        {
            throw new InvalidOperationException(
                "DEPENDABLY_MASTER_KEY is not configured; EnvelopeXmlEncryptor requires a KEK.");
        }

        _protector = new MfaSecretProtector(masterKeyProvider.GetMasterKey());
    }

    /// <summary>
    /// Serializes <paramref name="plaintextElement"/> to a string, AES-256-GCM-encrypts it,
    /// and returns an <see cref="EncryptedXmlInfo"/> whose element contains the base64
    /// ciphertext and whose decryptor type is <see cref="EnvelopeXmlDecryptor"/>.
    /// </summary>
    public EncryptedXmlInfo Encrypt(XElement plaintextElement)
    {
        string xmlText = plaintextElement.ToString(SaveOptions.DisableFormatting);
        string base64Cipher = _protector.Protect(xmlText);

        var encryptedElement = new XElement("encryptedKey",
            new XElement("value", base64Cipher));

        return new EncryptedXmlInfo(encryptedElement, typeof(EnvelopeXmlDecryptor));
    }

    public void Dispose() => _protector.Dispose();
}
