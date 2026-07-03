using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;

namespace Dependably.Infrastructure.Identity;

/// <summary>
/// Decrypts DataProtection key-ring XML elements that were encrypted by
/// <see cref="EnvelopeXmlEncryptor"/>. The DataProtection runtime resolves this type via the
/// DI-backed activator when it reads a key element whose <c>decryptorType</c> attribute names
/// this class. The ctor accepts <see cref="IServiceProvider"/> so the DataProtection activator
/// can inject it automatically (the activator has special-case support for the <c>IServiceProvider</c>
/// parameter pattern used by built-in decryptors such as <c>CertificateXmlDecryptor</c>).
///
/// Fails closed when the master key is absent: an element encrypted by a KEK-configured
/// instance cannot silently pass through on a key-less instance — it throws
/// <see cref="InvalidOperationException"/> naming <c>DEPENDABLY_MASTER_KEY</c>.
/// </summary>
internal sealed class EnvelopeXmlDecryptor : IXmlDecryptor, IDisposable
{
    private readonly bool _isConfigured;
    private readonly MfaSecretProtector? _protector;

    public EnvelopeXmlDecryptor(IServiceProvider services)
    {
        var masterKeyProvider = services.GetRequiredService<IMasterKeyProvider>();
        _isConfigured = masterKeyProvider.IsConfigured;

        if (_isConfigured)
        {
            _protector = new MfaSecretProtector(masterKeyProvider.GetMasterKey());
        }
    }

    /// <summary>
    /// Reads the <c>value</c> child element from <paramref name="encryptedElement"/>,
    /// AES-256-GCM-decrypts the base64 ciphertext, and returns the parsed
    /// <see cref="XElement"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the master key is not configured (lost-key fail-closed scenario).
    /// </exception>
    public XElement Decrypt(XElement encryptedElement)
    {
        if (!_isConfigured || _protector is null)
        {
            throw new InvalidOperationException(
                "The DataProtection key ring contains an element encrypted at rest, " +
                "but DEPENDABLY_MASTER_KEY is not configured. " +
                "Set DEPENDABLY_MASTER_KEY to the operator master key to load the ring.");
        }

        string base64Cipher = encryptedElement.Element("value")!.Value;
        string xmlText = _protector.Unprotect(base64Cipher);
        return XElement.Parse(xmlText);
    }

    public void Dispose() => _protector?.Dispose();
}
