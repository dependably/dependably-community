namespace Dependably.Infrastructure.Identity;

/// <summary>
/// Reads the operator master key-encryption key (KEK) from the <c>DEPENDABLY_MASTER_KEY</c>
/// configuration entry. The value is either an inline base64 string or a filesystem path to a
/// file whose contents are the base64 key.
///
/// Validation occurs at construction time so a misconfigured key fails the process on startup
/// rather than at the first encryption call (fail-closed). The 32-byte decoded key is cached
/// for the lifetime of the singleton; no further I/O occurs after construction.
/// </summary>
internal sealed class EnvFileMasterKeyProvider : IMasterKeyProvider
{
    private const int RequiredKeyBytes = 32;
    private const string ConfigKey = "DEPENDABLY_MASTER_KEY";

    private readonly byte[]? _key;

    /// <inheritdoc/>
    public bool IsConfigured => _key is not null;

    /// <inheritdoc/>
    public string ProviderName => "env-file";

    public EnvFileMasterKeyProvider(IConfiguration configuration)
    {
        string? raw = configuration[ConfigKey];

        if (string.IsNullOrWhiteSpace(raw))
        {
            return;
        }

        string base64 = ResolveBase64(raw.Trim());
        _key = DecodeAndValidate(base64);
    }

    /// <inheritdoc/>
    public byte[] GetMasterKey() =>
        _key ?? throw new InvalidOperationException(
            $"{ConfigKey} is not configured. Set the key before calling GetMasterKey().");

    /// <summary>
    /// If the trimmed value refers to an existing file path, reads the file and returns its
    /// trimmed text. Otherwise treats the value itself as an inline base64 string.
    /// </summary>
    private static string ResolveBase64(string value)
    {
        if (File.Exists(value))
        {
            try
            {
                return File.ReadAllText(value).Trim();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw new InvalidOperationException(
                    $"{ConfigKey} points to a file that cannot be read: {value}", ex);
            }
        }

        return value;
    }

    /// <summary>
    /// Base64-decodes <paramref name="base64"/> and asserts the result is exactly 32 bytes.
    /// Throws <see cref="InvalidOperationException"/> on any validation failure.
    /// </summary>
    private static byte[] DecodeAndValidate(string base64)
    {
        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(base64);
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException(
                $"{ConfigKey} is not valid base64.", ex);
        }

        return bytes.Length == RequiredKeyBytes
            ? bytes
            : throw new InvalidOperationException(
                $"{ConfigKey} must decode to exactly {RequiredKeyBytes} bytes (AES-256); " +
                $"got {bytes.Length}.");
    }
}
