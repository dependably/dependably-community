namespace Dependably.Protocol.Hex;

/// <summary>
/// The public repositories whose signing keys this registry knows out of the box, so the seeded
/// hex.pm upstream verifies without an operator pasting a PEM. An explicitly stored
/// <c>upstream_registry.public_key_pem</c> always wins over this table.
/// </summary>
public static class HexWellKnownRepositories
{
    /// <summary>hex.pm's repository name, the one a Hex client reserves and no other repository may claim.</summary>
    public const string HexpmRepositoryName = "hexpm";

    /// <summary>hex.pm's registry signing key, published at https://hex.pm/docs/public_keys and served at https://repo.hex.pm/public_key.</summary>
    public const string HexpmPublicKeyPem = """
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApqREcFDt5vV21JVe2QNB
        Edvzk6w36aNFhVGWN5toNJRjRJ6m4hIuG4KaXtDWVLjnvct6MYMfqhC79HAGwyF+
        IqR6Q6a5bbFSsImgBJwz1oadoVKD6ZNetAuCIK84cjMrEFRkELtEIPNHblCzUkkM
        3rS9+DPlnfG8hBvGi6tvQIuZmXGCxF/73hU0/MyGhbmEjIKRtG6b0sJYKelRLTPW
        XgK7s5pESgiwf2YC/2MGDXjAJfpfCd0RpLdvd4eRiXtVlE9qO9bND94E7PgQ/xqZ
        J1i2xWFndWa6nfFnRxZmCStCOZWYYPlaxr+FZceFbpMwzTNs4g3d4tLNUcbKAIH4
        0wIDAQAB
        -----END PUBLIC KEY-----

        """;

    /// <summary>The PEM public key for a well-known repository URL, or null for any other host.</summary>
    public static string? PublicKeyPemFor(string? url) =>
        url is not null
        && Uri.TryCreate(url, UriKind.Absolute, out var uri)
        && string.Equals(uri.Host, "repo.hex.pm", StringComparison.OrdinalIgnoreCase)
            ? HexpmPublicKeyPem
            : null;

    /// <summary>The repository name a well-known URL embeds in its signed payloads (the origin a client verifies), or null.</summary>
    public static string? RepositoryNameFor(string? url) =>
        PublicKeyPemFor(url) is null ? null : HexpmRepositoryName;
}
