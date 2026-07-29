namespace Dependably.Infrastructure;

/// <summary>
/// The ecosystems whose hosted-publish paths consult <see cref="Security.NameBindingGate"/> for
/// name-level publish authorization — every ecosystem that has a hosted push surface. Unlike the
/// legacy <see cref="ClaimEcosystems.Enforced"/> (which gates the proxy-merge claim resolver and
/// covered only npm/pypi/nuget/cargo), name-binding is the actual "who may write this name"
/// control and reaches maven, rpm, and oci as well — the three the supply-chain review found had
/// no name-level defence of any kind.
/// </summary>
public static class NameBindingEcosystems
{
    public static readonly IReadOnlySet<string> Enforced =
        new HashSet<string>(StringComparer.Ordinal)
        {
            "npm", "pypi", "nuget", "maven", "rpm", "oci", "cargo",
        };

    public static bool Covers(string ecosystem) => Enforced.Contains(ecosystem);
}
