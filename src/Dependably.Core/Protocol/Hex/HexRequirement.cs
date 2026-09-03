namespace Dependably.Protocol.Hex;

/// <summary>One entry of a release's <c>requirements</c>: the dependency as Mix and Rebar3 declare it.</summary>
public sealed record HexRequirement(
    string Name,
    string Requirement,
    bool Optional,
    string? App,
    string? Repository)
{
    /// <summary>The registry-index form of this requirement (<c>Dependency</c> in <c>package.proto</c>).</summary>
    public HexDependency ToDependency() => new(
        Name, Requirement,
        Optional ? true : null,
        !string.IsNullOrEmpty(App) && !string.Equals(App, Name, StringComparison.Ordinal) ? App : null,
        Repository is not (null or "hexpm") ? Repository : null);
}
