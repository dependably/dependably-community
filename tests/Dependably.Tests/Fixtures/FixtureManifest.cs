namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Documents the real package fixtures checked into Fixtures/packages/.
/// Hashes verified at time of download.
/// </summary>
public static class FixtureManifest
{
    /// <summary>Absolute path to the Fixtures/packages/ directory.</summary>
    public static string FixturesRoot { get; } =
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "packages");

    // PyPI
    public const string MypyExtensionsWheelSha256 =
        "4392f6c0eb8a5668a69e23d168ffa70f0be9ccfd32b5cc2d26a34ae5b844552d";
    public const string MypyExtensionsSdistSha256 =
        "75dbf8955dc00442a438fc4d0666508a9a97b6bd41aa2f0ffe9d2f2725af0782";

    // npm
    public const string IsOddTarballSha256 =
        "13c23b3f1f3a5c146b8906e23c8e674f8e4a6ff44b77720e1d4bddb7b2caf312";

    // NuGet
    public const string NewtonsoftJsonNupkgSha256 =
        "872fc189e638ab1056555b03aaa38f68bcb54286e221aa646eb1129babf63c77";
}
