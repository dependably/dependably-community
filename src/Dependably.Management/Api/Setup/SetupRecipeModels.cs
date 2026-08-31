namespace Dependably.Api.Setup;

/// <summary>
/// The client-configuration recipes for one ecosystem, as the Setup page consumes them.
///
/// This is the CONFIGURATION document — the files a developer writes once to point a
/// package manager at this registry. It is a different artefact from the per-artefact
/// INVOCATION built by <c>web/src/lib/installCommand.js</c>, and the two stay separate.
///
/// The shape is a flat <see cref="Recipes"/> list rather than a nested
/// variant/operation/scope tree because the page selects with a single lookup across the
/// three axes, and because a flat list makes an absent cell (Go has no publish path)
/// simply a row that was never emitted, rather than a branch that has to encode emptiness.
/// </summary>
/// <param name="Ecosystem">The ecosystem key, matching <c>web/src/lib/ecosystems.js</c>.</param>
/// <param name="Variants">
/// The tool variants offered for this ecosystem, in display order. A single-variant
/// ecosystem emits one entry and the page renders no variant control.
/// </param>
/// <param name="Recipes">Every (variant, operation, scope) cell that actually exists.</param>
public sealed record SetupRecipesResponse(
    string Ecosystem,
    IReadOnlyList<SetupVariant> Variants,
    IReadOnlyList<SetupRecipe> Recipes);

/// <param name="Id">Stable variant key used to select a recipe.</param>
/// <param name="Label">
/// Display name of the tool ("Gradle (Kotlin)"). A proper tool name, so it is not
/// translated — the same posture as <c>ECO_LABEL</c> on the frontend.
/// </param>
public sealed record SetupVariant(string Id, string Label);

/// <summary>One cell of the ecosystem × operation × scope × variant matrix.</summary>
/// <param name="CapabilityPreset">
/// The token preset this recipe needs — one of the package presets in
/// <c>web/src/lib/tokenCapabilities.js</c>. The page uses it to mint the right token in
/// step 1, which is why it is a preset key and not a raw capability list: a preset-matched
/// token renders as itself in the Tokens table, where a bespoke capability set renders as
/// "custom".
/// </param>
/// <param name="Files">
/// The files to write, in the order they should be written. A project-scoped recipe
/// commonly carries two: the committed file that names the registry, and the developer's
/// own credential file that must not be committed (<see cref="SetupFile.SecretBearing"/>).
/// </param>
/// <param name="Verify">
/// Shell commands that confirm the configuration works, ordered cheapest-and-most-
/// diagnostic first so a failure localizes itself (reachability before authentication
/// before resolution).
/// </param>
/// <param name="Caveats">
/// Caveat identifiers resolved to copy on the client. Shared with
/// <c>installCommand.js</c>'s CAVEATS vocabulary so the two surfaces word a given
/// gotcha identically.
/// </param>
public sealed record SetupRecipe(
    string Variant,
    string Operation,
    string Scope,
    string CapabilityPreset,
    IReadOnlyList<SetupFile> Files,
    SetupTokenDelivery TokenDelivery,
    string? Verify,
    IReadOnlyList<string> Caveats);

/// <param name="Path">The file to write, as the tool expects to find it.</param>
/// <param name="LocationHint">
/// Where that path is rooted ("in your repository root"), resolved to copy on the client.
/// Null when the path is already absolute and needs no explanation.
/// </param>
/// <param name="Language">Syntax hint for rendering; not load-bearing.</param>
/// <param name="Body">The file contents, with the registry URL already resolved.</param>
/// <param name="SecretBearing">
/// True when this file ends up holding the literal token. The page marks such a file as
/// "do not commit"; a false here is a positive claim that the body carries no secret.
/// </param>
public sealed record SetupFile(
    string Path,
    string? LocationHint,
    string Language,
    string Body,
    bool SecretBearing);

/// <summary>
/// How the token reaches the tool. This varies by scope, not only by ecosystem: the
/// project-scoped recipes reference an environment variable so the file stays committable,
/// while the global-scoped ones write the literal value into a file that was never under
/// source control and tighten its permissions instead.
/// </summary>
/// <param name="Kind">
/// <c>envVar</c> — the file interpolates <see cref="EnvVar"/> and holds no secret.
/// <c>literal</c> — the token is written into the file, which must not be committed.
/// <c>command</c> — the token travels in a command rather than a file: a CLI that stores
/// the credential (<c>docker login</c>, <c>cargo login</c>), or the environment assignment a
/// tool reads by convention and that appears in no file (uv's per-index variable pair).
/// </param>
/// <param name="EnvVar">Variable name for <c>envVar</c>; null otherwise.</param>
/// <param name="Command">Command template for <c>command</c>; null otherwise.</param>
public sealed record SetupTokenDelivery(string Kind, string? EnvVar, string? Command)
{
    public static SetupTokenDelivery FromEnvVar(string name) => new(SetupVocabulary.DeliveryEnvVar, name, null);

    public static SetupTokenDelivery Literal() => new(SetupVocabulary.DeliveryLiteral, null, null);

    public static SetupTokenDelivery FromCommand(string command) => new(SetupVocabulary.DeliveryCommand, null, command);
}

/// <summary>
/// The closed vocabularies the recipe axes draw from. Named constants rather than bare
/// strings because the frontend selectors, the compliance test, and every builder below
/// have to agree on them exactly, and a typo in any one of the three would surface as an
/// empty page rather than as a failure.
/// </summary>
public static class SetupVocabulary
{
    public const string OperationInstall = "install";
    public const string OperationPublish = "publish";

    public const string ScopeProject = "project";
    public const string ScopeGlobal = "global";

    // Package presets from web/src/lib/tokenCapabilities.js. The privileged presets
    // (admin/audit/sbom) are deliberately absent: none of them configures a client.
    public const string PresetPull = "pull";
    public const string PresetPush = "push";

    public const string DeliveryEnvVar = "envVar";
    public const string DeliveryLiteral = "literal";
    public const string DeliveryCommand = "command";

    public static readonly IReadOnlySet<string> Operations =
        new HashSet<string>(StringComparer.Ordinal) { OperationInstall, OperationPublish };

    public static readonly IReadOnlySet<string> Scopes =
        new HashSet<string>(StringComparer.Ordinal) { ScopeProject, ScopeGlobal };

    public static readonly IReadOnlySet<string> Presets =
        new HashSet<string>(StringComparer.Ordinal) { PresetPull, PresetPush };

    public static readonly IReadOnlySet<string> DeliveryKinds =
        new HashSet<string>(StringComparer.Ordinal) { DeliveryEnvVar, DeliveryLiteral, DeliveryCommand };
}
