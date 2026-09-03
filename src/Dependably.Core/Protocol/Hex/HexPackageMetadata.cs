namespace Dependably.Protocol.Hex;

/// <summary>
/// The typed view of a tarball's <c>metadata.config</c> — the Erlang term file Mix and Rebar3
/// write at <c>hex.publish</c> time — with the identity fields validated the way hex.pm
/// validates them, so a publish this registry accepts is one every client can resolve.
/// </summary>
public sealed record HexPackageMetadata(
    string Name,
    string Version,
    string App,
    string? Description,
    IReadOnlyList<string> Licenses,
    IReadOnlyDictionary<string, string> Links,
    IReadOnlyList<HexRequirement> Requirements,
    IReadOnlyList<string> BuildTools,
    string? Elixir,
    IReadOnlyList<string> Files)
{
    public static bool IsValidName(string name) => HexNaming.IsValidPackageName(name);

    public static bool IsValidVersion(string version) => HexNaming.IsValidVersion(version);

    /// <summary>
    /// Parses and validates a <c>metadata.config</c> body. Throws <see cref="HexProtocolException"/>
    /// when the text is not an Erlang term file, when <c>name</c> or <c>version</c> is missing
    /// or malformed, or when a requirement lacks the fields a resolver needs. Unknown keys are
    /// ignored, as hex_core ignores them.
    /// </summary>
    public static HexPackageMetadata Parse(string metadataText)
    {
        IReadOnlyList<object?> terms;
        try
        {
            terms = ErlangTermText.Consult(metadataText);
        }
        catch (ErlangTermException ex)
        {
            throw new HexProtocolException("metadata.config is not a readable Erlang term file.", ex);
        }

        var fields = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (object? term in terms)
        {
            // Each top-level term is {<<"key">>, Value}; anything else is ignored rather than refused.
            if (term is ErlangTuple { Items: [string key, var value] })
            {
                fields[key] = value;
            }
        }

        string name = RequiredString(fields, "name");
        if (!IsValidName(name))
        {
            throw new HexProtocolException("metadata.config name is not a valid Hex package name.");
        }

        string version = RequiredString(fields, "version");
        if (!IsValidVersion(version))
        {
            throw new HexProtocolException("metadata.config version is not a valid SemVer 2.0 version.");
        }

        string app = OptionalString(fields, "app") ?? name;
        return !IsValidName(app)
            ? throw new HexProtocolException("metadata.config app is not a valid OTP application name.")
            : new HexPackageMetadata(
            name, version, app,
            OptionalString(fields, "description"),
            StringList(fields, "licenses"),
            StringMap(fields, "links"),
            ParseRequirements(fields.GetValueOrDefault("requirements")),
            StringList(fields, "build_tools"),
            OptionalString(fields, "elixir"),
            StringList(fields, "files"));
    }

    private static string RequiredString(Dictionary<string, object?> fields, string key) =>
        fields.GetValueOrDefault(key) is string s && s.Length > 0
            ? s
            : throw new HexProtocolException($"metadata.config is missing {key}.");

    private static string? OptionalString(Dictionary<string, object?> fields, string key) =>
        fields.GetValueOrDefault(key) switch
        {
            string s => s,
            ErlangCharlist c => c.Value,
            _ => null,
        };

    private static IReadOnlyList<string> StringList(Dictionary<string, object?> fields, string key)
    {
        if (fields.GetValueOrDefault(key) is not IReadOnlyList<object?> list)
        {
            return Array.Empty<string>();
        }

        var result = new List<string>(list.Count);
        foreach (object? item in list)
        {
            if (item is string s)
            {
                result.Add(s);
            }
            else if (item is ErlangCharlist c)
            {
                result.Add(c.Value);
            }
        }

        return result;
    }

    private static IReadOnlyDictionary<string, string> StringMap(Dictionary<string, object?> fields, string key)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        switch (fields.GetValueOrDefault(key))
        {
            case IReadOnlyDictionary<object, object?> map:
                foreach (var (k, v) in map)
                {
                    if (k is string ks && v is string vs)
                    {
                        result[ks] = vs;
                    }
                }

                break;
            case IReadOnlyList<object?> proplist:
                foreach (object? item in proplist)
                {
                    if (item is ErlangTuple { Items: [string ks, string vs] })
                    {
                        result[ks] = vs;
                    }
                }

                break;
            default:
                break;
        }

        return result;
    }

    // Two shapes exist in the wild and hex_core normalizes both: the current
    // [{<<"name">>, [{<<"app">>,..},{<<"optional">>,..},{<<"requirement">>,..}]}] proplist keyed by
    // package name (or the same as a map), and the legacy list of proplists each carrying its own
    // <<"name">> entry.
    private static IReadOnlyList<HexRequirement> ParseRequirements(object? value)
    {
        var result = new List<HexRequirement>();
        switch (value)
        {
            case null:
                break;
            case IReadOnlyDictionary<object, object?> map:
                foreach (var (k, v) in map)
                {
                    if (k is string name)
                    {
                        result.Add(BuildRequirement(name, AsFields(v)));
                    }
                }

                break;
            case IReadOnlyList<object?> list:
                foreach (object? item in list)
                {
                    switch (item)
                    {
                        case ErlangTuple { Items: [string name, var body] }:
                            result.Add(BuildRequirement(name, AsFields(body)));
                            break;
                        case IReadOnlyList<object?> legacy:
                            var legacyFields = AsFields(legacy);
                            string legacyName = legacyFields.GetValueOrDefault("name") as string
                                ?? throw new HexProtocolException("metadata.config requirement is missing its name.");
                            result.Add(BuildRequirement(legacyName, legacyFields));
                            break;
                        default:
                            throw new HexProtocolException("metadata.config requirements entry has an unrecognized shape.");
                    }
                }

                break;
            default:
                throw new HexProtocolException("metadata.config requirements is neither a list nor a map.");
        }

        return result;
    }

    private static Dictionary<string, object?> AsFields(object? body)
    {
        var fields = new Dictionary<string, object?>(StringComparer.Ordinal);
        switch (body)
        {
            case IReadOnlyDictionary<object, object?> map:
                foreach (var (k, v) in map)
                {
                    if (k is string ks)
                    {
                        fields[ks] = v;
                    }
                }

                break;
            case IReadOnlyList<object?> proplist:
                foreach (object? item in proplist)
                {
                    if (item is ErlangTuple { Items: [string ks, var v] })
                    {
                        fields[ks] = v;
                    }
                }

                break;
            default:
                throw new HexProtocolException("metadata.config requirement body has an unrecognized shape.");
        }

        return fields;
    }

    private static HexRequirement BuildRequirement(string name, Dictionary<string, object?> fields)
    {
        if (!IsValidName(name))
        {
            throw new HexProtocolException("metadata.config requirement names an invalid package.");
        }

        string requirement = fields.GetValueOrDefault("requirement") switch
        {
            string s when s.Length > 0 => s,
            ErlangCharlist c when c.Value.Length > 0 => c.Value,
            _ => throw new HexProtocolException($"metadata.config requirement for {name} has no version requirement."),
        };

        bool optional = fields.GetValueOrDefault("optional") is ErlangAtom { IsTrue: true } or true;
        string? app = fields.GetValueOrDefault("app") as string;
        string? repository = fields.GetValueOrDefault("repository") as string;
        return new HexRequirement(name, requirement, optional, app, repository);
    }
}
