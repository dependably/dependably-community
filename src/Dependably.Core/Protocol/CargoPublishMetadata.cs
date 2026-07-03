using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Dependably.Protocol;

/// <summary>
/// The JSON metadata segment of a Cargo publish frame, as defined by the Cargo registry web
/// API. Only the fields needed to build the sparse-index line and identify the crate are
/// modelled; unknown fields are ignored. The publish-form dependency shape
/// (<see cref="CargoPublishDep"/>) differs from the index form — notably
/// <c>version_req</c> becomes <c>req</c> — and is mapped by <see cref="ToIndexLine"/>.
/// </summary>
public sealed class CargoPublishMetadata
{
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("vers")] public string Vers { get; init; } = "";
    [JsonPropertyName("deps")] public List<CargoPublishDep> Deps { get; init; } = new();
    [JsonPropertyName("features")] public Dictionary<string, List<string>> Features { get; init; } = new();
    [JsonPropertyName("links")] public string? Links { get; init; }

    /// <summary>
    /// Builds the canonical sparse-index JSON line for this crate version from the publish
    /// metadata plus the computed crate <paramref name="cksum"/> (SHA-256 hex) and the
    /// <paramref name="yanked"/> flag. The dependency shape is mapped from publish form to
    /// index form (<c>version_req</c> → <c>req</c>); <c>features</c>, <c>optional</c>,
    /// <c>default_features</c>, <c>target</c>, and <c>kind</c> are preserved verbatim, and a
    /// dependency's <c>registry</c> is emitted as null when it resolves to this same registry.
    /// </summary>
    public string ToIndexLine(string cksum, bool yanked)
    {
        var deps = new JsonArray();
        foreach (var dep in Deps)
        {
            deps.Add(dep.ToIndexNode());
        }

        var features = new JsonObject();
        foreach (var (key, vals) in Features)
        {
            var arr = new JsonArray();
            foreach (string v in vals)
            {
                arr.Add(v);
            }
            features[key] = arr;
        }

        var line = new JsonObject
        {
            ["name"] = Name,
            ["vers"] = Vers,
            ["deps"] = deps,
            ["cksum"] = cksum,
            ["features"] = features,
            ["yanked"] = yanked,
        };
        if (Links is not null)
        {
            line["links"] = Links;
        }

        return line.ToJsonString(CargoPublishJsonContext.CompactOptions);
    }
}

/// <summary>
/// A dependency in the Cargo publish-frame metadata. <c>version_req</c> is the publish-form
/// name for what the sparse index calls <c>req</c>. A null <c>registry</c> means the
/// dependency resolves against this same registry.
/// </summary>
public sealed class CargoPublishDep
{
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("version_req")] public string VersionReq { get; init; } = "";
    [JsonPropertyName("features")] public List<string> Features { get; init; } = new();
    [JsonPropertyName("optional")] public bool Optional { get; init; }
    [JsonPropertyName("default_features")] public bool DefaultFeatures { get; init; } = true;
    [JsonPropertyName("target")] public string? Target { get; init; }
    [JsonPropertyName("kind")] public string? Kind { get; init; }
    [JsonPropertyName("registry")] public string? Registry { get; init; }

    /// <summary>
    /// Renders this dependency in sparse-index form: <c>version_req</c> → <c>req</c>, the
    /// optional package rename (<c>explicit_name_in_toml</c>) preserved as <c>package</c> when
    /// present, and <c>registry</c> carried through (null for a same-registry dependency).
    /// </summary>
    public JsonNode ToIndexNode()
    {
        var featuresArr = new JsonArray();
        foreach (string f in Features)
        {
            featuresArr.Add(f);
        }

        return new JsonObject
        {
            ["name"] = Name,
            ["req"] = VersionReq,
            ["features"] = featuresArr,
            ["optional"] = Optional,
            ["default_features"] = DefaultFeatures,
            ["target"] = Target,
            ["kind"] = Kind ?? "normal",
            ["registry"] = Registry,
        };
    }
}

/// <summary>JSON options for Cargo publish-frame (de)serialization.</summary>
internal static class CargoPublishJsonContext
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    /// <summary>Compact, no-indent serialization for sparse-index lines (one JSON object per line).</summary>
    public static readonly JsonSerializerOptions CompactOptions = new()
    {
        WriteIndented = false,
    };
}
