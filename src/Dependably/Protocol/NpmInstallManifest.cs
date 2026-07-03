using System.Text.Json;
using System.Text.Json.Nodes;

namespace Dependably.Protocol;

/// <summary>
/// Builds the install-relevant manifest subset persisted at hosted npm publish
/// (<c>package_versions.manifest_json</c>) and later merged into the packument's
/// per-version objects. Fields are allowlisted to the set npm's install/resolve pipeline
/// reads from the abbreviated (install-v1) packument, so arbitrary manifest content
/// (readme, scripts, publish-body internals) never lands in the metadata index.
/// </summary>
public static class NpmInstallManifest
{
    // Per-version fields npm (arborist / libnpmexec) resolves from the abbreviated
    // packument rather than the unpacked tarball. name/version/dist are
    // registry-authoritative and deliberately excluded; deprecated and hasInstallScript
    // are stored in their own package_versions columns.
    private static readonly string[] InstallFields =
    [
        "bin", "dependencies", "optionalDependencies", "peerDependencies",
        "peerDependenciesMeta", "bundleDependencies", "bundledDependencies",
        "engines", "os", "cpu", "libc", "directories",
    ];

    /// <summary>
    /// Extracts the allowlisted install fields from the tarball's <c>package.json</c>
    /// (artefact-authoritative — the same parse the publish path already performs for
    /// name/version validation). The publish body's <c>versions[v]</c> object contributes
    /// only <c>_hasShrinkwrap</c>, which npm computes client-side and which never appears
    /// in <c>package.json</c> itself. A string-form <c>bin</c> is normalised to the object
    /// form npm serves, keyed by the unscoped package name, since clients resolve
    /// executables by key. Returns null when no install-relevant field is present.
    /// </summary>
    public static string? BuildJson(JsonObject? tarballManifest, JsonNode? publishBodyVersion, string fullName)
    {
        var result = new JsonObject();
        if (tarballManifest is not null)
        {
            foreach (string field in InstallFields)
            {
                if (tarballManifest[field] is { } node)
                {
                    result[field] = node.DeepClone();
                }
            }

            NormalizeBin(result, fullName);
        }

        var shrinkwrap = publishBodyVersion?["_hasShrinkwrap"];
        if (shrinkwrap is not null
            && shrinkwrap.GetValueKind() is JsonValueKind.True or JsonValueKind.False)
        {
            result["_hasShrinkwrap"] = shrinkwrap.GetValue<bool>();
        }

        return result.Count == 0 ? null : result.ToJsonString();
    }

    /// <summary>
    /// Returns the publisher-declared <c>dist.integrity</c> from the publish body's
    /// <c>versions[v]</c> object when it is a sha512 SRI string (the only algorithm npm
    /// clients accept in <c>dist.integrity</c>), otherwise null so the publish service
    /// falls back to a server-computed SRI over the uploaded bytes.
    /// </summary>
    public static string? DeclaredIntegritySri(JsonNode? publishBodyVersion)
    {
        var integrity = publishBodyVersion?["dist"]?["integrity"];
        if (integrity is null || integrity.GetValueKind() != JsonValueKind.String)
        {
            return null;
        }

        string value = integrity.GetValue<string>();
        return value.StartsWith("sha512-", StringComparison.Ordinal) ? value : null;
    }

    // npm normalises "bin": "./cli.js" to {"<unscoped-name>": "./cli.js"} in the packuments
    // it serves; clients (npx, arborist bin-linking) expect the object form.
    private static void NormalizeBin(JsonObject manifest, string fullName)
    {
        var bin = manifest["bin"];
        if (bin is null || bin.GetValueKind() != JsonValueKind.String)
        {
            return;
        }

        int slash = fullName.IndexOf('/');
        string unscoped = fullName.StartsWith('@') && slash > 0 && slash < fullName.Length - 1
            ? fullName[(slash + 1)..]
            : fullName;
        manifest["bin"] = new JsonObject { [unscoped] = bin.GetValue<string>() };
    }
}
