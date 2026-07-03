using System.Text.Json;
using System.Text.Json.Nodes;
using Dependably.Protocol;

namespace Dependably.Tests.Unit;

/// <summary>
/// Unit coverage for <see cref="NpmInstallManifest"/> — the allowlist filter that builds
/// the persisted install-manifest subset at hosted npm publish, and the publish-body
/// dist.integrity extractor.
/// </summary>
public class NpmInstallManifestTests
{
    [Fact]
    public void BuildJson_AllowlistsInstallFields_AndDropsEverythingElse()
    {
        var manifest = (JsonObject)JsonNode.Parse("""
            {
              "name": "acme-cli",
              "version": "1.0.0",
              "bin": { "acme": "./bin/acme.js" },
              "dependencies": { "yaml": "^2.0.0" },
              "optionalDependencies": { "fsevents": "^2.0.0" },
              "peerDependencies": { "react": ">=17" },
              "peerDependenciesMeta": { "react": { "optional": true } },
              "engines": { "node": ">=18" },
              "os": ["linux", "darwin"],
              "cpu": ["x64"],
              "directories": { "bin": "./bin" },
              "scripts": { "postinstall": "node evil.js" },
              "readme": "a very large blob",
              "dist": { "integrity": "sha512-forged" },
              "_attachments": { "x.tgz": {} }
            }
            """)!;

        string? json = NpmInstallManifest.BuildJson(manifest, publishBodyVersion: null, "acme-cli");

        Assert.NotNull(json);
        var result = (JsonObject)JsonNode.Parse(json!)!;
        Assert.Equal("./bin/acme.js", result["bin"]?["acme"]?.GetValue<string>());
        Assert.Equal("^2.0.0", result["dependencies"]?["yaml"]?.GetValue<string>());
        Assert.NotNull(result["optionalDependencies"]);
        Assert.NotNull(result["peerDependencies"]);
        Assert.NotNull(result["peerDependenciesMeta"]);
        Assert.Equal(">=18", result["engines"]?["node"]?.GetValue<string>());
        Assert.NotNull(result["os"]);
        Assert.NotNull(result["cpu"]);
        Assert.NotNull(result["directories"]);
        // Registry-authoritative and non-install fields never land in the stored subset.
        Assert.False(result.ContainsKey("name"));
        Assert.False(result.ContainsKey("version"));
        Assert.False(result.ContainsKey("dist"));
        Assert.False(result.ContainsKey("scripts"));
        Assert.False(result.ContainsKey("readme"));
        Assert.False(result.ContainsKey("_attachments"));
    }

    [Theory]
    [InlineData("acme-cli", "acme-cli")]
    [InlineData("@scope/acme-cli", "acme-cli")]
    public void BuildJson_StringBin_NormalizedToObjectKeyedByUnscopedName(string fullName, string expectedKey)
    {
        var manifest = (JsonObject)JsonNode.Parse("""{"bin": "./cli.js"}""")!;

        string? json = NpmInstallManifest.BuildJson(manifest, publishBodyVersion: null, fullName);

        var result = (JsonObject)JsonNode.Parse(json!)!;
        Assert.Equal(JsonValueKind.Object, result["bin"]!.GetValueKind());
        Assert.Equal("./cli.js", result["bin"]![expectedKey]?.GetValue<string>());
    }

    [Fact]
    public void BuildJson_ObjectBin_PreservedVerbatim()
    {
        var manifest = (JsonObject)JsonNode.Parse("""{"bin": {"a": "./a.js", "b": "./b.js"}}""")!;

        string? json = NpmInstallManifest.BuildJson(manifest, publishBodyVersion: null, "acme");

        var result = (JsonObject)JsonNode.Parse(json!)!;
        Assert.Equal("./a.js", result["bin"]?["a"]?.GetValue<string>());
        Assert.Equal("./b.js", result["bin"]?["b"]?.GetValue<string>());
    }

    [Fact]
    public void BuildJson_HasShrinkwrap_TakenFromPublishBodyOnlyWhenBoolean()
    {
        var manifest = (JsonObject)JsonNode.Parse("""{"dependencies": {"a": "1.0.0"}}""")!;
        var bodyTrue = JsonNode.Parse("""{"_hasShrinkwrap": true}""");
        var bodyString = JsonNode.Parse("""{"_hasShrinkwrap": "yes"}""");

        var withTrue = (JsonObject)JsonNode.Parse(
            NpmInstallManifest.BuildJson(manifest, bodyTrue, "acme")!)!;
        Assert.True(withTrue["_hasShrinkwrap"]!.GetValue<bool>());

        var withString = (JsonObject)JsonNode.Parse(
            NpmInstallManifest.BuildJson(manifest, bodyString, "acme")!)!;
        Assert.False(withString.ContainsKey("_hasShrinkwrap"));

        var withoutBody = (JsonObject)JsonNode.Parse(
            NpmInstallManifest.BuildJson(manifest, publishBodyVersion: null, "acme")!)!;
        Assert.False(withoutBody.ContainsKey("_hasShrinkwrap"));
    }

    [Fact]
    public void BuildJson_NoInstallRelevantFields_ReturnsNull()
    {
        var manifest = (JsonObject)JsonNode.Parse(
            """{"name": "acme", "version": "1.0.0", "description": "x", "main": "index.js"}""")!;

        Assert.Null(NpmInstallManifest.BuildJson(manifest, publishBodyVersion: null, "acme"));
        Assert.Null(NpmInstallManifest.BuildJson(null, publishBodyVersion: null, "acme"));
    }

    [Fact]
    public void DeclaredIntegritySri_Sha512_ReturnedVerbatim()
    {
        var body = JsonNode.Parse("""{"dist": {"integrity": "sha512-AbCd/EfG=="}}""");
        Assert.Equal("sha512-AbCd/EfG==", NpmInstallManifest.DeclaredIntegritySri(body));
    }

    [Theory]
    [InlineData("""{"dist": {"integrity": "sha1-deadbeef"}}""")]   // wrong algorithm
    [InlineData("""{"dist": {"integrity": 42}}""")]                 // non-string
    [InlineData("""{"dist": {}}""")]                                // missing integrity
    [InlineData("""{}""")]                                          // missing dist
    public void DeclaredIntegritySri_NonSha512OrMissing_ReturnsNull(string bodyJson)
    {
        Assert.Null(NpmInstallManifest.DeclaredIntegritySri(JsonNode.Parse(bodyJson)));
    }

    [Fact]
    public void DeclaredIntegritySri_NullBody_ReturnsNull()
    {
        Assert.Null(NpmInstallManifest.DeclaredIntegritySri(null));
    }
}
