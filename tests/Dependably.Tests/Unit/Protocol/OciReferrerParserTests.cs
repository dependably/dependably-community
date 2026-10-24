using System.Text;
using Dependably.Protocol;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// The OCI 1.1 referrer classification (<see cref="OciReferrerParser"/>): a stored manifest is a
/// referrer of a subject only when its <c>subject.digest</c> matches exactly, and the descriptor it
/// yields carries the caller's coordinates plus the manifest's artifact type and string annotations.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciReferrerParserTests
{
    private const string SubjectDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    private const string CandidateDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    private const string ManifestMediaType = "application/vnd.oci.image.manifest.v1+json";

    private static OciReferrerDescriptor? Parse(string manifestJson) =>
        OciReferrerParser.TryParseReferrer(
            Encoding.UTF8.GetBytes(manifestJson), CandidateDigest, ManifestMediaType, 512L, SubjectDigest);

    [Fact]
    public void Artifact_manifest_naming_the_subject_yields_a_descriptor_with_its_artifact_type()
    {
        var result = Parse($$"""
            {
              "schemaVersion": 2,
              "mediaType": "{{ManifestMediaType}}",
              "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json",
              "config": { "mediaType": "application/vnd.oci.empty.v1+json" },
              "subject": { "mediaType": "{{ManifestMediaType}}", "digest": "{{SubjectDigest}}", "size": 100 }
            }
            """);

        Assert.NotNull(result);
        Assert.Equal(ManifestMediaType, result.MediaType);
        Assert.Equal(CandidateDigest, result.Digest);
        Assert.Equal(512L, result.SizeBytes);
        Assert.Equal("application/vnd.dev.sigstore.bundle.v0.3+json", result.ArtifactType);
        Assert.Null(result.Annotations);
    }

    [Fact]
    public void Image_manifest_without_artifact_type_falls_back_to_the_config_media_type()
    {
        var result = Parse($$"""
            {
              "config": { "mediaType": "application/vnd.example.sbom.config+json" },
              "subject": { "digest": "{{SubjectDigest}}" }
            }
            """);

        Assert.NotNull(result);
        Assert.Equal("application/vnd.example.sbom.config+json", result.ArtifactType);
    }

    [Fact]
    public void Non_string_artifact_type_falls_back_to_the_config_media_type()
    {
        var result = Parse($$"""
            {
              "artifactType": 7,
              "config": { "mediaType": "application/vnd.example.config+json" },
              "subject": { "digest": "{{SubjectDigest}}" }
            }
            """);

        Assert.NotNull(result);
        Assert.Equal("application/vnd.example.config+json", result.ArtifactType);
    }

    [Fact]
    public void Manifest_with_neither_artifact_type_nor_config_has_no_artifact_type()
    {
        var result = Parse($$"""{ "subject": { "digest": "{{SubjectDigest}}" } }""");

        Assert.NotNull(result);
        Assert.Null(result.ArtifactType);
    }

    [Fact]
    public void Only_string_annotations_are_carried_onto_the_descriptor()
    {
        var result = Parse($$"""
            {
              "subject": { "digest": "{{SubjectDigest}}" },
              "annotations": {
                "org.opencontainers.image.created": "2026-01-01T00:00:00Z",
                "org.example.count": 3,
                "org.example.flag": true
              }
            }
            """);

        Assert.NotNull(result);
        Assert.NotNull(result.Annotations);
        var annotation = Assert.Single(result.Annotations);
        Assert.Equal("org.opencontainers.image.created", annotation.Key);
        Assert.Equal("2026-01-01T00:00:00Z", annotation.Value);
    }

    [Fact]
    public void Non_object_annotations_are_ignored()
    {
        var result = Parse($$"""{ "subject": { "digest": "{{SubjectDigest}}" }, "annotations": ["a"] }""");

        Assert.NotNull(result);
        Assert.Null(result.Annotations);
    }

    [Theory]
    [InlineData("")]
    [InlineData("{ not json")]
    [InlineData("[]")]
    [InlineData("\"manifest\"")]
    [InlineData("{}")]
    [InlineData("{ \"subject\": \"sha256:1111111111111111111111111111111111111111111111111111111111111111\" }")]
    [InlineData("{ \"subject\": {} }")]
    [InlineData("{ \"subject\": { \"digest\": 1 } }")]
    [InlineData("{ \"subject\": { \"digest\": \"sha256:3333333333333333333333333333333333333333333333333333333333333333\" } }")]
    [InlineData("{ \"subject\": { \"digest\": \"SHA256:1111111111111111111111111111111111111111111111111111111111111111\" } }")]
    public void Anything_but_a_manifest_naming_the_exact_subject_is_not_a_referrer(string manifestJson) =>
        Assert.Null(Parse(manifestJson));
}
