using Dependably.Protocol;
using Xunit;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class ManifestParserTests
{
    // ── Detect ────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("package-lock.json", "{}", ManifestParser.ManifestType.NpmPackageLock)]
    [InlineData("PACKAGE-LOCK.JSON", "{}", ManifestParser.ManifestType.NpmPackageLock)]
    [InlineData("path/to/package-lock.json", "{}", ManifestParser.ManifestType.NpmPackageLock)]
    [InlineData("requirements.txt", "django==4.0", ManifestParser.ManifestType.PipRequirements)]
    [InlineData("packages.lock.json", "{}", ManifestParser.ManifestType.NuGetPackagesLock)]
    public void Detect_PrefersFilename(string filename, string content, ManifestParser.ManifestType expected)
    {
        Assert.Equal(expected, ManifestParser.Detect(filename, content));
    }

    [Fact]
    public void Detect_SniffsNpmFromLockfileVersion()
    {
        Assert.Equal(
            ManifestParser.ManifestType.NpmPackageLock,
            ManifestParser.Detect("unknown.json", """{"lockfileVersion": 2}"""));
    }

    [Fact]
    public void Detect_SniffsNuGetFromDependenciesPlusVersion()
    {
        Assert.Equal(
            ManifestParser.ManifestType.NuGetPackagesLock,
            ManifestParser.Detect("unknown.json", """{"version": 1, "dependencies": {"net8.0": {}}}"""));
    }

    [Fact]
    public void Detect_TextContentFallsBackToPip()
    {
        Assert.Equal(
            ManifestParser.ManifestType.PipRequirements,
            ManifestParser.Detect("anything.txt", "django==4.0\n"));
    }

    [Fact]
    public void Detect_EmptyContent_Unknown()
    {
        Assert.Equal(ManifestParser.ManifestType.Unknown, ManifestParser.Detect("anything", ""));
    }

    [Fact]
    public void Detect_MalformedJson_Unknown()
    {
        Assert.Equal(ManifestParser.ManifestType.Unknown, ManifestParser.Detect("foo.json", "{not-json"));
    }

    // ── Parse: npm v2/v3 ──────────────────────────────────────────────────────

    [Fact]
    public void ParseNpm_V2_ReadsPackagesMap_AndSkipsRoot()
    {
        var json = """
        {
          "lockfileVersion": 2,
          "packages": {
            "": { "name": "root", "version": "0.0.0" },
            "node_modules/lodash": { "version": "4.17.21", "integrity": "sha512-AAAA" },
            "node_modules/@scope/pkg": { "version": "1.0.0" }
          }
        }
        """;

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NpmPackageLock, json);

        Assert.Equal(2, entries.Count);
        Assert.Contains(entries, e => e.Ecosystem == "npm" && e.Name == "lodash" && e.Version == "4.17.21");
        Assert.Contains(entries, e => e.Ecosystem == "npm" && e.Name == "@scope/pkg" && e.Version == "1.0.0");
    }

    [Fact]
    public void ParseNpm_V2_ExtractsLeafFromNestedNodeModules()
    {
        var json = """
        {
          "lockfileVersion": 3,
          "packages": {
            "node_modules/a/node_modules/b": { "version": "2.0.0" }
          }
        }
        """;

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NpmPackageLock, json);

        Assert.Single(entries);
        Assert.Equal("b", entries[0].Name);
        Assert.Equal("2.0.0", entries[0].Version);
    }

    [Fact]
    public void ParseNpm_V2_SkipsNonNodeModulesPath()
    {
        var json = """
        {
          "lockfileVersion": 2,
          "packages": {
            "workspaces/something": { "version": "1.0.0" },
            "node_modules/x": { "version": "1.0.0" }
          }
        }
        """;

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NpmPackageLock, json);

        Assert.Single(entries);
        Assert.Equal("x", entries[0].Name);
    }

    [Fact]
    public void ParseNpm_V2_SkipsEntriesWithoutVersion()
    {
        var json = """
        {
          "lockfileVersion": 2,
          "packages": {
            "node_modules/no-ver": { "integrity": "sha256-AA" },
            "node_modules/good": { "version": "1.0.0" }
          }
        }
        """;

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NpmPackageLock, json);

        Assert.Single(entries);
        Assert.Equal("good", entries[0].Name);
    }

    [Fact]
    public void ParseNpm_IntegritySha256_DecodedToHex()
    {
        // base64("hello") = "aGVsbG8=" → hex = "68656c6c6f"
        var json = """
        {
          "lockfileVersion": 2,
          "packages": {
            "node_modules/x": { "version": "1.0.0", "integrity": "sha256-aGVsbG8=" }
          }
        }
        """;

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NpmPackageLock, json);

        Assert.Single(entries);
        Assert.Equal("68656c6c6f", entries[0].Sha256);
    }

    [Fact]
    public void ParseNpm_IntegritySha512_NotRecorded()
    {
        var json = """
        {
          "lockfileVersion": 2,
          "packages": {
            "node_modules/x": { "version": "1.0.0", "integrity": "sha512-AAAA" }
          }
        }
        """;

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NpmPackageLock, json);

        Assert.Null(entries[0].Sha256);
    }

    [Fact]
    public void ParseNpm_IntegrityInvalidBase64_Null()
    {
        var json = """
        {
          "lockfileVersion": 2,
          "packages": {
            "node_modules/x": { "version": "1.0.0", "integrity": "sha256-not!valid!b64!" }
          }
        }
        """;

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NpmPackageLock, json);

        Assert.Null(entries[0].Sha256);
    }

    // ── Parse: npm v1 ─────────────────────────────────────────────────────────

    [Fact]
    public void ParseNpm_V1_WalksNestedTree_AndDedupes()
    {
        var json = """
        {
          "lockfileVersion": 1,
          "dependencies": {
            "lodash": {
              "version": "4.17.21",
              "dependencies": {
                "lodash": { "version": "4.17.21" },
                "leaf": { "version": "1.0.0" }
              }
            }
          }
        }
        """;

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NpmPackageLock, json);

        // lodash 4.17.21 appears twice in the tree, deduped to one entry.
        Assert.Equal(2, entries.Count);
        Assert.Contains(entries, e => e.Name == "lodash" && e.Version == "4.17.21");
        Assert.Contains(entries, e => e.Name == "leaf" && e.Version == "1.0.0");
    }

    [Fact]
    public void ParseNpm_NoLockfileVersion_TreatedAsV1()
    {
        var json = """
        {
          "dependencies": {
            "x": { "version": "1.0.0" }
          }
        }
        """;

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NpmPackageLock, json);

        Assert.Single(entries);
    }

    // ── Parse: pip requirements ───────────────────────────────────────────────

    [Fact]
    public void ParsePip_StrictEqualsOnly()
    {
        var content = "django==4.0\nflask>=2.0\nrequests~=2.28\n";
        var entries = ManifestParser.Parse(ManifestParser.ManifestType.PipRequirements, content);

        Assert.Single(entries);
        Assert.Equal("django", entries[0].Name);
        Assert.Equal("4.0", entries[0].Version);
    }

    [Fact]
    public void ParsePip_SkipsBlankCommentAndOptionLines()
    {
        var content = """
        # comment
        --index-url https://pypi.org

        django==4.0
        """;
        var entries = ManifestParser.Parse(ManifestParser.ManifestType.PipRequirements, content);

        Assert.Single(entries);
    }

    [Fact]
    public void ParsePip_StripsInlineCommentAndEnvMarker()
    {
        var content = "django==4.0 ; python_version >= '3.8'  # latest LTS\n";
        var entries = ManifestParser.Parse(ManifestParser.ManifestType.PipRequirements, content);

        Assert.Single(entries);
        Assert.Equal("4.0", entries[0].Version);
    }

    [Fact]
    public void ParsePip_NormalizesNameToPep503()
    {
        var content = "My_Package==1.0\n";
        var entries = ManifestParser.Parse(ManifestParser.ManifestType.PipRequirements, content);

        Assert.Single(entries);
        // PyPiArtifactValidator.Normalize lowercases and replaces _ with -.
        Assert.Equal("my-package", entries[0].Name);
    }

    [Fact]
    public void ParsePip_StitchesLineContinuations_AndExtractsSha256Hash()
    {
        var hash = new string('a', 64);
        var content = $"django==4.0 \\\n  --hash=sha256:{hash}\n";
        var entries = ManifestParser.Parse(ManifestParser.ManifestType.PipRequirements, content);

        Assert.Single(entries);
        Assert.Equal(hash, entries[0].Sha256);
    }

    [Fact]
    public void ParsePip_NonSha256HashIsIgnored()
    {
        var content = "django==4.0 --hash=md5:abc123\n";
        var entries = ManifestParser.Parse(ManifestParser.ManifestType.PipRequirements, content);

        Assert.Single(entries);
        Assert.Null(entries[0].Sha256);
    }

    // ── Parse: NuGet ──────────────────────────────────────────────────────────

    [Fact]
    public void ParseNuGet_ReadsResolvedAndContentHash_AcrossFrameworks_Deduped()
    {
        var json = """
        {
          "version": 1,
          "dependencies": {
            "net8.0": {
              "Newtonsoft.Json": { "type": "Direct", "resolved": "13.0.3", "contentHash": "HASHHASH==" }
            },
            "net9.0": {
              "Newtonsoft.Json": { "type": "Direct", "resolved": "13.0.3", "contentHash": "HASHHASH==" }
            }
          }
        }
        """;

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NuGetPackagesLock, json);

        Assert.Single(entries);
        Assert.Equal("nuget", entries[0].Ecosystem);
        Assert.Equal("newtonsoft.json", entries[0].Name);
        Assert.Equal("13.0.3", entries[0].Version);
        Assert.Equal("HASHHASH==", entries[0].Sha256);
    }

    [Fact]
    public void ParseNuGet_SkipsEntriesWithoutResolved()
    {
        var json = """
        {
          "dependencies": {
            "net8.0": {
              "Foo": { "type": "Project" },
              "Bar": { "type": "Direct", "resolved": "1.0.0" }
            }
          }
        }
        """;

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NuGetPackagesLock, json);

        Assert.Single(entries);
        Assert.Equal("bar", entries[0].Name);
    }

    [Fact]
    public void ParseNuGet_MissingDependenciesBlock_Empty()
    {
        var entries = ManifestParser.Parse(
            ManifestParser.ManifestType.NuGetPackagesLock,
            """{"version": 1}""");

        Assert.Empty(entries);
    }

    // ── Parse: unknown type ───────────────────────────────────────────────────

    [Fact]
    public void Parse_UnknownType_Empty()
    {
        Assert.Empty(ManifestParser.Parse(ManifestParser.ManifestType.Unknown, "anything"));
    }

    // ── Branch coverage extensions ────────────────────────────────────────────

    [Fact]
    public void Detect_JsonWithoutLockfileVersionOrNuGetShape_Unknown()
    {
        // {-prefixed JSON, parses cleanly, but has neither lockfileVersion nor (deps-object + version).
        Assert.Equal(
            ManifestParser.ManifestType.Unknown,
            ManifestParser.Detect("foo.json", """{"name": "thing"}"""));
    }

    [Fact]
    public void Detect_JsonWithDependenciesArray_FallsThroughToUnknown()
    {
        // dependencies is present but not an object — the NuGet sniff condition rejects it.
        Assert.Equal(
            ManifestParser.ManifestType.Unknown,
            ManifestParser.Detect("foo.json", """{"version": 1, "dependencies": []}"""));
    }

    [Fact]
    public void Detect_JsonWithDependenciesObjectButNoVersion_Unknown()
    {
        // dependencies-object present but no top-level "version" — NuGet sniff fails on AND.
        Assert.Equal(
            ManifestParser.ManifestType.Unknown,
            ManifestParser.Detect("foo.json", """{"dependencies": {"net8.0": {}}}"""));
    }

    [Fact]
    public void Detect_LeadingWhitespaceJson_StillSniffed()
    {
        Assert.Equal(
            ManifestParser.ManifestType.NpmPackageLock,
            ManifestParser.Detect("foo.json", "   \n\t{\"lockfileVersion\": 2}"));
    }

    [Fact]
    public void Detect_WhitespaceOnlyContent_Unknown()
    {
        // TrimStart yields empty, so the text-fallback branch is skipped — returns Unknown.
        Assert.Equal(ManifestParser.ManifestType.Unknown, ManifestParser.Detect("anything", "   \n\t  "));
    }

    [Fact]
    public void ParseNpm_V2_MissingPackagesMap_FallsBackToV1Dependencies()
    {
        // lockfileVersion >= 2 but no "packages" — the v1 walk fires instead.
        var json = """
        {
          "lockfileVersion": 2,
          "dependencies": {
            "fallback": { "version": "1.2.3" }
          }
        }
        """;

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NpmPackageLock, json);

        Assert.Single(entries);
        Assert.Equal("fallback", entries[0].Name);
        Assert.Equal("1.2.3", entries[0].Version);
    }

    [Fact]
    public void ParseNpm_V2_PackagesNotAnObject_FallsBackToV1()
    {
        // packages is an array (non-object) — v2 walk skipped, v1 walk fires.
        var json = """
        {
          "lockfileVersion": 2,
          "packages": [],
          "dependencies": {
            "x": { "version": "9.9.9" }
          }
        }
        """;

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NpmPackageLock, json);

        Assert.Single(entries);
        Assert.Equal("x", entries[0].Name);
    }

    [Fact]
    public void ParseNpm_V2_NoPackagesAndNoDependencies_Empty()
    {
        // lockfileVersion >= 2 but neither key — both branches skipped, result empty.
        var json = """{"lockfileVersion": 3}""";

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NpmPackageLock, json);

        Assert.Empty(entries);
    }

    [Fact]
    public void ParseNpm_LockfileVersionNonNumber_TreatedAsV1()
    {
        // lockfileVersion is a string, not a number — LockfileVersion helper returns 1.
        var json = """
        {
          "lockfileVersion": "two",
          "dependencies": {
            "x": { "version": "1.0.0" }
          }
        }
        """;

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NpmPackageLock, json);

        Assert.Single(entries);
        Assert.Equal("x", entries[0].Name);
    }

    [Fact]
    public void ParseNpm_V2_VersionNonString_Skipped()
    {
        // version field present but a number, not a string — entry skipped.
        var json = """
        {
          "lockfileVersion": 2,
          "packages": {
            "node_modules/bad": { "version": 1 },
            "node_modules/good": { "version": "1.0.0" }
          }
        }
        """;

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NpmPackageLock, json);

        Assert.Single(entries);
        Assert.Equal("good", entries[0].Name);
    }

    [Fact]
    public void ParseNpm_V2_IntegrityNonString_NullSha()
    {
        // integrity present but non-string — falls through to null sha.
        var json = """
        {
          "lockfileVersion": 2,
          "packages": {
            "node_modules/x": { "version": "1.0.0", "integrity": 42 }
          }
        }
        """;

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NpmPackageLock, json);

        Assert.Single(entries);
        Assert.Null(entries[0].Sha256);
    }

    [Fact]
    public void ParseNpm_V2_BarePathExactlyNodeModulesSlash_Skipped()
    {
        // "node_modules/" yields rest.Length == 0 → name extraction returns null.
        var json = """
        {
          "lockfileVersion": 2,
          "packages": {
            "node_modules/": { "version": "1.0.0" },
            "node_modules/keep": { "version": "1.0.0" }
          }
        }
        """;

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NpmPackageLock, json);

        Assert.Single(entries);
        Assert.Equal("keep", entries[0].Name);
    }

    [Fact]
    public void ParseNpm_V1_VersionNonString_Skipped()
    {
        var json = """
        {
          "lockfileVersion": 1,
          "dependencies": {
            "bad": { "version": 1 },
            "good": { "version": "1.0.0" }
          }
        }
        """;

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NpmPackageLock, json);

        Assert.Single(entries);
        Assert.Equal("good", entries[0].Name);
    }

    [Fact]
    public void ParseNpm_V1_IntegrityNonString_NullSha()
    {
        var json = """
        {
          "lockfileVersion": 1,
          "dependencies": {
            "x": { "version": "1.0.0", "integrity": 99 }
          }
        }
        """;

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NpmPackageLock, json);

        Assert.Null(entries[0].Sha256);
    }

    [Fact]
    public void ParseNpm_V1_NestedDependenciesNotObject_StopsWalkButKeepsParent()
    {
        // Nested "dependencies" is an array — recursion skipped, parent still recorded.
        var json = """
        {
          "lockfileVersion": 1,
          "dependencies": {
            "parent": { "version": "1.0.0", "dependencies": [] }
          }
        }
        """;

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NpmPackageLock, json);

        Assert.Single(entries);
        Assert.Equal("parent", entries[0].Name);
    }

    [Fact]
    public void ParseNpm_V1_TopDependenciesNotObject_Empty()
    {
        // No lockfileVersion (v1 default) and dependencies is not an object — empty result.
        var json = """{"dependencies": []}""";

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NpmPackageLock, json);

        Assert.Empty(entries);
    }

    [Fact]
    public void ParseNpm_IntegrityEmptyString_Null()
    {
        // integrity is an empty string — ParseIntegrity short-circuits to null.
        var json = """
        {
          "lockfileVersion": 2,
          "packages": {
            "node_modules/x": { "version": "1.0.0", "integrity": "" }
          }
        }
        """;

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NpmPackageLock, json);

        Assert.Null(entries[0].Sha256);
    }

    [Fact]
    public void ParseNpm_UnicodeScopedPackageName_Preserved()
    {
        var json = """
        {
          "lockfileVersion": 2,
          "packages": {
            "node_modules/@café/паке́т": { "version": "1.0.0" }
          }
        }
        """;

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NpmPackageLock, json);

        Assert.Single(entries);
        Assert.Equal("@café/паке́т", entries[0].Name);
    }

    [Fact]
    public void ParsePip_LongVersionString_Preserved()
    {
        var longVer = new string('9', 200);
        var content = $"pkg=={longVer}\n";

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.PipRequirements, content);

        Assert.Single(entries);
        Assert.Equal(longVer, entries[0].Version);
    }

    [Fact]
    public void ParsePip_LineContinuationCrLf_Stitched()
    {
        var hash = new string('b', 64);
        var content = $"django==4.0 \\\r\n  --hash=sha256:{hash}\r\n";

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.PipRequirements, content);

        Assert.Single(entries);
        Assert.Equal(hash, entries[0].Sha256);
    }

    [Fact]
    public void ParsePip_HashFollowedByAnotherHashFlag_TerminatesAtDash()
    {
        // Two hashes on one line — ExtractFirstSha256Hash should stop at the second flag's dash.
        var hash = new string('c', 64);
        var content = $"django==4.0 --hash=sha256:{hash} --hash=sha256:deadbeef\n";

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.PipRequirements, content);

        Assert.Single(entries);
        // Returns the first sha256, truncated at the next '-' before the second --hash flag.
        Assert.Equal(hash, entries[0].Sha256);
    }

    [Fact]
    public void ParsePip_HashTerminatedByTab()
    {
        var hash = new string('d', 64);
        var content = $"django==4.0 --hash=sha256:{hash}\tmore\n";

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.PipRequirements, content);

        Assert.Equal(hash, entries[0].Sha256);
    }

    [Fact]
    public void ParsePip_VersionTerminatedByTab()
    {
        // RHS contains a tab — version trimmed at tab boundary.
        var content = "pkg==1.2.3\tsome trailing\n";

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.PipRequirements, content);

        Assert.Single(entries);
        Assert.Equal("1.2.3", entries[0].Version);
    }

    [Fact]
    public void ParsePip_LineWithoutEquals_Skipped()
    {
        var content = "no-pin-here\nstill-no-pin\n";

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.PipRequirements, content);

        Assert.Empty(entries);
    }

    [Fact]
    public void ParseNuGet_FrameworkValueNonObject_Skipped()
    {
        // "net8.0" maps to an array — filtered out by the Where clause; only the valid framework
        // contributes entries.
        var json = """
        {
          "version": 1,
          "dependencies": {
            "net8.0": [],
            "net9.0": {
              "Foo": { "type": "Direct", "resolved": "1.0.0" }
            }
          }
        }
        """;

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NuGetPackagesLock, json);

        Assert.Single(entries);
        Assert.Equal("foo", entries[0].Name);
    }

    [Fact]
    public void ParseNuGet_PackageValueNonObject_Skipped()
    {
        // The package entry's value is a string, not an object — TryReadNuGetPackageEntry returns null.
        var json = """
        {
          "dependencies": {
            "net8.0": {
              "BogusString": "1.0.0",
              "Valid": { "resolved": "2.0.0" }
            }
          }
        }
        """;

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NuGetPackagesLock, json);

        Assert.Single(entries);
        Assert.Equal("valid", entries[0].Name);
    }

    [Fact]
    public void ParseNuGet_ResolvedNonString_Skipped()
    {
        var json = """
        {
          "dependencies": {
            "net8.0": {
              "Bad": { "resolved": 1 },
              "Good": { "resolved": "1.0.0" }
            }
          }
        }
        """;

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NuGetPackagesLock, json);

        Assert.Single(entries);
        Assert.Equal("good", entries[0].Name);
    }

    [Fact]
    public void ParseNuGet_ContentHashNonString_NullSha()
    {
        var json = """
        {
          "dependencies": {
            "net8.0": {
              "Foo": { "resolved": "1.0.0", "contentHash": 42 }
            }
          }
        }
        """;

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NuGetPackagesLock, json);

        Assert.Single(entries);
        Assert.Null(entries[0].Sha256);
    }

    [Fact]
    public void ParseNuGet_DependenciesNotObject_Empty()
    {
        // Top-level dependencies is an array, not an object — early return with empty list.
        var json = """{"dependencies": []}""";

        var entries = ManifestParser.Parse(ManifestParser.ManifestType.NuGetPackagesLock, json);

        Assert.Empty(entries);
    }
}
