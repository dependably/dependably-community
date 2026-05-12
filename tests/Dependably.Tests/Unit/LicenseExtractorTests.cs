using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using System.Text.Json.Nodes;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit;

public class LicenseExtractorTests
{
    // ── PyPI: real fixtures ──────────────────────────────────────────────────

    [Fact]
    public void PyPi_Wheel_RealFixture_ExtractsLicense()
    {
        var bytes = File.ReadAllBytes(Path.Combine(
            FixtureManifest.FixturesRoot, "pypi", "mypy_extensions-1.0.0-py3-none-any.whl"));
        var result = LicenseExtractor.FromPyPiPackageBytes(bytes, "mypy_extensions-1.0.0-py3-none-any.whl");
        Assert.NotEmpty(result.Spdx);
        Assert.Null(result.Deprecated);
    }

    [Fact]
    public void PyPi_Sdist_RealFixture_ExtractsLicense()
    {
        var bytes = File.ReadAllBytes(Path.Combine(
            FixtureManifest.FixturesRoot, "pypi", "mypy_extensions-1.0.0.tar.gz"));
        var result = LicenseExtractor.FromPyPiPackageBytes(bytes, "mypy_extensions-1.0.0.tar.gz");
        Assert.NotEmpty(result.Spdx);
    }

    // ── PyPI: synthetic METADATA cases ───────────────────────────────────────

    [Fact]
    public void PyPi_Synthetic_LicenseExpression_PreferredOverFreeText()
    {
        var bytes = BuildWheel("""
            Metadata-Version: 2.3
            Name: foo
            Version: 1.0
            License-Expression: MIT OR Apache-2.0
            License: This is some legalese describing the MIT license.

            body
            """);
        var result = LicenseExtractor.FromPyPiPackageBytes(bytes, "foo-1.0-py3-none-any.whl");
        Assert.Equal(new[] { "MIT OR Apache-2.0" }, result.Spdx);
    }

    [Fact]
    public void PyPi_Synthetic_FreeTextLicense_RejectedWhenMultiline()
    {
        var bytes = BuildWheel("""
            Metadata-Version: 2.1
            Name: foo
            Version: 1.0
            License: Copyright (c) 2024 Example
                    Permission is hereby granted, free of charge,
                    to any person obtaining a copy...

            body
            """);
        var result = LicenseExtractor.FromPyPiPackageBytes(bytes, "foo-1.0-py3-none-any.whl");
        Assert.Empty(result.Spdx);
    }

    [Fact]
    public void PyPi_Synthetic_FreeTextLicense_AcceptedWhenSpdxShaped()
    {
        var bytes = BuildWheel("""
            Metadata-Version: 2.1
            Name: foo
            Version: 1.0
            License: BSD-3-Clause

            body
            """);
        var result = LicenseExtractor.FromPyPiPackageBytes(bytes, "foo-1.0-py3-none-any.whl");
        Assert.Equal(new[] { "BSD-3-Clause" }, result.Spdx);
    }

    [Fact]
    public void PyPi_Synthetic_NoLicenseFields_ReturnsEmpty()
    {
        var bytes = BuildWheel("""
            Metadata-Version: 2.1
            Name: foo
            Version: 1.0

            body
            """);
        var result = LicenseExtractor.FromPyPiPackageBytes(bytes, "foo-1.0-py3-none-any.whl");
        Assert.Empty(result.Spdx);
        Assert.Null(result.Deprecated);
    }

    [Fact]
    public void PyPi_MalformedZip_ReturnsEmptyWithoutThrowing()
    {
        var bytes = Encoding.UTF8.GetBytes("not a zip file at all");
        var result = LicenseExtractor.FromPyPiPackageBytes(bytes, "broken.whl");
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    // ── npm: real fixture ────────────────────────────────────────────────────

    [Fact]
    public void Npm_Tarball_RealFixture_ExtractsLicense()
    {
        var bytes = File.ReadAllBytes(Path.Combine(
            FixtureManifest.FixturesRoot, "npm", "is-odd-3.0.1.tgz"));
        var result = LicenseExtractor.FromNpmTarballPackageJson(bytes);
        Assert.NotEmpty(result.Spdx);
    }

    // ── npm: JsonNode shapes ─────────────────────────────────────────────────

    [Fact]
    public void Npm_LicenseAsString_Extracted()
    {
        var node = JsonNode.Parse("""{"license":"MIT"}""");
        var result = LicenseExtractor.FromNpmPackumentVersion(node);
        Assert.Equal(new[] { "MIT" }, result.Spdx);
    }

    [Fact]
    public void Npm_LicenseAsObject_Extracted()
    {
        var node = JsonNode.Parse("""{"license":{"type":"Apache-2.0","url":"https://..."}}""");
        var result = LicenseExtractor.FromNpmPackumentVersion(node);
        Assert.Equal(new[] { "Apache-2.0" }, result.Spdx);
    }

    [Fact]
    public void Npm_LegacyPluralLicenses_Extracted()
    {
        var node = JsonNode.Parse("""
            {"licenses":[{"type":"MIT","url":"x"},{"type":"Apache-2.0","url":"y"}]}
            """);
        var result = LicenseExtractor.FromNpmPackumentVersion(node);
        Assert.Equal(new[] { "MIT", "Apache-2.0" }, result.Spdx);
    }

    [Fact]
    public void Npm_DeprecatedString_PassedThrough()
    {
        var node = JsonNode.Parse("""{"license":"MIT","deprecated":"use foo@2 instead"}""");
        var result = LicenseExtractor.FromNpmPackumentVersion(node);
        Assert.Equal("use foo@2 instead", result.Deprecated);
    }

    [Fact]
    public void Npm_DeprecatedAsBoolean_NotPassedThrough()
    {
        // Some old packages set deprecated: true rather than a string message.
        var node = JsonNode.Parse("""{"license":"MIT","deprecated":true}""");
        var result = LicenseExtractor.FromNpmPackumentVersion(node);
        Assert.Null(result.Deprecated);
    }

    [Fact]
    public void Npm_NoLicenseOrDeprecated_ReturnsEmpty()
    {
        var node = JsonNode.Parse("""{"name":"foo","version":"1.0.0"}""");
        var result = LicenseExtractor.FromNpmPackumentVersion(node);
        Assert.Empty(result.Spdx);
        Assert.Null(result.Deprecated);
    }

    // ── NuGet: real fixture ──────────────────────────────────────────────────

    [Fact]
    public void NuGet_Nupkg_RealFixture_ExtractsLicense()
    {
        var bytes = File.ReadAllBytes(Path.Combine(
            FixtureManifest.FixturesRoot, "nuget", "Newtonsoft.Json.13.0.3.nupkg"));
        var result = LicenseExtractor.FromNuspec(bytes);
        Assert.Equal(new[] { "MIT" }, result.Spdx);
    }

    // ── NuGet: synthetic .nuspec shapes ──────────────────────────────────────

    [Fact]
    public void NuGet_Synthetic_LicenseTypeFile_Ignored()
    {
        var bytes = BuildNupkg("""
            <?xml version="1.0"?>
            <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
              <metadata>
                <id>Foo</id>
                <version>1.0.0</version>
                <license type="file">LICENSE.txt</license>
              </metadata>
            </package>
            """);
        var result = LicenseExtractor.FromNuspec(bytes);
        Assert.Empty(result.Spdx);
    }

    [Fact]
    public void NuGet_Synthetic_NoLicenseElement_ReturnsEmpty()
    {
        var bytes = BuildNupkg("""
            <?xml version="1.0"?>
            <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
              <metadata>
                <id>Foo</id>
                <version>1.0.0</version>
              </metadata>
            </package>
            """);
        var result = LicenseExtractor.FromNuspec(bytes);
        Assert.Empty(result.Spdx);
    }

    [Fact]
    public void NuGet_MalformedXml_ReturnsEmptyWithoutThrowing()
    {
        var bytes = BuildNupkg("not xml");
        var result = LicenseExtractor.FromNuspec(bytes);
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static byte[] BuildWheel(string metadata)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = zip.CreateEntry("foo-1.0.dist-info/METADATA");
            using var s = entry.Open();
            using var w = new StreamWriter(s, new UTF8Encoding(false));
            w.Write(metadata);
        }
        return ms.ToArray();
    }

    private static byte[] BuildNupkg(string nuspecXml)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = zip.CreateEntry("foo.nuspec");
            using var s = entry.Open();
            using var w = new StreamWriter(s, new UTF8Encoding(false));
            w.Write(nuspecXml);
        }
        return ms.ToArray();
    }
}
