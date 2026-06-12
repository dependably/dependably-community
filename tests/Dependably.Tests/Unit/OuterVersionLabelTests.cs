using Dependably.Protocol;

namespace Dependably.Tests.Unit;

/// <summary>
/// Coverage for the outer-label version extractor. The override is invisible for canonical
/// publish-tool output (where wrappers are <c>package/</c>, filenames match embedded
/// metadata, etc.) and only kicks in for source-archive / relabelled shapes — so each helper
/// is tested with both the positive case (override applies) and the negative case (override
/// is silent, caller keeps the embedded value).
/// </summary>
[Trait("Category", "Unit")]
public sealed class OuterVersionLabelTests
{
    // ── npm wrapper-dir override ─────────────────────────────────────────────

    [Theory]
    [InlineData("mermaid-mermaid-11.13.0", "11.13.0")]
    [InlineData("acme-pkg-1.2.3", "1.2.3")]
    [InlineData("pkg-1.2.3-beta.1", "1.2.3-beta.1")]
    [InlineData("pkg-1.2.3-beta.1+build.7", "1.2.3-beta.1+build.7")]
    [InlineData("pkg-0.0.1", "0.0.1")]
    public void NpmWrapper_Extracts_Semver(string wrapper, string expected)
    {
        Assert.True(OuterVersionLabel.TryFromNpmWrapper(wrapper, out string? v));
        Assert.Equal(expected, v);
    }

    [Theory]
    [InlineData("package")]                  // canonical npm pack — no override
    [InlineData("my-monorepo")]              // no version suffix
    [InlineData("node-v16")]                 // not three numeric components
    [InlineData("pkg-1.2")]                  // only two components — not semver
    [InlineData("pkg-1")]                    // only one component
    [InlineData("")]                         // root-level entry, no wrapper
    [InlineData("pkg")]                      // no dash at all
    public void NpmWrapper_Does_Not_Match_NonSemver(string wrapper)
    {
        Assert.False(OuterVersionLabel.TryFromNpmWrapper(wrapper, out _));
    }

    // ── PyPI sdist wrapper-dir override ──────────────────────────────────────

    [Theory]
    [InlineData("myproj-1.0.0", "1.0.0")]
    [InlineData("myproj-1.0.0a1", "1.0.0a1")]           // PEP 440 prerelease
    [InlineData("myproj-1.0.0.post1", "1.0.0.post1")]   // PEP 440 post-release
    [InlineData("my-proj-2.0.0", "2.0.0")]              // multi-segment name
    [InlineData("myproj-1.0.0+local", "1.0.0+local")]   // PEP 440 local version
    public void PyPiSdistWrapper_Extracts_Pep440(string wrapper, string expected)
    {
        Assert.True(OuterVersionLabel.TryFromPyPiSdistWrapper(wrapper, out string? v));
        Assert.Equal(expected, v);
    }

    [Theory]
    [InlineData("myproj")]                   // no dash
    [InlineData("my-proj-name")]             // no digit-leading suffix
    [InlineData("")]
    public void PyPiSdistWrapper_Does_Not_Match_NonPep440(string wrapper)
    {
        Assert.False(OuterVersionLabel.TryFromPyPiSdistWrapper(wrapper, out _));
    }

    // ── PEP 427 wheel filename ───────────────────────────────────────────────

    [Theory]
    [InlineData("mermaid-11.13.0-py3-none-any.whl", "11.13.0")]
    [InlineData("acme_pkg-1.0.0-py3-none-any.whl", "1.0.0")]
    [InlineData("acme-2.0.0-1-py3-none-any.whl", "2.0.0")]   // with build tag
    public void WheelFilename_Extracts_Version(string filename, string expected)
    {
        Assert.True(OuterVersionLabel.TryFromWheelFilename(filename, out string? v));
        Assert.Equal(expected, v);
    }

    [Theory]
    [InlineData("not-a-wheel.tar.gz")]
    [InlineData("pkg-1.0.0.whl")]                            // only 2 segments — not PEP 427
    [InlineData("pkg-1.0.0-py3-none.whl")]                   // only 4 segments
    [InlineData("")]
    [InlineData("pkg--py3-none-any.whl")]                    // empty version segment (candidate.Length == 0)
    [InlineData("pkg-alpha-py3-none-any.whl")]               // non-digit-leading candidate
    public void WheelFilename_Does_Not_Match_NonPep427(string filename)
    {
        Assert.False(OuterVersionLabel.TryFromWheelFilename(filename, out _));
    }

    [Theory]
    [InlineData("acme-1.0.0-py3-none-any.WHL", "1.0.0")]     // uppercase extension — OrdinalIgnoreCase branch
    public void WheelFilename_Matches_Case_Insensitively(string filename, string expected)
    {
        Assert.True(OuterVersionLabel.TryFromWheelFilename(filename, out string? v));
        Assert.Equal(expected, v);
    }

    // ── NuGet nupkg filename ─────────────────────────────────────────────────

    [Theory]
    [InlineData("Microsoft.AspNetCore.App.6.0.0.nupkg", "6.0.0")]
    [InlineData("Newtonsoft.Json.13.0.3.nupkg", "13.0.3")]
    [InlineData("Foo.Bar.1.2.3-beta.nupkg", "1.2.3-beta")]
    [InlineData("Simple.1.0.0.nupkg", "1.0.0")]
    [InlineData("Pkg.1.0.0.snupkg", "1.0.0")]                // symbols package
    public void NupkgFilename_Extracts_Version(string filename, string expected)
    {
        Assert.True(OuterVersionLabel.TryFromNupkgFilename(filename, out string? v));
        Assert.Equal(expected, v);
    }

    [Theory]
    [InlineData("notapackage.zip")]
    [InlineData("NoVersionHere.nupkg")]
    [InlineData("")]
    [InlineData("Pkg..nupkg")]                               // empty candidate after dot (Length == 0)
    [InlineData("Pkg.1..nupkg")]                             // candidate starts with digit but TryParse rejects
    public void NupkgFilename_Does_Not_Match_NonNupkg(string filename)
    {
        Assert.False(OuterVersionLabel.TryFromNupkgFilename(filename, out _));
    }

    [Theory]
    [InlineData("Simple.1.0.0.NUPKG", "1.0.0")]              // uppercase extension — OrdinalIgnoreCase branch
    [InlineData("Pkg.1.0.0.SNUPKG", "1.0.0")]                // uppercase symbols extension
    public void NupkgFilename_Matches_Case_Insensitively(string filename, string expected)
    {
        Assert.True(OuterVersionLabel.TryFromNupkgFilename(filename, out string? v));
        Assert.Equal(expected, v);
    }
}
