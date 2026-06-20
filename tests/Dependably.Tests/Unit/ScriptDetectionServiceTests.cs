using System.Buffers.Binary;
using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using Dependably.Protocol;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class ScriptDetectionServiceTests
{
    // ── npm ──────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("preinstall", "npm:preinstall")]
    [InlineData("install", "npm:install")]
    [InlineData("postinstall", "npm:postinstall")]
    public void Npm_WithLifecycleHook_Detected(string hook, string expectedKind)
    {
        byte[] bytes = BuildTarball(
            ("package/package.json",
             "{\"name\":\"acme\",\"version\":\"1.0.0\",\"scripts\":{\"" + hook + "\":\"node setup.js\"}}"));

        var result = ScriptDetectionService.Detect("npm", "acme-1.0.0.tgz", bytes);

        Assert.True(result.HasScript);
        Assert.Equal(expectedKind, result.Kind);
    }

    [Fact]
    public void Npm_PreinstallWinsOverPostinstall()
    {
        // Precedence: preinstall is reported even when postinstall is also present.
        byte[] bytes = BuildTarball(
            ("package/package.json",
             """{"name":"acme","version":"1.0.0","scripts":{"postinstall":"a","preinstall":"b"}}"""));

        var result = ScriptDetectionService.Detect("npm", "acme-1.0.0.tgz", bytes);

        Assert.True(result.HasScript);
        Assert.Equal("npm:preinstall", result.Kind);
    }

    [Fact]
    public void Npm_OnlyNonInstallScripts_NotDetected()
    {
        // test/build hooks are not install-time hooks — must not trip the gate.
        byte[] bytes = BuildTarball(
            ("package/package.json",
             """{"name":"acme","version":"1.0.0","scripts":{"test":"jest","build":"tsc"}}"""));

        var result = ScriptDetectionService.Detect("npm", "acme-1.0.0.tgz", bytes);

        Assert.False(result.HasScript);
        Assert.Null(result.Kind);
    }

    [Fact]
    public void Npm_NoScriptsBlock_NotDetected()
    {
        byte[] bytes = BuildTarball(
            ("package/package.json", """{"name":"acme","version":"1.0.0"}"""));

        var result = ScriptDetectionService.Detect("npm", "acme-1.0.0.tgz", bytes);

        Assert.False(result.HasScript);
    }

    [Fact]
    public void Npm_InvalidGzip_FailsSoftToNone()
    {
        var result = ScriptDetectionService.Detect("npm", "x.tgz", "not gzip"u8.ToArray());
        Assert.False(result.HasScript);
        Assert.Null(result.Kind);
    }

    // ── PyPI ─────────────────────────────────────────────────────────────────

    [Fact]
    public void PyPi_SdistWithSetupPy_Detected()
    {
        byte[] bytes = BuildTarball(
            ("acme-1.0.0/setup.py", "from setuptools import setup\nsetup()\n"),
            ("acme-1.0.0/PKG-INFO", "Name: acme\nVersion: 1.0.0\n"));

        var result = ScriptDetectionService.Detect("pypi", "acme-1.0.0.tar.gz", bytes);

        Assert.True(result.HasScript);
        Assert.Equal("pypi:setup.py", result.Kind);
    }

    [Fact]
    public void PyPi_SdistWithoutSetupPy_NotDetected()
    {
        // A PEP 517 sdist that ships only pyproject.toml runs no setup.py at install time.
        byte[] bytes = BuildTarball(
            ("acme-1.0.0/pyproject.toml", "[build-system]\nrequires=['flit_core']\n"),
            ("acme-1.0.0/PKG-INFO", "Name: acme\nVersion: 1.0.0\n"));

        var result = ScriptDetectionService.Detect("pypi", "acme-1.0.0.tar.gz", bytes);

        Assert.False(result.HasScript);
        Assert.Null(result.Kind);
    }

    [Fact]
    public void PyPi_Wheel_NeverDetected()
    {
        // Even a wheel that somehow carries a setup.py is pre-built and runs no install code.
        byte[] bytes = BuildZip(("acme-1.0.0.dist-info/METADATA", "Name: acme\nVersion: 1.0.0\n"));

        var result = ScriptDetectionService.Detect("pypi", "acme-1.0.0-py3-none-any.whl", bytes);

        Assert.False(result.HasScript);
    }

    [Fact]
    public void PyPi_ZipSdistWithSetupPy_Detected()
    {
        byte[] bytes = BuildZip(("acme-1.0.0/setup.py", "setup()\n"));

        var result = ScriptDetectionService.Detect("pypi", "acme-1.0.0.zip", bytes);

        Assert.True(result.HasScript);
        Assert.Equal("pypi:setup.py", result.Kind);
    }

    [Fact]
    public void PyPi_DeeplyNestedSetupPy_NotDetected()
    {
        // A setup.py buried below the single {name}-{version}/ wrapper is a vendored copy/test
        // fixture, not the install entry point.
        byte[] bytes = BuildTarball(
            ("acme-1.0.0/tests/fixtures/setup.py", "setup()\n"),
            ("acme-1.0.0/PKG-INFO", "Name: acme\nVersion: 1.0.0\n"));

        var result = ScriptDetectionService.Detect("pypi", "acme-1.0.0.tar.gz", bytes);

        Assert.False(result.HasScript);
    }

    // ── NuGet ────────────────────────────────────────────────────────────────

    [Fact]
    public void NuGet_ToolsInstallPs1_Detected()
    {
        byte[] bytes = BuildZip(
            ("Acme.nuspec", "<package/>"),
            ("tools/install.ps1", "param($installPath)"));

        var result = ScriptDetectionService.Detect("nuget", "acme.1.0.0.nupkg", bytes);

        Assert.True(result.HasScript);
        Assert.Equal("nuget:install.ps1", result.Kind);
    }

    [Fact]
    public void NuGet_BuildTargets_DetectedAsMsbuild()
    {
        byte[] bytes = BuildZip(
            ("Acme.nuspec", "<package/>"),
            ("build/Acme.targets", "<Project/>"));

        var result = ScriptDetectionService.Detect("nuget", "acme.1.0.0.nupkg", bytes);

        Assert.True(result.HasScript);
        Assert.Equal("nuget:msbuild", result.Kind);
    }

    [Fact]
    public void NuGet_InstallScriptRanksAboveMsbuild()
    {
        byte[] bytes = BuildZip(
            ("Acme.nuspec", "<package/>"),
            ("build/Acme.props", "<Project/>"),
            ("tools/init.ps1", "param($installPath)"));

        var result = ScriptDetectionService.Detect("nuget", "acme.1.0.0.nupkg", bytes);

        Assert.True(result.HasScript);
        Assert.Equal("nuget:install.ps1", result.Kind);
    }

    [Fact]
    public void NuGet_PlainLibrary_NotDetected()
    {
        byte[] bytes = BuildZip(
            ("Acme.nuspec", "<package/>"),
            ("lib/net8.0/Acme.dll", "binary"));

        var result = ScriptDetectionService.Detect("nuget", "acme.1.0.0.nupkg", bytes);

        Assert.False(result.HasScript);
    }

    // ── RPM ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Rpm_WithPostScriptlet_Detected()
    {
        // A %post scriptlet with a non-empty body is the install-time hook signal.
        byte[] bytes = BuildRpm(postScript: "echo installed");
        var result = ScriptDetectionService.Detect("rpm", "test-1.0-1.x86_64.rpm", bytes);

        Assert.True(result.HasScript);
        Assert.Equal("rpm:scriptlet", result.Kind);
    }

    [Fact]
    public void Rpm_WithPreScriptlet_Detected()
    {
        byte[] bytes = BuildRpm(preScript: "groupadd myapp");
        var result = ScriptDetectionService.Detect("rpm", "test-1.0-1.x86_64.rpm", bytes);

        Assert.True(result.HasScript);
        Assert.Equal("rpm:scriptlet", result.Kind);
    }

    [Fact]
    public void Rpm_ScriptlessPackage_NotDetected()
    {
        byte[] bytes = BuildRpm();
        var result = ScriptDetectionService.Detect("rpm", "test-1.0-1.x86_64.rpm", bytes);

        Assert.False(result.HasScript);
        Assert.Null(result.Kind);
    }

    [Fact]
    public void Rpm_EmptyStringScriptlet_NotDetected()
    {
        // A tag that exists but carries an empty string must not be counted.
        byte[] bytes = BuildRpm(postScript: "");
        var result = ScriptDetectionService.Detect("rpm", "test-1.0-1.x86_64.rpm", bytes);

        Assert.False(result.HasScript);
        Assert.Null(result.Kind);
    }

    [Fact]
    public void Rpm_MalformedBytes_FailsSoftToNone()
    {
        // A corrupt/truncated RPM must not throw — fail-soft returns None.
        var result = ScriptDetectionService.Detect("rpm", "bad.rpm", "not an rpm"u8.ToArray());

        Assert.False(result.HasScript);
        Assert.Null(result.Kind);
    }

    [Fact]
    public async Task Rpm_DetectAsync_StreamOverload_MatchesByteOverload()
    {
        byte[] bytes = BuildRpm(postScript: "echo hello");
        using var stream = new MemoryStream(bytes);

        var result = await ScriptDetectionService.DetectAsync("rpm", "test-1.0-1.x86_64.rpm", stream);

        Assert.True(result.HasScript);
        Assert.Equal("rpm:scriptlet", result.Kind);
    }

    [Fact]
    public void Rpm_MixedBatch_ScriptletAndClean_BothHandledIndependently()
    {
        // House rule: mixed/partial-failure — one RPM with a scriptlet, one without,
        // one corrupt. All three are independent; the corrupt one fails soft to None.
        byte[] withScript = BuildRpm(postScript: "echo post");
        byte[] scriptless = BuildRpm();
        byte[] corrupt = "garbage"u8.ToArray();

        var batch = new[]
        {
            ScriptDetectionService.Detect("rpm", "a.rpm", withScript),
            ScriptDetectionService.Detect("rpm", "b.rpm", scriptless),
            ScriptDetectionService.Detect("rpm", "c.rpm", corrupt),
        };

        Assert.True(batch[0].HasScript);
        Assert.Equal("rpm:scriptlet", batch[0].Kind);
        Assert.False(batch[1].HasScript);
        Assert.False(batch[2].HasScript); // fail-soft, not thrown
    }

    // Builds a minimal synthetic RPM binary with the four mandatory NEVRA tags and
    // optional %pre / %post scriptlet bodies. Uses the same lead + header structure as
    // RpmHeaderParserTests to stay consistent with the parser's expectations.
    private static byte[] BuildRpm(string? preScript = null, string? postScript = null)
    {
        var tags = new List<RpmTag>
        {
            RpmTag.Str(1000, "test"),     // NAME
            RpmTag.Str(1001, "1.0"),      // VERSION
            RpmTag.Str(1002, "1"),        // RELEASE
            RpmTag.Str(1022, "x86_64"),   // ARCH
        };
        if (preScript is not null)
        {
            tags.Add(RpmTag.Str(1023, preScript));  // %pre
        }

        if (postScript is not null)
        {
            tags.Add(RpmTag.Str(1024, postScript)); // %post
        }

        return BuildRpmWithTags(tags);
    }

    private static byte[] BuildRpmWithTags(List<RpmTag> tags)
    {
        byte[] lead = new byte[96];
        lead[0] = 0xED; lead[1] = 0xAB; lead[2] = 0xEE; lead[3] = 0xDB;
        lead[4] = 3; // RPM major version 3

        // Empty signature header: 0 index entries, 0 hsize.
        byte[] sig = RpmHeaderIntro(0, 0);
        int sigEnd = 96 + sig.Length;
        byte[] pad = new byte[(8 - (sigEnd % 8)) % 8];

        var (index, store) = BuildRpmHeader(tags);
        byte[] intro = RpmHeaderIntro(tags.Count, store.Length);

        return [.. lead, .. sig, .. pad, .. intro, .. index, .. store];
    }

    private static byte[] RpmHeaderIntro(int nindex, int hsize)
    {
        byte[] b = new byte[16];
        b[0] = 0x8E; b[1] = 0xAD; b[2] = 0xE8; b[3] = 0x01;
        BinaryPrimitives.WriteInt32BigEndian(b.AsSpan(8, 4), nindex);
        BinaryPrimitives.WriteInt32BigEndian(b.AsSpan(12, 4), hsize);
        return b;
    }

    private static (byte[] Index, byte[] Store) BuildRpmHeader(List<RpmTag> tags)
    {
        var indexBytes = new List<byte>();
        var storeBytes = new List<byte>();
        foreach (var t in tags)
        {
            int offset = storeBytes.Count;
            byte[] entry = new byte[16];
            BinaryPrimitives.WriteInt32BigEndian(entry.AsSpan(0, 4), t.Tag);
            BinaryPrimitives.WriteInt32BigEndian(entry.AsSpan(4, 4), t.Type);
            BinaryPrimitives.WriteInt32BigEndian(entry.AsSpan(8, 4), offset);
            BinaryPrimitives.WriteInt32BigEndian(entry.AsSpan(12, 4), t.Count);
            indexBytes.AddRange(entry);
            storeBytes.AddRange(t.Bytes);
        }
        return (indexBytes.ToArray(), storeBytes.ToArray());
    }

    private sealed record RpmTag(int Tag, int Type, int Count, byte[] Bytes)
    {
        public static RpmTag Str(int tag, string value)
        {
            byte[] raw = Encoding.UTF8.GetBytes(value);
            byte[] withNul = new byte[raw.Length + 1];
            Array.Copy(raw, withNul, raw.Length);
            return new RpmTag(tag, Type: 6, Count: 1, withNul);
        }
    }

    // ── Routing ──────────────────────────────────────────────────────────────

    [Fact]
    public void UnknownEcosystem_ReturnsNone()
    {
        byte[] bytes = BuildZip(("tools/install.ps1", "x"));
        var result = ScriptDetectionService.Detect("maven", "x.jar", bytes);
        Assert.False(result.HasScript);
    }

    [Fact]
    public async Task DetectAsync_StreamOverload_MatchesByteOverload()
    {
        byte[] bytes = BuildTarball(
            ("package/package.json",
             """{"name":"acme","version":"1.0.0","scripts":{"postinstall":"x"}}"""));

        using var stream = new MemoryStream(bytes);
        var result = await ScriptDetectionService.DetectAsync("npm", "acme-1.0.0.tgz", stream);

        Assert.True(result.HasScript);
        Assert.Equal("npm:postinstall", result.Kind);
    }

    [Fact]
    public async Task DetectAsync_UnknownEcosystem_SkipsBufferingAndReturnsNone()
    {
        using var stream = new MemoryStream(BuildZip(("tools/install.ps1", "x")));
        var result = await ScriptDetectionService.DetectAsync("oci", "blob", stream);
        Assert.False(result.HasScript);
    }

    [Fact]
    public void MixedBatch_SomeDetectSomeFailSoft_EachIndependent()
    {
        // House rule: a fan-out over artefacts must handle "some succeed, some fail in the same
        // pass". A corrupt artefact returns None (fail-soft) without affecting its neighbours, and
        // a clean one still reports no script.
        byte[] withScript = BuildTarball(
            ("package/package.json", """{"name":"a","version":"1.0.0","scripts":{"postinstall":"x"}}"""));
        byte[] corrupt = "not a tarball"u8.ToArray();
        byte[] clean = BuildTarball(
            ("package/package.json", """{"name":"c","version":"1.0.0"}"""));

        var batch = new[]
        {
            ScriptDetectionService.Detect("npm", "a.tgz", withScript),
            ScriptDetectionService.Detect("npm", "b.tgz", corrupt),
            ScriptDetectionService.Detect("npm", "c.tgz", clean),
        };

        Assert.True(batch[0].HasScript);
        Assert.Equal("npm:postinstall", batch[0].Kind);
        Assert.False(batch[1].HasScript); // fail-soft, not a thrown exception
        Assert.False(batch[2].HasScript);
    }

    private static byte[] BuildTarball(params (string Name, string Content)[] entries)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
        using (var tw = new TarWriter(gz, leaveOpen: true))
        {
            foreach (var (n, c) in entries)
            {
                tw.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, n)
                {
                    DataStream = new MemoryStream(Encoding.UTF8.GetBytes(c)),
                });
            }
        }
        return ms.ToArray();
    }

    private static byte[] BuildZip(params (string Name, string Content)[] entries)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (n, c) in entries)
            {
                var entry = zip.CreateEntry(n);
                using var w = new StreamWriter(entry.Open());
                w.Write(c);
            }
        }
        return ms.ToArray();
    }
}
