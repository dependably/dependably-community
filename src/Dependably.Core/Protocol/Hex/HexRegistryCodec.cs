namespace Dependably.Protocol.Hex;

/// <summary>
/// Hand-written proto2 codec for the four Hex registry resources and their <c>Signed</c>
/// envelope. Hand-written because the schemas are <c>syntax = "proto2"</c>, which the C#
/// protobuf generator does not support, and because every field is a varint, a length-delimited
/// string/bytes, a fixed32 float or a packed int32 run — a closed vocabulary small enough to own.
/// <para>Encoding writes fields in field-number order with optional fields omitted when null, the
/// same canonical layout hex.pm's encoder produces, so re-encoding a decoded upstream payload is
/// byte-stable. Decoding skips unknown fields, accepts packed and unpacked repeated integers,
/// keeps unknown enum values as their integer, and refuses a missing <c>required</c> field with
/// <see cref="HexProtocolException"/> — the same rule hex_core's generated validator applies to
/// what this registry serves.</para>
/// </summary>
public static class HexRegistryCodec
{
    /// <summary>Largest resource body this decoder will walk (after gunzip). hex.pm's whole <c>/versions</c> is a few MiB.</summary>
    public const int MaxPayloadBytes = 64 * 1024 * 1024;

    /// <summary>Upper bound on any one repeated field, so a hostile payload cannot force an unbounded list.</summary>
    public const int MaxRepeatedElements = 1_000_000;

    // ── Signed ────────────────────────────────────────────────────────────────

    public static byte[] EncodeSigned(HexSigned signed)
    {
        var w = new ProtobufWriter();
        w.WriteBytes(1, signed.Payload);
        if (signed.Signature is not null)
        {
            w.WriteBytes(2, signed.Signature);
        }

        return w.ToArray();
    }

    public static HexSigned DecodeSigned(ReadOnlySpan<byte> data)
    {
        GuardSize(data);
        byte[]? payload = null;
        byte[]? signature = null;
        var r = new ProtobufReader(data);
        while (r.TryReadTag(out int field, out var wire))
        {
            switch (field)
            {
                case 1 when wire == ProtobufWireType.LengthDelimited: payload = r.ReadLengthDelimited().ToArray(); break;
                case 2 when wire == ProtobufWireType.LengthDelimited: signature = r.ReadLengthDelimited().ToArray(); break;
                default: r.Skip(wire); break;
            }
        }

        return new HexSigned(Required(payload, "Signed.payload"), signature);
    }

    // ── Names ─────────────────────────────────────────────────────────────────

    public static byte[] EncodeNames(HexNames names)
    {
        var w = new ProtobufWriter();
        foreach (var p in names.Packages)
        {
            var pw = new ProtobufWriter();
            pw.WriteString(1, p.Name);
            if (p.UpdatedAt is not null)
            {
                pw.WriteMessage(3, EncodeTimestamp(p.UpdatedAt));
            }

            w.WriteMessage(1, pw);
        }

        w.WriteString(2, names.Repository);
        return w.ToArray();
    }

    public static HexNames DecodeNames(ReadOnlySpan<byte> data)
    {
        GuardSize(data);
        var packages = new List<HexNameEntry>();
        string? repository = null;
        var r = new ProtobufReader(data);
        while (r.TryReadTag(out int field, out var wire))
        {
            switch (field)
            {
                case 1 when wire == ProtobufWireType.LengthDelimited:
                    Bounded(packages);
                    packages.Add(DecodeNameEntry(r.ReadLengthDelimited()));
                    break;
                case 2 when wire == ProtobufWireType.LengthDelimited: repository = r.ReadString(); break;
                default: r.Skip(wire); break;
            }
        }

        return new HexNames(Required(repository, "Names.repository"), packages);
    }

    private static HexNameEntry DecodeNameEntry(ReadOnlySpan<byte> data)
    {
        string? name = null;
        HexTimestamp? updatedAt = null;
        var r = new ProtobufReader(data);
        while (r.TryReadTag(out int field, out var wire))
        {
            switch (field)
            {
                case 1 when wire == ProtobufWireType.LengthDelimited: name = r.ReadString(); break;
                case 3 when wire == ProtobufWireType.LengthDelimited: updatedAt = DecodeTimestamp(r.ReadLengthDelimited()); break;
                default: r.Skip(wire); break;
            }
        }

        return new HexNameEntry(Required(name, "Names.Package.name"), updatedAt);
    }

    // ── Versions ──────────────────────────────────────────────────────────────

    public static byte[] EncodeVersions(HexVersions versions)
    {
        var w = new ProtobufWriter();
        foreach (var p in versions.Packages)
        {
            var pw = new ProtobufWriter();
            pw.WriteString(1, p.Name);
            foreach (string v in p.Versions)
            {
                pw.WriteString(2, v);
            }

            pw.WritePackedInt32(3, p.Retired);
            pw.WritePackedInt32(5, p.WithAdvisories);
            w.WriteMessage(1, pw);
        }

        w.WriteString(2, versions.Repository);
        return w.ToArray();
    }

    public static HexVersions DecodeVersions(ReadOnlySpan<byte> data)
    {
        GuardSize(data);
        var packages = new List<HexVersionsEntry>();
        string? repository = null;
        var r = new ProtobufReader(data);
        while (r.TryReadTag(out int field, out var wire))
        {
            switch (field)
            {
                case 1 when wire == ProtobufWireType.LengthDelimited:
                    Bounded(packages);
                    packages.Add(DecodeVersionsEntry(r.ReadLengthDelimited()));
                    break;
                case 2 when wire == ProtobufWireType.LengthDelimited: repository = r.ReadString(); break;
                default: r.Skip(wire); break;
            }
        }

        return new HexVersions(Required(repository, "Versions.repository"), packages);
    }

    private static HexVersionsEntry DecodeVersionsEntry(ReadOnlySpan<byte> data)
    {
        string? name = null;
        var versions = new List<string>();
        var retired = new List<int>();
        var withAdvisories = new List<int>();
        var r = new ProtobufReader(data);
        while (r.TryReadTag(out int field, out var wire))
        {
            switch (field)
            {
                case 1 when wire == ProtobufWireType.LengthDelimited: name = r.ReadString(); break;
                case 2 when wire == ProtobufWireType.LengthDelimited:
                    Bounded(versions);
                    versions.Add(r.ReadString());
                    break;
                case 3: r.ReadRepeatedInt32(wire, retired, MaxRepeatedElements); break;
                case 5: r.ReadRepeatedInt32(wire, withAdvisories, MaxRepeatedElements); break;
                default: r.Skip(wire); break;
            }
        }

        return new HexVersionsEntry(Required(name, "Versions.Package.name"), versions, retired, withAdvisories);
    }

    // ── Package ───────────────────────────────────────────────────────────────

    public static byte[] EncodePackage(HexPackage package)
    {
        var w = new ProtobufWriter();
        foreach (var release in package.Releases)
        {
            w.WriteMessage(1, EncodeRelease(release));
        }

        w.WriteString(2, package.Name);
        w.WriteString(3, package.Repository);
        foreach (var advisory in package.Advisories)
        {
            w.WriteMessage(4, EncodeAdvisory(advisory));
        }

        return w.ToArray();
    }

    private static ProtobufWriter EncodeRelease(HexRelease release)
    {
        var w = new ProtobufWriter();
        w.WriteString(1, release.Version);
        w.WriteBytes(2, release.InnerChecksum);
        foreach (var dep in release.Dependencies)
        {
            var dw = new ProtobufWriter();
            dw.WriteString(1, dep.Package);
            dw.WriteString(2, dep.Requirement);
            if (dep.Optional is { } optional)
            {
                dw.WriteBool(3, optional);
            }

            if (dep.App is not null)
            {
                dw.WriteString(4, dep.App);
            }

            if (dep.Repository is not null)
            {
                dw.WriteString(5, dep.Repository);
            }

            w.WriteMessage(3, dw);
        }

        if (release.Retired is { } retired)
        {
            var rw = new ProtobufWriter();
            rw.WriteInt32(1, (int)retired.Reason);
            if (retired.Message is not null)
            {
                rw.WriteString(2, retired.Message);
            }

            w.WriteMessage(4, rw);
        }

        if (release.OuterChecksum is not null)
        {
            w.WriteBytes(5, release.OuterChecksum);
        }

        // advisory_indexes carries no [packed] annotation, so proto2 writes one tag per element.
        foreach (uint index in release.AdvisoryIndexes ?? Array.Empty<uint>())
        {
            w.WriteUInt32(6, index);
        }

        if (release.PublishedAt is not null)
        {
            w.WriteMessage(7, EncodeTimestamp(release.PublishedAt));
        }

        return w;
    }

    private static ProtobufWriter EncodeAdvisory(HexSecurityAdvisory advisory)
    {
        var w = new ProtobufWriter();
        w.WriteString(1, advisory.Id);
        w.WriteString(2, advisory.Summary);
        w.WriteString(3, advisory.HtmlUrl);
        if (advisory.Severity is { } severity)
        {
            w.WriteInt32(4, (int)severity);
        }

        if (advisory.CvssScore is { } score)
        {
            w.WriteFloat(5, score);
        }

        w.WriteString(6, advisory.ApiUrl);
        foreach (string alias in advisory.Aliases ?? Array.Empty<string>())
        {
            w.WriteString(7, alias);
        }

        return w;
    }

    public static HexPackage DecodePackage(ReadOnlySpan<byte> data)
    {
        GuardSize(data);
        var releases = new List<HexRelease>();
        var advisories = new List<HexSecurityAdvisory>();
        string? name = null;
        string? repository = null;
        var r = new ProtobufReader(data);
        while (r.TryReadTag(out int field, out var wire))
        {
            switch (field)
            {
                case 1 when wire == ProtobufWireType.LengthDelimited:
                    Bounded(releases);
                    releases.Add(DecodeRelease(r.ReadLengthDelimited()));
                    break;
                case 2 when wire == ProtobufWireType.LengthDelimited: name = r.ReadString(); break;
                case 3 when wire == ProtobufWireType.LengthDelimited: repository = r.ReadString(); break;
                case 4 when wire == ProtobufWireType.LengthDelimited:
                    Bounded(advisories);
                    advisories.Add(DecodeAdvisory(r.ReadLengthDelimited()));
                    break;
                default: r.Skip(wire); break;
            }
        }

        return new HexPackage(
            Required(name, "Package.name"), Required(repository, "Package.repository"), releases, advisories);
    }

    private static HexRelease DecodeRelease(ReadOnlySpan<byte> data)
    {
        string? version = null;
        byte[]? innerChecksum = null;
        byte[]? outerChecksum = null;
        HexRetirementStatus? retired = null;
        HexTimestamp? publishedAt = null;
        var dependencies = new List<HexDependency>();
        var advisoryIndexes = new List<uint>();
        var r = new ProtobufReader(data);
        while (r.TryReadTag(out int field, out var wire))
        {
            switch (field)
            {
                case 1 when wire == ProtobufWireType.LengthDelimited: version = r.ReadString(); break;
                case 2 when wire == ProtobufWireType.LengthDelimited: innerChecksum = r.ReadLengthDelimited().ToArray(); break;
                case 3 when wire == ProtobufWireType.LengthDelimited:
                    Bounded(dependencies);
                    dependencies.Add(DecodeDependency(r.ReadLengthDelimited()));
                    break;
                case 4 when wire == ProtobufWireType.LengthDelimited: retired = DecodeRetirement(r.ReadLengthDelimited()); break;
                case 5 when wire == ProtobufWireType.LengthDelimited: outerChecksum = r.ReadLengthDelimited().ToArray(); break;
                case 6: r.ReadRepeatedUInt32(wire, advisoryIndexes, MaxRepeatedElements); break;
                case 7 when wire == ProtobufWireType.LengthDelimited: publishedAt = DecodeTimestamp(r.ReadLengthDelimited()); break;
                default: r.Skip(wire); break;
            }
        }

        return new HexRelease(
            Required(version, "Release.version"),
            Required(innerChecksum, "Release.inner_checksum"),
            dependencies, retired, outerChecksum,
            advisoryIndexes.Count > 0 ? advisoryIndexes : null,
            publishedAt);
    }

    private static HexDependency DecodeDependency(ReadOnlySpan<byte> data)
    {
        string? package = null;
        string? requirement = null;
        bool? optional = null;
        string? app = null;
        string? repository = null;
        var r = new ProtobufReader(data);
        while (r.TryReadTag(out int field, out var wire))
        {
            switch (field)
            {
                case 1 when wire == ProtobufWireType.LengthDelimited: package = r.ReadString(); break;
                case 2 when wire == ProtobufWireType.LengthDelimited: requirement = r.ReadString(); break;
                case 3 when wire == ProtobufWireType.Varint: optional = r.ReadBool(); break;
                case 4 when wire == ProtobufWireType.LengthDelimited: app = r.ReadString(); break;
                case 5 when wire == ProtobufWireType.LengthDelimited: repository = r.ReadString(); break;
                default: r.Skip(wire); break;
            }
        }

        return new HexDependency(
            Required(package, "Dependency.package"), Required(requirement, "Dependency.requirement"),
            optional, app, repository);
    }

    private static HexRetirementStatus DecodeRetirement(ReadOnlySpan<byte> data)
    {
        int? reason = null;
        string? message = null;
        var r = new ProtobufReader(data);
        while (r.TryReadTag(out int field, out var wire))
        {
            switch (field)
            {
                case 1 when wire == ProtobufWireType.Varint: reason = r.ReadInt32(); break;
                case 2 when wire == ProtobufWireType.LengthDelimited: message = r.ReadString(); break;
                default: r.Skip(wire); break;
            }
        }

        return new HexRetirementStatus((HexRetirementReason)Required(reason, "RetirementStatus.reason"), message);
    }

    private static HexSecurityAdvisory DecodeAdvisory(ReadOnlySpan<byte> data)
    {
        string? id = null, summary = null, htmlUrl = null, apiUrl = null;
        int? severity = null;
        float? cvss = null;
        var aliases = new List<string>();
        var r = new ProtobufReader(data);
        while (r.TryReadTag(out int field, out var wire))
        {
            switch (field)
            {
                case 1 when wire == ProtobufWireType.LengthDelimited: id = r.ReadString(); break;
                case 2 when wire == ProtobufWireType.LengthDelimited: summary = r.ReadString(); break;
                case 3 when wire == ProtobufWireType.LengthDelimited: htmlUrl = r.ReadString(); break;
                case 4 when wire == ProtobufWireType.Varint: severity = r.ReadInt32(); break;
                case 5 when wire == ProtobufWireType.Fixed32: cvss = r.ReadFixed32Float(); break;
                case 6 when wire == ProtobufWireType.LengthDelimited: apiUrl = r.ReadString(); break;
                case 7 when wire == ProtobufWireType.LengthDelimited:
                    Bounded(aliases);
                    aliases.Add(r.ReadString());
                    break;
                default: r.Skip(wire); break;
            }
        }

        return new HexSecurityAdvisory(
            Required(id, "SecurityAdvisory.id"), Required(summary, "SecurityAdvisory.summary"),
            Required(htmlUrl, "SecurityAdvisory.html_url"), Required(apiUrl, "SecurityAdvisory.api_url"),
            severity is { } s ? (HexAdvisorySeverity)s : null, cvss,
            aliases.Count > 0 ? aliases : null);
    }

    // ── Policy ────────────────────────────────────────────────────────────────

    public static byte[] EncodePolicy(HexPolicy policy)
    {
        var w = new ProtobufWriter();
        w.WriteString(1, policy.Repository);
        w.WriteString(2, policy.Name);
        if (policy.Description is not null)
        {
            w.WriteString(3, policy.Description);
        }

        w.WriteInt32(4, (int)policy.Visibility);
        foreach (var repo in policy.Repositories)
        {
            var rw = new ProtobufWriter();
            rw.WriteString(1, repo.Repository);
            if (repo.Restriction is { } restriction)
            {
                rw.WriteMessage(2, EncodeRestriction(restriction));
            }

            foreach (var o in repo.Overrides)
            {
                rw.WriteMessage(3, EncodeOverride(o));
            }

            w.WriteMessage(5, rw);
        }

        return w.ToArray();
    }

    /// <summary>A repository policy's restriction submessage: severity floor, retirement reasons, cooldown.</summary>
    private static ProtobufWriter EncodeRestriction(HexRestriction restriction)
    {
        var sw = new ProtobufWriter();
        if (restriction.AdvisoryMinSeverity is { } minSeverity)
        {
            sw.WriteInt32(1, (int)minSeverity);
        }

        sw.WritePackedInt32(2, restriction.RetirementReasons.Select(x => (int)x).ToList());
        if (restriction.Cooldown is not null)
        {
            sw.WriteString(3, restriction.Cooldown);
        }

        return sw;
    }

    /// <summary>A per-package override submessage: the action, its package ref, and the optional annotations.</summary>
    private static ProtobufWriter EncodeOverride(HexOverride o)
    {
        var ow = new ProtobufWriter();
        ow.WriteInt32(1, (int)o.Action);

        var refw = new ProtobufWriter();
        refw.WriteString(1, o.Ref.Package);
        if (o.Ref.Requirement is not null)
        {
            refw.WriteString(2, o.Ref.Requirement);
        }

        ow.WriteMessage(2, refw);
        if (o.AdvisoryId is not null)
        {
            ow.WriteString(3, o.AdvisoryId);
        }

        if (o.RetirementReason is { } reason)
        {
            ow.WriteInt32(4, (int)reason);
        }

        if (o.Comment is not null)
        {
            ow.WriteString(5, o.Comment);
        }

        return ow;
    }

    public static HexPolicy DecodePolicy(ReadOnlySpan<byte> data)
    {
        GuardSize(data);
        string? repository = null, name = null, description = null;
        int? visibility = null;
        var repositories = new List<HexRepositoryPolicy>();
        var r = new ProtobufReader(data);
        while (r.TryReadTag(out int field, out var wire))
        {
            switch (field)
            {
                case 1 when wire == ProtobufWireType.LengthDelimited: repository = r.ReadString(); break;
                case 2 when wire == ProtobufWireType.LengthDelimited: name = r.ReadString(); break;
                case 3 when wire == ProtobufWireType.LengthDelimited: description = r.ReadString(); break;
                case 4 when wire == ProtobufWireType.Varint: visibility = r.ReadInt32(); break;
                case 5 when wire == ProtobufWireType.LengthDelimited:
                    Bounded(repositories);
                    repositories.Add(DecodeRepositoryPolicy(r.ReadLengthDelimited()));
                    break;
                default: r.Skip(wire); break;
            }
        }

        return new HexPolicy(
            Required(repository, "Policy.repository"), Required(name, "Policy.name"),
            (HexVisibility)Required(visibility, "Policy.visibility"), repositories, description);
    }

    private static HexRepositoryPolicy DecodeRepositoryPolicy(ReadOnlySpan<byte> data)
    {
        string? repository = null;
        HexRestriction? restriction = null;
        var overrides = new List<HexOverride>();
        var r = new ProtobufReader(data);
        while (r.TryReadTag(out int field, out var wire))
        {
            switch (field)
            {
                case 1 when wire == ProtobufWireType.LengthDelimited: repository = r.ReadString(); break;
                case 2 when wire == ProtobufWireType.LengthDelimited: restriction = DecodeRestriction(r.ReadLengthDelimited()); break;
                case 3 when wire == ProtobufWireType.LengthDelimited:
                    Bounded(overrides);
                    overrides.Add(DecodeOverride(r.ReadLengthDelimited()));
                    break;
                default: r.Skip(wire); break;
            }
        }

        return new HexRepositoryPolicy(Required(repository, "RepositoryPolicy.repository"), restriction, overrides);
    }

    private static HexRestriction DecodeRestriction(ReadOnlySpan<byte> data)
    {
        int? minSeverity = null;
        string? cooldown = null;
        var reasons = new List<int>();
        var r = new ProtobufReader(data);
        while (r.TryReadTag(out int field, out var wire))
        {
            switch (field)
            {
                case 1 when wire == ProtobufWireType.Varint: minSeverity = r.ReadInt32(); break;
                case 2: r.ReadRepeatedInt32(wire, reasons, MaxRepeatedElements); break;
                case 3 when wire == ProtobufWireType.LengthDelimited: cooldown = r.ReadString(); break;
                default: r.Skip(wire); break;
            }
        }

        return new HexRestriction(
            minSeverity is { } s ? (HexAdvisorySeverity)s : null,
            reasons.Select(x => (HexRetirementReason)x).ToList(), cooldown);
    }

    private static HexOverride DecodeOverride(ReadOnlySpan<byte> data)
    {
        int? action = null, retirementReason = null;
        HexPackageRef? packageRef = null;
        string? advisoryId = null, comment = null;
        var r = new ProtobufReader(data);
        while (r.TryReadTag(out int field, out var wire))
        {
            switch (field)
            {
                case 1 when wire == ProtobufWireType.Varint: action = r.ReadInt32(); break;
                case 2 when wire == ProtobufWireType.LengthDelimited: packageRef = DecodePackageRef(r.ReadLengthDelimited()); break;
                case 3 when wire == ProtobufWireType.LengthDelimited: advisoryId = r.ReadString(); break;
                case 4 when wire == ProtobufWireType.Varint: retirementReason = r.ReadInt32(); break;
                case 5 when wire == ProtobufWireType.LengthDelimited: comment = r.ReadString(); break;
                default: r.Skip(wire); break;
            }
        }

        return new HexOverride(
            (HexOverrideAction)Required(action, "Override.action"), Required(packageRef, "Override.ref"),
            advisoryId, retirementReason is { } rr ? (HexRetirementReason)rr : null, comment);
    }

    private static HexPackageRef DecodePackageRef(ReadOnlySpan<byte> data)
    {
        string? package = null, requirement = null;
        var r = new ProtobufReader(data);
        while (r.TryReadTag(out int field, out var wire))
        {
            switch (field)
            {
                case 1 when wire == ProtobufWireType.LengthDelimited: package = r.ReadString(); break;
                case 2 when wire == ProtobufWireType.LengthDelimited: requirement = r.ReadString(); break;
                default: r.Skip(wire); break;
            }
        }

        return new HexPackageRef(Required(package, "PackageRef.package"), requirement);
    }

    // ── Timestamp ─────────────────────────────────────────────────────────────

    private static ProtobufWriter EncodeTimestamp(HexTimestamp ts)
    {
        var w = new ProtobufWriter();
        w.WriteInt64(1, ts.Seconds);
        w.WriteInt32(2, ts.Nanos);
        return w;
    }

    private static HexTimestamp DecodeTimestamp(ReadOnlySpan<byte> data)
    {
        long? seconds = null;
        int? nanos = null;
        var r = new ProtobufReader(data);
        while (r.TryReadTag(out int field, out var wire))
        {
            switch (field)
            {
                case 1 when wire == ProtobufWireType.Varint: seconds = r.ReadInt64(); break;
                case 2 when wire == ProtobufWireType.Varint: nanos = r.ReadInt32(); break;
                default: r.Skip(wire); break;
            }
        }

        return new HexTimestamp(Required(seconds, "Timestamp.seconds"), Required(nanos, "Timestamp.nanos"));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private static void GuardSize(ReadOnlySpan<byte> data)
    {
        if (data.Length > MaxPayloadBytes)
        {
            throw new HexProtocolException($"Registry payload exceeds the {MaxPayloadBytes}-byte limit.");
        }
    }

    private static void Bounded<T>(List<T> list)
    {
        if (list.Count >= MaxRepeatedElements)
        {
            throw new HexProtocolException("Malformed protobuf: repeated field exceeds the element limit.");
        }
    }

    private static T Required<T>(T? value, string field) where T : class =>
        value ?? throw new HexProtocolException($"Registry payload is missing required field {field}.");

    private static T Required<T>(T? value, string field) where T : struct =>
        value ?? throw new HexProtocolException($"Registry payload is missing required field {field}.");
}
