using System.Numerics;

namespace Dependably.Protocol.Hex;

/// <summary>
/// An Erlang atom. Atoms are a distinct type from binaries and charlists on the Erlang
/// side, so they get their own wrapper here rather than collapsing into <see cref="string"/>:
/// a Hex payload that carries <c>false</c> (the atom) means something different from one
/// that carries <c>&lt;&lt;"false"&gt;&gt;</c> (the binary).
/// </summary>
public sealed record ErlangAtom(string Name)
{
    public static readonly ErlangAtom True = new("true");
    public static readonly ErlangAtom False = new("false");
    public static readonly ErlangAtom Nil = new("nil");
    public static readonly ErlangAtom Undefined = new("undefined");

    public bool IsTrue => string.Equals(Name, "true", StringComparison.Ordinal);

    public bool IsFalse => string.Equals(Name, "false", StringComparison.Ordinal);

    public bool IsNil => string.Equals(Name, "nil", StringComparison.Ordinal);

    public override string ToString() => Name;
}

/// <summary>
/// An Erlang tuple. Equality is structural over the items (element-wise
/// <see cref="ErlangTermModel.DeepEquals"/>), not reference equality of the backing list,
/// so two independently decoded copies of the same tuple compare equal.
/// </summary>
public sealed record ErlangTuple(IReadOnlyList<object?> Items)
{
    public static readonly ErlangTuple Empty = new(Array.Empty<object?>());

    public int Arity => Items.Count;

    public object? this[int index] => Items[index];

    public bool Equals(ErlangTuple? other) =>
        other is not null && ErlangTermModel.SequenceEquals(Items, other.Items);

    public override int GetHashCode() => ErlangTermModel.DeepHash(this);
}

/// <summary>
/// A double-quoted Erlang string — that is, a charlist: a list of code points. Erlang has no
/// distinct string type, so <c>"abc"</c> and <c>[97,98,99]</c> are the same term; this wrapper
/// keeps the textual form distinguishable from a binary and from a plain list of integers so a
/// caller can decide how to treat it, and <see cref="ErlangTermText.Print"/> can render it back
/// in the form it was written.
/// </summary>
public sealed record ErlangCharlist(string Value)
{
    public override string ToString() => Value;
}

/// <summary>
/// Raised for every malformed, unsupported, or over-budget term encountered by
/// <see cref="ErlangTermFormat"/> and <see cref="ErlangTermText"/>. Both codecs treat hostile
/// input as expected input: a caller only ever has to catch this type, never an index,
/// arithmetic, or allocation failure.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization ctor on Exception is obsolete in .NET 10 (SYSLIB0051); this exception is never serialized across an AppDomain or binary boundary.")]
public sealed class ErlangTermException : Exception
{
    public ErlangTermException()
    {
    }

    public ErlangTermException(string message)
        : base(message)
    {
    }

    public ErlangTermException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Construction and comparison helpers for the term model. The decoded shapes are deliberately
/// plain BCL types so callers need no wrapper for the common cases: lists are
/// <see cref="IReadOnlyList{T}"/> of <see cref="object"/>, maps are
/// <see cref="IReadOnlyDictionary{TKey, TValue}"/> keyed by the decoded key term, binaries are
/// <see cref="string"/> when their bytes are valid UTF-8 and <see cref="byte"/>[] when they are
/// not, integers are <see cref="long"/> (or <see cref="BigInteger"/> when they do not fit) and
/// floats are <see cref="double"/>.
/// </summary>
public static class ErlangTermModel
{
    internal static readonly BigInteger LongMinimum = long.MinValue;
    internal static readonly BigInteger LongMaximum = long.MaxValue;

    /// <summary>
    /// Narrows an integer term to <see cref="long"/> whenever it fits one, which is the shape
    /// both codecs hand back so a caller is not forced to test for two integer types.
    /// </summary>
    public static object NarrowInteger(BigInteger value) =>
        value >= LongMinimum && value <= LongMaximum ? (long)value : (object)value;

    /// <summary>
    /// Compares two terms structurally: element-wise for tuples and lists, entry-wise for maps,
    /// byte-wise for binaries, and by numeric value across <see cref="long"/> and
    /// <see cref="BigInteger"/>. Reference equality of the backing collections is never required.
    /// </summary>
    public static bool DeepEquals(object? left, object? right) =>
        ReferenceEquals(left, right) || (left is not null && right is not null && CompareTerms(left, right));

    private static bool CompareTerms(object left, object right) =>
        left switch
        {
            ErlangAtom leftAtom =>
                right is ErlangAtom rightAtom && string.Equals(leftAtom.Name, rightAtom.Name, StringComparison.Ordinal),
            ErlangCharlist leftCharlist =>
                right is ErlangCharlist rightCharlist && string.Equals(leftCharlist.Value, rightCharlist.Value, StringComparison.Ordinal),
            string leftText => right is string rightText && string.Equals(leftText, rightText, StringComparison.Ordinal),
            byte[] leftBytes => right is byte[] rightBytes && leftBytes.AsSpan().SequenceEqual(rightBytes),
            ErlangTuple leftTuple => right is ErlangTuple rightTuple && SequenceEquals(leftTuple.Items, rightTuple.Items),
            double leftDouble => right is double rightDouble && leftDouble.Equals(rightDouble),
            IReadOnlyDictionary<object, object?> leftMap =>
                right is IReadOnlyDictionary<object, object?> rightMap && MapEquals(leftMap, rightMap),
            IReadOnlyList<object?> leftList =>
                right is IReadOnlyList<object?> rightList && SequenceEquals(leftList, rightList),

            // Integers fall through to here so that a long and a BigInteger holding the same
            // value compare equal, whichever way each side was built.
            _ => TryAsInteger(left, out var leftInteger)
                ? TryAsInteger(right, out var rightInteger) && leftInteger == rightInteger
                : left.Equals(right),
        };

    /// <summary>
    /// The hash counterpart of <see cref="DeepEquals"/>: terms that compare equal hash equal, so
    /// a decoded term can be used as a dictionary key.
    /// </summary>
    public static int DeepHash(object? term)
    {
        switch (term)
        {
            case null:
                return 0;
            case ErlangAtom atom:
                return HashCode.Combine(1, atom.Name.GetHashCode(StringComparison.Ordinal));
            case ErlangCharlist charlist:
                return HashCode.Combine(2, charlist.Value.GetHashCode(StringComparison.Ordinal));
            case string text:
                return HashCode.Combine(3, text.GetHashCode(StringComparison.Ordinal));
            case byte[] bytes:
                {
                    var binaryHash = new HashCode();
                    binaryHash.Add(4);
                    binaryHash.AddBytes(bytes);
                    return binaryHash.ToHashCode();
                }

            case ErlangTuple tuple:
                return SequenceHash(5, tuple.Items);
            case double value:
                return HashCode.Combine(6, value);
            case IReadOnlyDictionary<object, object?> map:
                {
                    // Entry hashes are combined with XOR so the result does not depend on
                    // enumeration order, which no map guarantees.
                    int mapHash = 7;
                    foreach (var entry in map)
                    {
                        mapHash ^= HashCode.Combine(DeepHash(entry.Key), DeepHash(entry.Value));
                    }

                    return mapHash;
                }

            case IReadOnlyList<object?> list:
                return SequenceHash(8, list);
            default:
                return TryAsInteger(term, out var integer)
                    ? HashCode.Combine(9, integer)
                    : term.GetHashCode();
        }
    }

    /// <summary>
    /// An equality comparer over the term model. It keys decoded maps, so that a lookup with a
    /// freshly built key term (a plain <see cref="string"/>, say) finds the decoded entry.
    /// </summary>
    public static IEqualityComparer<object> TermComparer { get; } = new DeepTermComparer();

    /// <summary>Builds a map with string (binary) keys — the shape every Hex payload uses.</summary>
    public static IReadOnlyDictionary<object, object?> Map(params (string key, object? value)[] entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        var map = new Dictionary<object, object?>(entries.Length, TermComparer);
        foreach ((string key, object? value) in entries)
        {
            map[key] = value;
        }

        return map;
    }

    /// <summary>Builds a proper list term.</summary>
    public static IReadOnlyList<object?> List(params object?[] items)
    {
        ArgumentNullException.ThrowIfNull(items);
        return items;
    }

    /// <summary>Builds a tuple term.</summary>
    public static ErlangTuple Tuple(params object?[] items)
    {
        ArgumentNullException.ThrowIfNull(items);
        return new ErlangTuple(items);
    }

    internal static bool SequenceEquals(IReadOnlyList<object?> left, IReadOnlyList<object?> right)
    {
        if (left.Count != right.Count)
        {
            return false;
        }

        for (int i = 0; i < left.Count; i++)
        {
            if (!DeepEquals(left[i], right[i]))
            {
                return false;
            }
        }

        return true;
    }

    internal static bool TryAsInteger(object value, out BigInteger integer)
    {
        switch (value)
        {
            case sbyte or byte or short or ushort or int or long:
                integer = Convert.ToInt64(value, System.Globalization.CultureInfo.InvariantCulture);
                return true;
            case ulong unsigned:
                integer = unsigned;
                return true;
            case BigInteger big:
                integer = big;
                return true;
            default:
                integer = BigInteger.Zero;
                return false;
        }
    }

    private static bool MapEquals(IReadOnlyDictionary<object, object?> left, IReadOnlyDictionary<object, object?> right)
    {
        if (left.Count != right.Count)
        {
            return false;
        }

        foreach (var entry in left)
        {
            if (right.TryGetValue(entry.Key, out object? candidate) && DeepEquals(entry.Value, candidate))
            {
                continue;
            }

            // The right-hand map may be keyed by a different comparer (an ordinal string
            // dictionary, say), so fall back to a structural scan before declaring a mismatch.
            bool matched = false;
            foreach (var other in right)
            {
                if (DeepEquals(entry.Key, other.Key) && DeepEquals(entry.Value, other.Value))
                {
                    matched = true;
                    break;
                }
            }

            if (!matched)
            {
                return false;
            }
        }

        return true;
    }

    private static int SequenceHash(int seed, IReadOnlyList<object?> items)
    {
        var hash = new HashCode();
        hash.Add(seed);
        hash.Add(items.Count);
        foreach (object? item in items)
        {
            hash.Add(DeepHash(item));
        }

        return hash.ToHashCode();
    }

    private sealed class DeepTermComparer : IEqualityComparer<object>
    {
        public new bool Equals(object? x, object? y) => DeepEquals(x, y);

        public int GetHashCode(object obj) => DeepHash(obj);
    }
}
