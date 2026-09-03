using System.Buffers.Binary;
using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Unicode;

namespace Dependably.Protocol.Hex;

/// <summary>
/// Codec for the Erlang external term format — the byte encoding produced by
/// <c>erlang:term_to_binary/1</c> and read back by <c>erlang:binary_to_term/1</c>. Hex serves
/// its registry resources (package and version metadata, the signed payload envelope) in this
/// format, and hex_core reads them through <c>hex_safe_binary_to_term</c>, so only the safe
/// subset of tags is implemented here.
/// </summary>
/// <remarks>
/// <para>
/// Supported tags: 70 NEW_FLOAT_EXT, 97 SMALL_INTEGER_EXT, 98 INTEGER_EXT, 100 ATOM_EXT,
/// 104 SMALL_TUPLE_EXT, 105 LARGE_TUPLE_EXT, 106 NIL_EXT, 107 STRING_EXT, 108 LIST_EXT,
/// 109 BINARY_EXT, 110 SMALL_BIG_EXT, 111 LARGE_BIG_EXT, 116 MAP_EXT, 118 ATOM_UTF8_EXT and
/// 119 SMALL_ATOM_UTF8_EXT. Every other tag — process identifiers, ports, references,
/// functions, exports, bit binaries, and the compressed-term envelope — is rejected: those
/// carry node-local or executable state that has no meaning in a registry payload, which is the
/// same reason hex_core refuses them.
/// </para>
/// <para>
/// Decoding normalizes: a binary whose bytes are valid UTF-8 becomes a <see cref="string"/> and
/// otherwise a <see cref="byte"/>[]; an integer becomes a <see cref="long"/> whenever it fits
/// one and a <see cref="BigInteger"/> when it does not; STRING_EXT becomes an
/// <see cref="IReadOnlyList{T}"/> of <see cref="long"/>, because that is what it is on the
/// Erlang side — a list of small integers. Re-encoding a decoded term therefore need not
/// reproduce the original bytes, but it always produces a term Erlang compares equal.
/// </para>
/// </remarks>
public static class ErlangTermFormat
{
    /// <summary>The leading version byte of every external term format payload.</summary>
    public const byte VersionMagic = 131;

    /// <summary>
    /// The largest payload <see cref="Decode(ReadOnlySpan{byte})"/> will look at. Hex registry
    /// resources are orders of magnitude smaller; the cap exists so a hostile payload cannot
    /// turn a decode into an unbounded allocation.
    /// </summary>
    public const int MaxInputBytes = 16 * 1024 * 1024;

    /// <summary>The deepest term nesting either direction of the codec will follow.</summary>
    public const int MaxDepth = 64;

    private const byte TagNewFloat = 70;
    private const byte TagSmallInteger = 97;
    private const byte TagInteger = 98;
    private const byte TagAtom = 100;
    private const byte TagSmallTuple = 104;
    private const byte TagLargeTuple = 105;
    private const byte TagNil = 106;
    private const byte TagString = 107;
    private const byte TagList = 108;
    private const byte TagBinary = 109;
    private const byte TagSmallBig = 110;
    private const byte TagLargeBig = 111;
    private const byte TagMap = 116;
    private const byte TagAtomUtf8 = 118;
    private const byte TagSmallAtomUtf8 = 119;

    /// <summary>
    /// Encodes a term, including the leading version byte, exactly as
    /// <c>erlang:term_to_binary/1</c> would.
    /// </summary>
    /// <remarks>
    /// Map entries are written in ascending ordinal order of their encoded key bytes, so the
    /// output for a given term is byte-stable regardless of the dictionary's enumeration order.
    /// Two keys that encode to the same bytes are rejected: they are one key on the Erlang side,
    /// and the decoder refuses duplicate keys.
    /// </remarks>
    public static byte[] Encode(object? term)
    {
        using var buffer = new MemoryStream(256);
        buffer.WriteByte(VersionMagic);
        WriteTerm(buffer, term, 0);
        return buffer.ToArray();
    }

    /// <summary>Decodes one complete term. Trailing bytes after the root term are an error.</summary>
    public static object? Decode(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length > MaxInputBytes)
        {
            throw new ErlangTermException(
                $"External term format input of {bytes.Length} bytes exceeds the {MaxInputBytes} byte limit.");
        }

        if (bytes.IsEmpty)
        {
            throw new ErlangTermException("External term format input is empty.");
        }

        var reader = new Reader(bytes);
        byte version = reader.ReadByte();
        if (version != VersionMagic)
        {
            throw new ErlangTermException(
                $"Expected external term format version byte {VersionMagic} but found {version}.");
        }

        object? term = ReadTerm(ref reader, 0);
        return !reader.AtEnd
            ? throw new ErlangTermException(
                $"{reader.Remaining} trailing byte(s) after the root term at offset {reader.Offset}.")
            : term;
    }

    /// <inheritdoc cref="Decode(ReadOnlySpan{byte})"/>
    public static object? Decode(ReadOnlyMemory<byte> bytes) => Decode(bytes.Span);

    /// <inheritdoc cref="Decode(ReadOnlySpan{byte})"/>
    public static object? Decode(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        return Decode(new ReadOnlySpan<byte>(bytes));
    }

    private static void WriteTerm(MemoryStream buffer, object? term, int depth)
    {
        if (depth > MaxDepth)
        {
            throw new ErlangTermException($"Term nesting exceeds the maximum depth of {MaxDepth}.");
        }

        switch (term)
        {
            case null:
                WriteAtom(buffer, ErlangAtom.Nil.Name);
                return;
            case bool flag:
                WriteAtom(buffer, flag ? ErlangAtom.True.Name : ErlangAtom.False.Name);
                return;
            case ErlangAtom atom:
                WriteAtom(buffer, atom.Name);
                return;
            case string text:
                WriteBinary(buffer, Encoding.UTF8.GetBytes(text));
                return;
            case byte[] bytes:
                WriteBinary(buffer, bytes);
                return;
            case ErlangCharlist charlist:
                WriteCodePointList(buffer, charlist.Value, depth);
                return;
            case ErlangTuple tuple:
                WriteTuple(buffer, tuple.Items, depth);
                return;
            case sbyte or byte or short or ushort or int or long:
                WriteInteger(buffer, Convert.ToInt64(term, CultureInfo.InvariantCulture));
                return;
            case ulong unsigned:
                WriteBig(buffer, unsigned);
                return;
            case BigInteger big:
                WriteBig(buffer, big);
                return;
            case float single:
                WriteFloat(buffer, single);
                return;
            case double value:
                WriteFloat(buffer, value);
                return;
            default:
                WriteCompoundTerm(buffer, term, depth);
                return;
        }
    }

    private static void WriteCompoundTerm(MemoryStream buffer, object term, int depth)
    {
        if (TryGetMapEntries(term, out var entries))
        {
            WriteMap(buffer, entries, depth);
            return;
        }

        if (term is IEnumerable<object?> sequence)
        {
            WriteList(buffer, sequence, depth);
            return;
        }

        if (term is System.Collections.IEnumerable untypedSequence)
        {
            WriteList(buffer, untypedSequence.Cast<object?>(), depth);
            return;
        }

        throw new ErlangTermException(
            $"No external term format encoding for values of type {term.GetType().FullName}.");
    }

    /// <summary>
    /// Recognizes the dictionary shapes a caller can hand either codec as a map term and
    /// normalizes their entries to key/value term pairs. Both the byte encoder and the textual
    /// printer route through this, so one shape cannot be a map to one of them and a list to the
    /// other.
    /// </summary>
    internal static bool TryGetMapEntries(object term, out IEnumerable<KeyValuePair<object, object?>> entries)
    {
        switch (term)
        {
            case IReadOnlyDictionary<object, object?> map:
                entries = map;
                return true;
            case IReadOnlyDictionary<string, object?> stringMap:
                entries = MapEntries(stringMap);
                return true;
            case IDictionary<string, object?> mutableStringMap:
                entries = MapEntries(mutableStringMap);
                return true;
            case System.Collections.IDictionary untypedMap:
                entries = MapEntries(untypedMap);
                return true;
            default:
                entries = Array.Empty<KeyValuePair<object, object?>>();
                return false;
        }
    }

    private static IEnumerable<KeyValuePair<object, object?>> MapEntries(IEnumerable<KeyValuePair<string, object?>> map) =>
        map.Select(entry => new KeyValuePair<object, object?>(entry.Key, entry.Value));

    private static IEnumerable<KeyValuePair<object, object?>> MapEntries(System.Collections.IDictionary map)
    {
        foreach (System.Collections.DictionaryEntry entry in map)
        {
            yield return new KeyValuePair<object, object?>(entry.Key, entry.Value);
        }
    }

    private static void WriteAtom(MemoryStream buffer, string name)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(name);
        if (bytes.Length <= byte.MaxValue)
        {
            buffer.WriteByte(TagSmallAtomUtf8);
            buffer.WriteByte((byte)bytes.Length);
        }
        else if (bytes.Length <= ushort.MaxValue)
        {
            buffer.WriteByte(TagAtomUtf8);
            WriteUInt16(buffer, (ushort)bytes.Length);
        }
        else
        {
            throw new ErlangTermException(
                $"Atom of {bytes.Length} UTF-8 bytes exceeds the {ushort.MaxValue} byte atom limit.");
        }

        buffer.Write(bytes);
    }

    private static void WriteBinary(MemoryStream buffer, byte[] bytes)
    {
        buffer.WriteByte(TagBinary);
        WriteUInt32(buffer, (uint)bytes.Length);
        buffer.Write(bytes);
    }

    private static void WriteInteger(MemoryStream buffer, long value)
    {
        if (value is >= 0 and <= byte.MaxValue)
        {
            buffer.WriteByte(TagSmallInteger);
            buffer.WriteByte((byte)value);
            return;
        }

        if (value is >= int.MinValue and <= int.MaxValue)
        {
            buffer.WriteByte(TagInteger);
            Span<byte> scratch = stackalloc byte[4];
            BinaryPrimitives.WriteInt32BigEndian(scratch, (int)value);
            buffer.Write(scratch);
            return;
        }

        WriteBig(buffer, value);
    }

    private static void WriteBig(MemoryStream buffer, BigInteger value)
    {
        byte sign = (byte)(value.Sign < 0 ? 1 : 0);
        byte[] digits = BigInteger.Abs(value).ToByteArray(isUnsigned: true, isBigEndian: false);

        // ToByteArray can leave high-order zero padding; Erlang writes the minimal digit count,
        // keeping one digit for zero itself.
        int length = digits.Length;
        while (length > 1 && digits[length - 1] == 0)
        {
            length--;
        }

        if (length <= byte.MaxValue)
        {
            buffer.WriteByte(TagSmallBig);
            buffer.WriteByte((byte)length);
        }
        else
        {
            buffer.WriteByte(TagLargeBig);
            WriteUInt32(buffer, (uint)length);
        }

        buffer.WriteByte(sign);
        buffer.Write(digits.AsSpan(0, length));
    }

    private static void WriteFloat(MemoryStream buffer, double value)
    {
        buffer.WriteByte(TagNewFloat);
        Span<byte> scratch = stackalloc byte[8];
        BinaryPrimitives.WriteDoubleBigEndian(scratch, value);
        buffer.Write(scratch);
    }

    private static void WriteTuple(MemoryStream buffer, IReadOnlyList<object?> items, int depth)
    {
        if (items.Count <= byte.MaxValue)
        {
            buffer.WriteByte(TagSmallTuple);
            buffer.WriteByte((byte)items.Count);
        }
        else
        {
            buffer.WriteByte(TagLargeTuple);
            WriteUInt32(buffer, (uint)items.Count);
        }

        foreach (object? item in items)
        {
            WriteTerm(buffer, item, depth + 1);
        }
    }

    private static void WriteList(MemoryStream buffer, IEnumerable<object?> items, int depth)
    {
        var materialized = items as IReadOnlyList<object?> ?? items.ToList();
        if (materialized.Count == 0)
        {
            buffer.WriteByte(TagNil);
            return;
        }

        buffer.WriteByte(TagList);
        WriteUInt32(buffer, (uint)materialized.Count);
        foreach (object? item in materialized)
        {
            WriteTerm(buffer, item, depth + 1);
        }

        // Proper lists only: the tail is always NIL_EXT. STRING_EXT is never emitted — a list of
        // small integers is written as LIST_EXT of SMALL_INTEGER_EXT, which Erlang reads as the
        // same term.
        buffer.WriteByte(TagNil);
    }

    private static void WriteCodePointList(MemoryStream buffer, string text, int depth)
    {
        var codePoints = new List<object?>(text.Length);
        for (int i = 0; i < text.Length; i++)
        {
            if (char.IsHighSurrogate(text[i]) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
            {
                codePoints.Add((long)char.ConvertToUtf32(text[i], text[i + 1]));
                i++;
                continue;
            }

            codePoints.Add((long)text[i]);
        }

        WriteList(buffer, codePoints, depth);
    }

    private static void WriteMap(MemoryStream buffer, IEnumerable<KeyValuePair<object, object?>> entries, int depth)
    {
        var encoded = new List<(byte[] Key, object? Value)>();
        foreach (var entry in entries)
        {
            using var keyBuffer = new MemoryStream(32);
            WriteTerm(keyBuffer, entry.Key, depth + 1);
            encoded.Add((keyBuffer.ToArray(), entry.Value));
        }

        encoded.Sort(static (left, right) => left.Key.AsSpan().SequenceCompareTo(right.Key));
        for (int i = 1; i < encoded.Count; i++)
        {
            if (encoded[i - 1].Key.AsSpan().SequenceEqual(encoded[i].Key))
            {
                throw new ErlangTermException("Map contains two keys that encode to the same term.");
            }
        }

        buffer.WriteByte(TagMap);
        WriteUInt32(buffer, (uint)encoded.Count);
        foreach ((byte[] key, object? value) in encoded)
        {
            buffer.Write(key);
            WriteTerm(buffer, value, depth + 1);
        }
    }

    private static void WriteUInt16(MemoryStream buffer, ushort value)
    {
        Span<byte> scratch = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(scratch, value);
        buffer.Write(scratch);
    }

    private static void WriteUInt32(MemoryStream buffer, uint value)
    {
        Span<byte> scratch = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(scratch, value);
        buffer.Write(scratch);
    }

    private static object? ReadTerm(ref Reader reader, int depth)
    {
        if (depth > MaxDepth)
        {
            throw new ErlangTermException($"Term nesting exceeds the maximum depth of {MaxDepth}.");
        }

        int tagOffset = reader.Offset;
        byte tag = reader.ReadByte();
        return tag switch
        {
            TagSmallInteger => (long)reader.ReadByte(),
            TagInteger => (long)reader.ReadInt32(),
            TagNewFloat => reader.ReadDouble(),
            TagAtom => new ErlangAtom(Encoding.Latin1.GetString(reader.ReadBytes(reader.ReadUInt16()))),
            TagAtomUtf8 => new ErlangAtom(ReadUtf8Atom(ref reader, reader.ReadUInt16())),
            TagSmallAtomUtf8 => new ErlangAtom(ReadUtf8Atom(ref reader, reader.ReadByte())),
            TagSmallTuple => ReadTuple(ref reader, reader.ReadByte(), depth),
            TagLargeTuple => ReadTuple(ref reader, reader.ReadUInt32(), depth),
            TagNil => Array.Empty<object?>(),
            TagString => ReadString(ref reader),
            TagList => ReadList(ref reader, depth),
            TagBinary => ReadBinary(ref reader),
            TagSmallBig => ReadBig(ref reader, reader.ReadByte()),
            TagLargeBig => ReadBig(ref reader, reader.ReadUInt32()),
            TagMap => ReadMap(ref reader, depth),
            _ => throw new ErlangTermException(
                $"Tag {tag} at offset {tagOffset} is outside the safe external term format subset."),
        };
    }

    private static string ReadUtf8Atom(ref Reader reader, uint length)
    {
        var bytes = reader.ReadBytes(length);
        return !Utf8.IsValid(bytes)
            ? throw new ErlangTermException($"Atom at offset {reader.Offset - bytes.Length} is not valid UTF-8.")
            : Encoding.UTF8.GetString(bytes);
    }

    private static ErlangTuple ReadTuple(ref Reader reader, uint arity, int depth)
    {
        // Every element costs at least its tag byte, so an arity larger than the remaining input
        // is a lie and is refused before anything is allocated.
        reader.RequireAtLeast(arity, "tuple elements");
        object?[] items = new object?[arity];
        for (int i = 0; i < items.Length; i++)
        {
            items[i] = ReadTerm(ref reader, depth + 1);
        }

        return new ErlangTuple(items);
    }

    private static IReadOnlyList<object?> ReadString(ref Reader reader)
    {
        var bytes = reader.ReadBytes(reader.ReadUInt16());
        object?[] items = new object?[bytes.Length];
        for (int i = 0; i < bytes.Length; i++)
        {
            items[i] = (long)bytes[i];
        }

        return items;
    }

    private static IReadOnlyList<object?> ReadList(ref Reader reader, int depth)
    {
        uint count = reader.ReadUInt32();
        reader.RequireAtLeast(count, "list elements");
        object?[] items = new object?[count];
        for (int i = 0; i < items.Length; i++)
        {
            items[i] = ReadTerm(ref reader, depth + 1);
        }

        int tailOffset = reader.Offset;
        byte tail = reader.ReadByte();
        return tail != TagNil
            ? throw new ErlangTermException(
                $"Improper list at offset {tailOffset}: the tail is tag {tail} rather than NIL_EXT.")
            : (IReadOnlyList<object?>)items;
    }

    private static object ReadBinary(ref Reader reader)
    {
        var bytes = reader.ReadBytes(reader.ReadUInt32());
        return Utf8.IsValid(bytes) ? Encoding.UTF8.GetString(bytes) : bytes.ToArray();
    }

    private static object ReadBig(ref Reader reader, uint digitCount)
    {
        byte sign = reader.ReadByte();
        if (sign > 1)
        {
            throw new ErlangTermException($"Bignum sign byte {sign} at offset {reader.Offset - 1} is not 0 or 1.");
        }

        var digits = reader.ReadBytes(digitCount);
        var magnitude = new BigInteger(digits, isUnsigned: true, isBigEndian: false);
        var value = sign == 1 ? -magnitude : magnitude;
        return ErlangTermModel.NarrowInteger(value);
    }

    private static IReadOnlyDictionary<object, object?> ReadMap(ref Reader reader, int depth)
    {
        uint arity = reader.ReadUInt32();

        // Each entry costs at least a key tag byte and a value tag byte.
        reader.RequireAtLeast((long)arity * 2, "map entries");
        var map = new Dictionary<object, object?>((int)arity, ErlangTermModel.TermComparer);
        for (uint i = 0; i < arity; i++)
        {
            int keyOffset = reader.Offset;
            object? key = ReadTerm(ref reader, depth + 1);
            object? value = ReadTerm(ref reader, depth + 1);
            if (key is null)
            {
                throw new ErlangTermException($"Map key at offset {keyOffset} decoded to no term.");
            }

            if (!map.TryAdd(key, value))
            {
                throw new ErlangTermException($"Duplicate map key at offset {keyOffset}.");
            }
        }

        return map;
    }

    /// <summary>
    /// A bounds-checked cursor over the payload. Every read goes through
    /// <see cref="Require"/>, so a truncated or over-claiming payload raises
    /// <see cref="ErlangTermException"/> rather than an index or allocation failure.
    /// </summary>
    private ref struct Reader
    {
        private readonly ReadOnlySpan<byte> _bytes;

        public Reader(ReadOnlySpan<byte> bytes)
        {
            _bytes = bytes;
            Offset = 0;
        }

        public int Offset { get; private set; }

        public readonly int Remaining => _bytes.Length - Offset;

        public readonly bool AtEnd => Offset >= _bytes.Length;

        public byte ReadByte()
        {
            Require(1);
            return _bytes[Offset++];
        }

        public ReadOnlySpan<byte> ReadBytes(uint count)
        {
            Require(count);
            var slice = _bytes.Slice(Offset, (int)count);
            Offset += (int)count;
            return slice;
        }

        public ushort ReadUInt16()
        {
            Require(2);
            ushort value = BinaryPrimitives.ReadUInt16BigEndian(_bytes.Slice(Offset, 2));
            Offset += 2;
            return value;
        }

        public int ReadInt32()
        {
            Require(4);
            int value = BinaryPrimitives.ReadInt32BigEndian(_bytes.Slice(Offset, 4));
            Offset += 4;
            return value;
        }

        public uint ReadUInt32()
        {
            Require(4);
            uint value = BinaryPrimitives.ReadUInt32BigEndian(_bytes.Slice(Offset, 4));
            Offset += 4;
            return value;
        }

        public double ReadDouble()
        {
            Require(8);
            double value = BinaryPrimitives.ReadDoubleBigEndian(_bytes.Slice(Offset, 8));
            Offset += 8;
            return value;
        }

        public readonly void RequireAtLeast(long count, string what)
        {
            if (count > Remaining)
            {
                throw new ErlangTermException(
                    $"Declared {count} {what} at offset {Offset} but only {Remaining} byte(s) remain.");
            }
        }

        private readonly void Require(long count)
        {
            if (count > Remaining)
            {
                throw new ErlangTermException(
                    $"Truncated external term format input: {count} byte(s) needed at offset {Offset} but only {Remaining} remain.");
            }
        }
    }
}
