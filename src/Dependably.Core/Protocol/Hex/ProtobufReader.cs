using System.Buffers.Binary;

namespace Dependably.Protocol.Hex;

/// <summary>Protocol Buffers wire types (the three the Hex schemas use, plus the two skipped).</summary>
internal enum ProtobufWireType
{
    Varint = 0,
    Fixed64 = 1,
    LengthDelimited = 2,
    StartGroup = 3,
    EndGroup = 4,
    Fixed32 = 5,
}

/// <summary>
/// A bounds-checked forward reader over one protobuf message body. Every length prefix is
/// validated against the bytes actually present before anything is sliced or allocated, so a
/// hostile payload claiming a multi-gigabyte field fails on the claim rather than on the
/// allocation. Nesting is the caller's concern: a sub-message is read by constructing a new
/// reader over the slice <see cref="ReadLengthDelimited"/> returned, and
/// <see cref="HexRegistryCodec"/> bounds that depth.
/// </summary>
internal ref struct ProtobufReader
{
    private readonly ReadOnlySpan<byte> _data;
    private int _position;

    public ProtobufReader(ReadOnlySpan<byte> data)
    {
        _data = data;
        _position = 0;
    }

    public bool AtEnd => _position >= _data.Length;

    /// <summary>Reads the next field tag. False at end of input.</summary>
    public bool TryReadTag(out int fieldNumber, out ProtobufWireType wireType)
    {
        if (AtEnd)
        {
            fieldNumber = 0;
            wireType = ProtobufWireType.Varint;
            return false;
        }

        ulong tag = ReadVarint();
        fieldNumber = checked((int)(tag >> 3));
        wireType = (ProtobufWireType)(tag & 0x7);
        return fieldNumber != 0 && wireType is not (ProtobufWireType.StartGroup or ProtobufWireType.EndGroup)
            && (int)wireType <= 5
            ? true
            : throw new HexProtocolException("Malformed protobuf: invalid field tag.");
    }

    public ulong ReadVarint()
    {
        ulong result = 0;
        int shift = 0;
        while (true)
        {
            if (_position >= _data.Length)
            {
                throw new HexProtocolException("Malformed protobuf: truncated varint.");
            }

            byte b = _data[_position++];
            result |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0)
            {
                return result;
            }

            shift += 7;
            if (shift > 63)
            {
                throw new HexProtocolException("Malformed protobuf: varint longer than 10 bytes.");
            }
        }
    }

    /// <summary>A proto2 <c>int32</c>: negative values arrive as 10-byte varints and truncate to 32 bits.</summary>
    public int ReadInt32() => unchecked((int)ReadVarint());

    public long ReadInt64() => unchecked((long)ReadVarint());

    public uint ReadUInt32() => unchecked((uint)ReadVarint());

    public bool ReadBool() => ReadVarint() != 0;

    public ReadOnlySpan<byte> ReadLengthDelimited()
    {
        ulong length = ReadVarint();
        if (length > (ulong)(_data.Length - _position))
        {
            throw new HexProtocolException("Malformed protobuf: length-delimited field runs past the end of input.");
        }

        var slice = _data.Slice(_position, (int)length);
        _position += (int)length;
        return slice;
    }

    public string ReadString()
    {
        var bytes = ReadLengthDelimited();
        try
        {
            return HexProtocolText.Utf8Strict.GetString(bytes);
        }
        catch (Exception ex) when (ex is ArgumentException or System.Text.DecoderFallbackException)
        {
            throw new HexProtocolException("Malformed protobuf: string field is not valid UTF-8.", ex);
        }
    }

    public float ReadFixed32Float()
    {
        if (_data.Length - _position < 4)
        {
            throw new HexProtocolException("Malformed protobuf: truncated fixed32.");
        }

        float value = BinaryPrimitives.ReadSingleLittleEndian(_data.Slice(_position, 4));
        _position += 4;
        return value;
    }

    public double ReadFixed64Double()
    {
        if (_data.Length - _position < 8)
        {
            throw new HexProtocolException("Malformed protobuf: truncated fixed64.");
        }

        double value = BinaryPrimitives.ReadDoubleLittleEndian(_data.Slice(_position, 8));
        _position += 8;
        return value;
    }

    /// <summary>
    /// Skips a field this decoder does not model. Unknown fields are allowed by the protocol and
    /// expected across schema revisions, so they are stepped over rather than refused.
    /// </summary>
    public void Skip(ProtobufWireType wireType)
    {
        switch (wireType)
        {
            case ProtobufWireType.Varint: ReadVarint(); break;
            case ProtobufWireType.Fixed64: ReadFixed64Double(); break;
            case ProtobufWireType.LengthDelimited: ReadLengthDelimited(); break;
            case ProtobufWireType.Fixed32: ReadFixed32Float(); break;
            default: throw new HexProtocolException("Malformed protobuf: unsupported wire type.");
        }
    }

    /// <summary>
    /// Reads a repeated int32 field that may arrive packed (one length-delimited run of varints)
    /// or unpacked (one varint per tag). proto2 readers must accept both regardless of the
    /// schema's <c>[packed]</c> annotation.
    /// </summary>
    public void ReadRepeatedInt32(ProtobufWireType wireType, List<int> into, int maxCount)
    {
        if (wireType == ProtobufWireType.LengthDelimited)
        {
            var packed = new ProtobufReader(ReadLengthDelimited());
            while (!packed.AtEnd)
            {
                AddBounded(into, packed.ReadInt32(), maxCount);
            }
        }
        else
        {
            AddBounded(into, ReadInt32(), maxCount);
        }
    }

    public void ReadRepeatedUInt32(ProtobufWireType wireType, List<uint> into, int maxCount)
    {
        if (wireType == ProtobufWireType.LengthDelimited)
        {
            var packed = new ProtobufReader(ReadLengthDelimited());
            while (!packed.AtEnd)
            {
                AddBounded(into, packed.ReadUInt32(), maxCount);
            }
        }
        else
        {
            AddBounded(into, ReadUInt32(), maxCount);
        }
    }

    private static void AddBounded<T>(List<T> into, T value, int maxCount)
    {
        if (into.Count >= maxCount)
        {
            throw new HexProtocolException("Malformed protobuf: repeated field exceeds the element limit.");
        }

        into.Add(value);
    }
}

/// <summary>Strict UTF-8 shared by the protobuf and term codecs: invalid sequences throw rather than substitute.</summary>
internal static class HexProtocolText
{
    public static readonly System.Text.UTF8Encoding Utf8Strict = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
}
