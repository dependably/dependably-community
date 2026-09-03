using System.Buffers;
using System.Buffers.Binary;

namespace Dependably.Protocol.Hex;

/// <summary>
/// A minimal proto2 encoder: fields are written in the order the caller emits them, which
/// <see cref="HexRegistryCodec"/> keeps in field-number order so the output matches what a
/// canonical encoder (hex.pm's <c>gpb</c>) produces for the same message. Optional fields are
/// omitted when null; a proto2 <c>required</c> field is always written, even when empty.
/// </summary>
internal sealed class ProtobufWriter
{
    private readonly ArrayBufferWriter<byte> _buffer = new();

    public int Length => _buffer.WrittenCount;

    public byte[] ToArray() => _buffer.WrittenSpan.ToArray();

    public void WriteString(int field, string value)
    {
        WriteTag(field, ProtobufWireType.LengthDelimited);
        int byteCount = HexProtocolText.Utf8Strict.GetByteCount(value);
        WriteVarint((ulong)byteCount);
        var span = _buffer.GetSpan(byteCount);
        HexProtocolText.Utf8Strict.GetBytes(value, span);
        _buffer.Advance(byteCount);
    }

    public void WriteBytes(int field, ReadOnlySpan<byte> value)
    {
        WriteTag(field, ProtobufWireType.LengthDelimited);
        WriteVarint((ulong)value.Length);
        _buffer.Write(value);
    }

    public void WriteMessage(int field, ProtobufWriter message) => WriteBytes(field, message._buffer.WrittenSpan);

    public void WriteInt32(int field, int value)
    {
        WriteTag(field, ProtobufWireType.Varint);
        // proto2 int32 sign-extends a negative value to ten bytes; encoding through int64 does that.
        WriteVarint(unchecked((ulong)(long)value));
    }

    public void WriteInt64(int field, long value)
    {
        WriteTag(field, ProtobufWireType.Varint);
        WriteVarint(unchecked((ulong)value));
    }

    public void WriteUInt32(int field, uint value)
    {
        WriteTag(field, ProtobufWireType.Varint);
        WriteVarint(value);
    }

    public void WriteBool(int field, bool value)
    {
        WriteTag(field, ProtobufWireType.Varint);
        WriteVarint(value ? 1UL : 0UL);
    }

    public void WriteFloat(int field, float value)
    {
        WriteTag(field, ProtobufWireType.Fixed32);
        var span = _buffer.GetSpan(4);
        BinaryPrimitives.WriteSingleLittleEndian(span, value);
        _buffer.Advance(4);
    }

    /// <summary>A <c>[packed=true]</c> repeated int32/enum field. Nothing is written for an empty list.</summary>
    public void WritePackedInt32(int field, IReadOnlyList<int> values)
    {
        if (values.Count == 0)
        {
            return;
        }

        var packed = new ProtobufWriter();
        foreach (int v in values)
        {
            packed.WriteVarint(unchecked((ulong)(long)v));
        }

        WriteMessage(field, packed);
    }

    private void WriteTag(int field, ProtobufWireType wireType) => WriteVarint(((ulong)field << 3) | (ulong)wireType);

    private void WriteVarint(ulong value)
    {
        var span = _buffer.GetSpan(10);
        int i = 0;
        while (value >= 0x80)
        {
            span[i++] = (byte)(value | 0x80);
            value >>= 7;
        }

        span[i++] = (byte)value;
        _buffer.Advance(i);
    }
}
