using System.Globalization;
using System.Numerics;
using System.Text;
using Dependably.Protocol.Hex;
using Xunit;

namespace Dependably.Tests.Unit.Hex;

/// <summary>
/// Golden-vector and adversarial coverage for the Erlang external term format codec.
/// </summary>
/// <remarks>
/// <para>
/// Every <c>Vector…</c> constant is the byte list a real Erlang node printed for the expression
/// named in its comment, produced with
/// <c>docker run --rm erlang:latest escript …</c> running
/// <c>io:format("~w~n", [binary_to_list(term_to_binary(Term))])</c>. Nothing here was derived
/// from this codec's own output, so a shared misreading of the format cannot make the suite
/// agree with itself.
/// </para>
/// <para>
/// The reverse direction is pinned too: <see cref="Encode_TermsErlangReadsBack_MatchPinnedBytes"/>
/// carries the bytes this encoder produces alongside the <c>~p</c> rendering a real node printed
/// after <c>binary_to_term/1</c> on exactly those bytes, which is what proves Erlang accepts the
/// deliberate encoding choices (map key ordering, LIST_EXT instead of STRING_EXT, SMALL_BIG_EXT
/// for a small <see cref="BigInteger"/>).
/// </para>
/// </remarks>
[Trait("Category", "Unit")]
public sealed class ErlangTermFormatTests
{
    // term_to_binary(0)
    private const string VectorSmallIntegerZero = "131,97,0";

    // term_to_binary(255)
    private const string VectorSmallIntegerMax = "131,97,255";

    // term_to_binary(256)
    private const string VectorInteger256 = "131,98,0,0,1,0";

    // term_to_binary(-1234567)
    private const string VectorIntegerNegative = "131,98,255,237,41,121";

    // term_to_binary(-2147483648)
    private const string VectorIntegerMinInt32 = "131,98,128,0,0,0";

    // term_to_binary(1 bsl 70)
    private const string VectorSmallBigTwoPow70 = "131,110,9,0,0,0,0,0,0,0,0,0,64";

    // term_to_binary(-(1 bsl 70))
    private const string VectorSmallBigNegative = "131,110,9,1,0,0,0,0,0,0,0,0,64";

    // term_to_binary(1 bsl 3000) — header only; the 376 little-endian digit bytes are 375 zeroes
    // followed by 1, which the test builds rather than pinning verbatim.
    private const string VectorLargeBigHeader = "131,111,0,0,1,120";

    // term_to_binary(3.14159)
    private const string VectorFloatPi = "131,70,64,9,33,249,240,27,134,110";

    // term_to_binary(-1.0e-3)
    private const string VectorFloatSmallExponent = "131,70,191,80,98,77,210,241,169,252";

    // term_to_binary({true, false})
    private const string VectorAtomTrueFalse = "131,104,2,119,4,116,114,117,101,119,5,102,97,108,115,101";

    // term_to_binary({nil, undefined})
    private const string VectorAtomNilUndefined = "131,104,2,119,3,110,105,108,119,9,117,110,100,101,102,105,110,101,100";

    // term_to_binary(list_to_atom([233, $l, $i, $x, $i, $r])) — the atom élixir
    private const string VectorAtomUnicode = "131,119,7,195,169,108,105,120,105,114";

    // term_to_binary(list_to_atom(lists:duplicate(200, 233))) — header only; the payload is the
    // UTF-8 encoding of é repeated 200 times, which is 400 bytes and so needs ATOM_UTF8_EXT.
    private const string VectorLongAtomHeader = "131,118,1,144";

    // term_to_binary([])
    private const string VectorNil = "131,106";

    // term_to_binary("abc") — a charlist, which Erlang writes as STRING_EXT
    private const string VectorStringExtAbc = "131,107,0,3,97,98,99";

    // term_to_binary([1, <<"two">>, three])
    private const string VectorListMixed = "131,108,0,0,0,3,97,1,109,0,0,0,3,116,119,111,119,5,116,104,114,101,101,106";

    // term_to_binary(<<"decimal">>)
    private const string VectorBinaryDecimal = "131,109,0,0,0,7,100,101,99,105,109,97,108";

    // term_to_binary(<<"café — \"quoted\"">>)
    private const string VectorBinaryUtf8 =
        "131,109,0,0,0,18,99,97,102,195,169,32,226,128,148,32,34,113,117,111,116,101,100,34";

    // term_to_binary(<<255, 254, 0>>)
    private const string VectorBinaryInvalidUtf8 = "131,109,0,0,0,3,255,254,0";

    // term_to_binary(<<>>)
    private const string VectorBinaryEmpty = "131,109,0,0,0,0";

    // term_to_binary({<<"name">>, <<"decimal">>})
    private const string VectorTuplePair =
        "131,104,2,109,0,0,0,4,110,97,109,101,109,0,0,0,7,100,101,99,105,109,97,108";

    // term_to_binary(list_to_tuple(lists:seq(1, 300))) — header only; the 300 elements are built
    // by the test, 1..255 as SMALL_INTEGER_EXT and 256..300 as INTEGER_EXT.
    private const string VectorLargeTupleHeader = "131,105,0,0,1,44";

    // term_to_binary(#{<<"reason">> => <<"deprecated">>})
    private const string VectorMapSingle =
        "131,116,0,0,0,1,109,0,0,0,6,114,101,97,115,111,110,109,0,0,0,10,100,101,112,114,101,99,97,116,101,100";

    // term_to_binary(#{<<"a">> => 1, <<"b">> => [1, 2], c => 2.5}) — note Erlang's own key order
    // (atom before binary) and its STRING_EXT encoding of the small-integer list.
    private const string VectorMapMulti =
        "131,116,0,0,0,3,119,1,99,70,64,4,0,0,0,0,0,0,109,0,0,0,1,97,97,1,109,0,0,0,1,98,107,0,2,1,2";

    // term_to_binary(#{})
    private const string VectorMapEmpty = "131,116,0,0,0,0";

    // term_to_binary({ok, [#{<<"deps">> => [{<<"jason">>, <<"~> 1.0">>}]}], 3})
    private const string VectorNestedMapInListInTuple =
        "131,104,3,119,2,111,107,108,0,0,0,1,116,0,0,0,1,109,0,0,0,4,100,101,112,115,108,0,0,0,1,104,2," +
        "109,0,0,0,5,106,97,115,111,110,109,0,0,0,6,126,62,32,49,46,48,106,106,97,3";

    // term_to_binary({<<"requirements">>, [{<<"jason">>, [{<<"app">>, <<"jason">>},
    //   {<<"optional">>, false}, {<<"requirement">>, <<"~> 1.0">>},
    //   {<<"repository">>, <<"hexpm">>}]}]})
    private const string VectorMetadataRequirements =
        "131,104,2,109,0,0,0,12,114,101,113,117,105,114,101,109,101,110,116,115,108,0,0,0,1,104,2,109," +
        "0,0,0,5,106,97,115,111,110,108,0,0,0,4,104,2,109,0,0,0,3,97,112,112,109,0,0,0,5,106,97,115,111," +
        "110,104,2,109,0,0,0,8,111,112,116,105,111,110,97,108,119,5,102,97,108,115,101,104,2,109,0,0,0," +
        "11,114,101,113,117,105,114,101,109,101,110,116,109,0,0,0,6,126,62,32,49,46,48,104,2,109,0,0,0," +
        "10,114,101,112,111,115,105,116,111,114,121,109,0,0,0,5,104,101,120,112,109,106,106";

    // term_to_binary([a | b]) — an improper list
    private const string VectorImproperList = "131,108,0,0,0,1,119,1,97,119,1,98";

    // term_to_binary(self()) — NEW_PID_EXT
    private const string VectorPid =
        "131,88,119,13,110,111,110,111,100,101,64,110,111,104,111,115,116,0,0,0,10,0,0,0,0,0,0,0,0";

    // term_to_binary(fun(X) -> X end) — NEW_FUN_EXT header; the tag alone must be refused, so the
    // rest of the real vector is not needed to prove the rejection.
    private const string VectorFunHeader = "131,112,0,0,0,118,1,6,114,219,145,187,242,95,140,157";

    [Fact]
    public void Decode_SmallAndPlainIntegerVectors_ProduceLongs()
    {
        Assert.Equal(0L, ErlangTermFormat.Decode(Etf(VectorSmallIntegerZero)));
        Assert.Equal(255L, ErlangTermFormat.Decode(Etf(VectorSmallIntegerMax)));
        Assert.Equal(256L, ErlangTermFormat.Decode(Etf(VectorInteger256)));
        Assert.Equal(-1234567L, ErlangTermFormat.Decode(Etf(VectorIntegerNegative)));
        Assert.Equal((long)int.MinValue, ErlangTermFormat.Decode(Etf(VectorIntegerMinInt32)));
    }

    [Fact]
    public void Decode_SmallBigVectors_ProduceBigIntegers()
    {
        Assert.Equal(BigInteger.Pow(2, 70), ErlangTermFormat.Decode(Etf(VectorSmallBigTwoPow70)));
        Assert.Equal(-BigInteger.Pow(2, 70), ErlangTermFormat.Decode(Etf(VectorSmallBigNegative)));
    }

    [Fact]
    public void Decode_LargeBigVector_ProducesBigInteger()
    {
        Assert.Equal(BigInteger.Pow(2, 3000), ErlangTermFormat.Decode(LargeBigVector()));
    }

    [Fact]
    public void Decode_BigIntegerThatFitsALong_NarrowsToLong()
    {
        // A hand-built SMALL_BIG_EXT holding 5: Erlang accepts the wide encoding of a small value,
        // and the decoder normalizes it to the same long a SMALL_INTEGER_EXT would give.
        Assert.Equal(5L, ErlangTermFormat.Decode(Etf("131,110,1,0,5")));
    }

    [Fact]
    public void Decode_FloatVectors_ProduceDoubles()
    {
        Assert.Equal(3.14159d, ErlangTermFormat.Decode(Etf(VectorFloatPi)));
        Assert.Equal(-1.0e-3d, ErlangTermFormat.Decode(Etf(VectorFloatSmallExponent)));
    }

    [Fact]
    public void Decode_AtomVectors_ProduceAtoms()
    {
        AssertTerm(ErlangTermModel.Tuple(ErlangAtom.True, ErlangAtom.False), ErlangTermFormat.Decode(Etf(VectorAtomTrueFalse)));
        AssertTerm(
            ErlangTermModel.Tuple(ErlangAtom.Nil, ErlangAtom.Undefined),
            ErlangTermFormat.Decode(Etf(VectorAtomNilUndefined)));
        AssertTerm(new ErlangAtom("élixir"), ErlangTermFormat.Decode(Etf(VectorAtomUnicode)));
    }

    [Fact]
    public void Decode_AtomLongerThan255Bytes_ReadsAtomUtf8Ext()
    {
        AssertTerm(new ErlangAtom(new string('é', 200)), ErlangTermFormat.Decode(LongAtomVector()));
    }

    [Fact]
    public void Decode_LegacyLatin1AtomExt_ProducesAtom()
    {
        // ATOM_EXT (tag 100) is the legacy Latin-1 form. Modern OTP writes tag 119 instead, so
        // this vector is built to the specification rather than captured from term_to_binary/1:
        // a 2-byte length and the Latin-1 bytes of "café".
        AssertTerm(new ErlangAtom("café"), ErlangTermFormat.Decode(Etf("131,100,0,4,99,97,102,233")));
    }

    [Fact]
    public void Decode_NilVector_ProducesEmptyList()
    {
        AssertTerm(ErlangTermModel.List(), ErlangTermFormat.Decode(Etf(VectorNil)));
    }

    [Fact]
    public void Decode_StringExtVector_ProducesListOfIntegers()
    {
        // STRING_EXT is a compact list of small integers, not a binary — Erlang reads the same
        // term back from a LIST_EXT of the same integers.
        AssertTerm(ErlangTermModel.List(97L, 98L, 99L), ErlangTermFormat.Decode(Etf(VectorStringExtAbc)));
    }

    [Fact]
    public void Decode_MixedListVector_ProducesListOfMixedTerms()
    {
        AssertTerm(
            ErlangTermModel.List(1L, "two", new ErlangAtom("three")),
            ErlangTermFormat.Decode(Etf(VectorListMixed)));
    }

    [Fact]
    public void Decode_BinaryVectors_ProduceStringsWhenValidUtf8AndBytesOtherwise()
    {
        Assert.Equal("decimal", ErlangTermFormat.Decode(Etf(VectorBinaryDecimal)));
        Assert.Equal("café — \"quoted\"", ErlangTermFormat.Decode(Etf(VectorBinaryUtf8)));
        Assert.Equal(string.Empty, ErlangTermFormat.Decode(Etf(VectorBinaryEmpty)));
        Assert.Equal(new byte[] { 255, 254, 0 }, Assert.IsType<byte[]>(ErlangTermFormat.Decode(Etf(VectorBinaryInvalidUtf8))));
    }

    [Fact]
    public void Decode_TupleVector_ProducesTuple()
    {
        AssertTerm(ErlangTermModel.Tuple("name", "decimal"), ErlangTermFormat.Decode(Etf(VectorTuplePair)));
    }

    [Fact]
    public void Decode_LargeTupleVector_ProducesTupleOfArity300()
    {
        object? decoded = ErlangTermFormat.Decode(LargeTupleVector());
        var tuple = Assert.IsType<ErlangTuple>(decoded);
        Assert.Equal(300, tuple.Arity);
        Assert.Equal(1L, tuple[0]);
        Assert.Equal(255L, tuple[254]);
        Assert.Equal(256L, tuple[255]);
        Assert.Equal(300L, tuple[299]);
    }

    [Fact]
    public void Decode_MapVectors_ProduceMapsKeyedByTheDecodedKeyTerm()
    {
        var single = Assert.IsAssignableFrom<IReadOnlyDictionary<object, object?>>(
            ErlangTermFormat.Decode(Etf(VectorMapSingle)));
        Assert.Equal("deprecated", single["reason"]);

        var multi = Assert.IsAssignableFrom<IReadOnlyDictionary<object, object?>>(
            ErlangTermFormat.Decode(Etf(VectorMapMulti)));
        Assert.Equal(3, multi.Count);
        Assert.Equal(1L, multi["a"]);
        AssertTerm(ErlangTermModel.List(1L, 2L), multi["b"]);
        Assert.Equal(2.5d, multi[new ErlangAtom("c")]);

        var empty = Assert.IsAssignableFrom<IReadOnlyDictionary<object, object?>>(
            ErlangTermFormat.Decode(Etf(VectorMapEmpty)));
        Assert.Empty(empty);
    }

    [Fact]
    public void Decode_NestedMapInListInTupleVector_ProducesTheWholeShape()
    {
        AssertTerm(
            ErlangTermModel.Tuple(
                new ErlangAtom("ok"),
                ErlangTermModel.List(ErlangTermModel.Map(("deps", ErlangTermModel.List(ErlangTermModel.Tuple("jason", "~> 1.0"))))),
                3L),
            ErlangTermFormat.Decode(Etf(VectorNestedMapInListInTuple)));
    }

    [Fact]
    public void Decode_MetadataRequirementsVector_ProducesTheProplistShape()
    {
        AssertTerm(
            ErlangTermModel.Tuple(
                "requirements",
                ErlangTermModel.List(ErlangTermModel.Tuple(
                    "jason",
                    ErlangTermModel.List(
                        ErlangTermModel.Tuple("app", "jason"),
                        ErlangTermModel.Tuple("optional", ErlangAtom.False),
                        ErlangTermModel.Tuple("requirement", "~> 1.0"),
                        ErlangTermModel.Tuple("repository", "hexpm"))))),
            ErlangTermFormat.Decode(Etf(VectorMetadataRequirements)));
    }

    [Fact]
    public void Encode_ScalarTerms_MatchTheErlangVectors()
    {
        Assert.Equal(Etf(VectorSmallIntegerZero), ErlangTermFormat.Encode(0L));
        Assert.Equal(Etf(VectorSmallIntegerMax), ErlangTermFormat.Encode(255));
        Assert.Equal(Etf(VectorInteger256), ErlangTermFormat.Encode(256L));
        Assert.Equal(Etf(VectorIntegerNegative), ErlangTermFormat.Encode(-1234567L));
        Assert.Equal(Etf(VectorIntegerMinInt32), ErlangTermFormat.Encode(int.MinValue));
        Assert.Equal(Etf(VectorSmallBigTwoPow70), ErlangTermFormat.Encode(BigInteger.Pow(2, 70)));
        Assert.Equal(Etf(VectorSmallBigNegative), ErlangTermFormat.Encode(-BigInteger.Pow(2, 70)));
        Assert.Equal(LargeBigVector(), ErlangTermFormat.Encode(BigInteger.Pow(2, 3000)));
        Assert.Equal(Etf(VectorFloatPi), ErlangTermFormat.Encode(3.14159d));
        Assert.Equal(Etf(VectorFloatSmallExponent), ErlangTermFormat.Encode(-1.0e-3d));
        Assert.Equal(Etf(VectorBinaryDecimal), ErlangTermFormat.Encode("decimal"));
        Assert.Equal(Etf(VectorBinaryUtf8), ErlangTermFormat.Encode("café — \"quoted\""));
        Assert.Equal(Etf(VectorBinaryInvalidUtf8), ErlangTermFormat.Encode(new byte[] { 255, 254, 0 }));
        Assert.Equal(Etf(VectorBinaryEmpty), ErlangTermFormat.Encode(string.Empty));
        Assert.Equal(Etf(VectorNil), ErlangTermFormat.Encode(ErlangTermModel.List()));
        Assert.Equal(Etf(VectorAtomUnicode), ErlangTermFormat.Encode(new ErlangAtom("élixir")));
        Assert.Equal(LongAtomVector(), ErlangTermFormat.Encode(new ErlangAtom(new string('é', 200))));
    }

    [Fact]
    public void Encode_CompoundTerms_MatchTheErlangVectors()
    {
        Assert.Equal(Etf(VectorAtomTrueFalse), ErlangTermFormat.Encode(ErlangTermModel.Tuple(true, false)));
        Assert.Equal(
            Etf(VectorAtomNilUndefined),
            ErlangTermFormat.Encode(ErlangTermModel.Tuple(null, ErlangAtom.Undefined)));
        Assert.Equal(Etf(VectorTuplePair), ErlangTermFormat.Encode(ErlangTermModel.Tuple("name", "decimal")));
        Assert.Equal(
            Etf(VectorMapSingle),
            ErlangTermFormat.Encode(ErlangTermModel.Map(("reason", "deprecated"))));
        Assert.Equal(Etf(VectorMapEmpty), ErlangTermFormat.Encode(ErlangTermModel.Map()));
        Assert.Equal(
            Etf(VectorListMixed),
            ErlangTermFormat.Encode(ErlangTermModel.List(1L, "two", new ErlangAtom("three"))));
        Assert.Equal(
            Etf(VectorNestedMapInListInTuple),
            ErlangTermFormat.Encode(ErlangTermModel.Tuple(
                new ErlangAtom("ok"),
                ErlangTermModel.List(ErlangTermModel.Map(("deps", ErlangTermModel.List(ErlangTermModel.Tuple("jason", "~> 1.0"))))),
                3L)));
        Assert.Equal(
            Etf(VectorMetadataRequirements),
            ErlangTermFormat.Encode(ErlangTermModel.Tuple(
                "requirements",
                ErlangTermModel.List(ErlangTermModel.Tuple(
                    "jason",
                    ErlangTermModel.List(
                        ErlangTermModel.Tuple("app", "jason"),
                        ErlangTermModel.Tuple("optional", false),
                        ErlangTermModel.Tuple("requirement", "~> 1.0"),
                        ErlangTermModel.Tuple("repository", "hexpm")))))));
        Assert.Equal(LargeTupleVector(), ErlangTermFormat.Encode(new ErlangTuple(LargeTupleItems())));
    }

    [Fact]
    public void Encode_ListOfSmallIntegers_NeverEmitsStringExt()
    {
        // Erlang would write STRING_EXT here; a LIST_EXT of SMALL_INTEGER_EXT is the same term on
        // the Erlang side and keeps one encoding path for every list.
        byte[] encoded = ErlangTermFormat.Encode(ErlangTermModel.List(97L, 98L, 99L));
        Assert.Equal(Etf("131,108,0,0,0,3,97,97,97,98,97,99,106"), encoded);
        Assert.DoesNotContain((byte)107, encoded);
        AssertTerm(ErlangTermFormat.Decode(Etf(VectorStringExtAbc)), ErlangTermFormat.Decode(encoded));
    }

    [Fact]
    public void Encode_MapEntries_AreOrderedByEncodedKeyBytesWhateverTheInsertionOrder()
    {
        var forwards = new Dictionary<object, object?>(ErlangTermModel.TermComparer)
        {
            ["alpha"] = 1L,
            ["beta"] = 2L,
            ["gamma"] = 3L,
        };
        var backwards = new Dictionary<object, object?>(ErlangTermModel.TermComparer)
        {
            ["gamma"] = 3L,
            ["beta"] = 2L,
            ["alpha"] = 1L,
        };

        Assert.Equal(ErlangTermFormat.Encode(forwards), ErlangTermFormat.Encode(backwards));
    }

    [Fact]
    public void Encode_MapWithTwoKeysThatEncodeIdentically_Throws()
    {
        // "a" as a string and as its UTF-8 bytes are one key on the Erlang side.
        var map = new Dictionary<object, object?>
        {
            ["a"] = 1L,
            [new byte[] { 97 }] = 2L,
        };

        Assert.Throws<ErlangTermException>(() => ErlangTermFormat.Encode(map));
    }

    [Fact]
    public void Encode_StringKeyedDictionaryShapes_AreAllMaps()
    {
        byte[] expected = ErlangTermFormat.Encode(ErlangTermModel.Map(("reason", "deprecated")));
        var mutable = new Dictionary<string, object?> { ["reason"] = "deprecated" };
        IReadOnlyDictionary<string, object?> readOnly = mutable;

        Assert.Equal(expected, ErlangTermFormat.Encode(mutable));
        Assert.Equal(expected, ErlangTermFormat.Encode(readOnly));
    }

    [Fact]
    public void Encode_UnsupportedType_Throws()
    {
        Assert.Throws<ErlangTermException>(() => ErlangTermFormat.Encode(new object()));
    }

    [Fact]
    public void Encode_TermNestedDeeperThanTheLimit_Throws()
    {
        object? nested = ErlangTermModel.List();
        for (int i = 0; i < 70; i++)
        {
            nested = ErlangTermModel.List(nested);
        }

        Assert.Throws<ErlangTermException>(() => ErlangTermFormat.Encode(nested));
    }

    [Fact]
    public void Encode_TermsErlangReadsBack_MatchPinnedBytes()
    {
        // Each pinned array is this encoder's output, and the comment is what a real Erlang node
        // printed for binary_to_term/1 of exactly those bytes with ~p. That is the direction a
        // decode-side golden vector cannot cover: it proves Erlang accepts the encoding choices
        // this codec makes where they differ from term_to_binary/1's own.

        // #{<<"name">> => <<"decimal">>,<<"version">> => <<"2.3.0">>}
        Assert.Equal(
            Etf("131,116,0,0,0,2,109,0,0,0,4,110,97,109,101,109,0,0,0,7,100,101,99,105,109,97,108,109,0," +
                "0,0,7,118,101,114,115,105,111,110,109,0,0,0,5,50,46,51,46,48"),
            ErlangTermFormat.Encode(ErlangTermModel.Map(("name", "decimal"), ("version", "2.3.0"))));

        // [1,2,3]
        Assert.Equal(
            Etf("131,108,0,0,0,3,97,1,97,2,97,3,106"),
            ErlangTermFormat.Encode(ErlangTermModel.List(1L, 2L, 3L)));

        // "abc"
        Assert.Equal(
            Etf("131,108,0,0,0,3,97,97,97,98,97,99,106"),
            ErlangTermFormat.Encode(new ErlangCharlist("abc")));

        // 5
        Assert.Equal(Etf("131,110,1,0,5"), ErlangTermFormat.Encode(new BigInteger(5)));

        // {true,false,nil}
        Assert.Equal(
            Etf("131,104,3,119,4,116,114,117,101,119,5,102,97,108,115,101,119,3,110,105,108"),
            ErlangTermFormat.Encode(ErlangTermModel.Tuple(true, false, null)));

        // <<255,254,0>>
        Assert.Equal(Etf(VectorBinaryInvalidUtf8), ErlangTermFormat.Encode(new byte[] { 255, 254, 0 }));
    }

    [Theory]
    [InlineData(VectorSmallIntegerZero)]
    [InlineData(VectorIntegerNegative)]
    [InlineData(VectorSmallBigTwoPow70)]
    [InlineData(VectorFloatPi)]
    [InlineData(VectorAtomTrueFalse)]
    [InlineData(VectorNil)]
    [InlineData(VectorListMixed)]
    [InlineData(VectorBinaryUtf8)]
    [InlineData(VectorBinaryInvalidUtf8)]
    [InlineData(VectorTuplePair)]
    [InlineData(VectorMapSingle)]
    [InlineData(VectorNestedMapInListInTuple)]
    [InlineData(VectorMetadataRequirements)]
    public void DecodeThenEncodeThenDecode_ReproducesTheSameTerm(string vector)
    {
        object? decoded = ErlangTermFormat.Decode(Etf(vector));
        AssertTerm(decoded, ErlangTermFormat.Decode(ErlangTermFormat.Encode(decoded)));
    }

    [Fact]
    public void Decode_TruncatedInput_Throws()
    {
        // A BINARY_EXT claiming seven bytes with only three present.
        Assert.Throws<ErlangTermException>(() => ErlangTermFormat.Decode(Etf("131,109,0,0,0,7,100,101,99")));

        // The version byte alone.
        Assert.Throws<ErlangTermException>(() => ErlangTermFormat.Decode(Etf("131")));

        // Every prefix of a real vector is truncated somewhere.
        byte[] full = Etf(VectorMetadataRequirements);
        for (int length = 1; length < full.Length; length++)
        {
            Assert.Throws<ErlangTermException>(() => ErlangTermFormat.Decode(full.AsSpan(0, length).ToArray()));
        }
    }

    [Fact]
    public void Decode_ListClaimingMoreElementsThanTheInputHolds_ThrowsWithoutAllocating()
    {
        // LIST_EXT with a length of 4294967295 and nothing following it.
        Assert.Throws<ErlangTermException>(() => ErlangTermFormat.Decode(Etf("131,108,255,255,255,255")));

        // LARGE_TUPLE_EXT with the same lie.
        Assert.Throws<ErlangTermException>(() => ErlangTermFormat.Decode(Etf("131,105,255,255,255,255")));

        // MAP_EXT with the same lie.
        Assert.Throws<ErlangTermException>(() => ErlangTermFormat.Decode(Etf("131,116,255,255,255,255")));

        // LARGE_BIG_EXT with the same lie.
        Assert.Throws<ErlangTermException>(() => ErlangTermFormat.Decode(Etf("131,111,255,255,255,255,0")));
    }

    [Fact]
    public void Decode_ProcessIdentifierTag_Throws()
    {
        var thrown = Assert.Throws<ErlangTermException>(() => ErlangTermFormat.Decode(Etf(VectorPid)));
        Assert.Contains("88", thrown.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Decode_FunctionTag_Throws()
    {
        Assert.Throws<ErlangTermException>(() => ErlangTermFormat.Decode(Etf(VectorFunHeader)));
    }

    [Theory]
    [InlineData(77)]
    [InlineData(88)]
    [InlineData(89)]
    [InlineData(90)]
    [InlineData(101)]
    [InlineData(102)]
    [InlineData(103)]
    [InlineData(112)]
    [InlineData(113)]
    [InlineData(114)]
    [InlineData(115)]
    [InlineData(117)]
    [InlineData(80)]
    [InlineData(99)]
    public void Decode_TagOutsideTheSafeSubset_Throws(int tag)
    {
        byte[] input = new byte[] { 131, (byte)tag, 0, 0, 0, 0, 0, 0, 0, 0 };
        Assert.Throws<ErlangTermException>(() => ErlangTermFormat.Decode(input));
    }

    [Fact]
    public void Decode_ImproperList_Throws()
    {
        var thrown = Assert.Throws<ErlangTermException>(() => ErlangTermFormat.Decode(Etf(VectorImproperList)));
        Assert.Contains("Improper list", thrown.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Decode_MapWithDuplicateKeys_Throws()
    {
        // MAP_EXT of arity 2 whose two keys are both <<"a">>.
        byte[] input = Etf("131,116,0,0,0,2,109,0,0,0,1,97,97,1,109,0,0,0,1,97,97,2");
        var thrown = Assert.Throws<ErlangTermException>(() => ErlangTermFormat.Decode(input));
        Assert.Contains("Duplicate map key", thrown.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Decode_DepthBomb_Throws()
    {
        // 70 nested single-element lists, which is past the 64-level limit.
        var buffer = new List<byte> { 131 };
        for (int i = 0; i < 70; i++)
        {
            buffer.AddRange(new byte[] { 108, 0, 0, 0, 1 });
        }

        buffer.Add(106);
        for (int i = 0; i < 70; i++)
        {
            buffer.Add(106);
        }

        Assert.Throws<ErlangTermException>(() => ErlangTermFormat.Decode(buffer.ToArray()));
    }

    [Fact]
    public void Decode_TrailingBytesAfterTheRootTerm_Throws()
    {
        var thrown = Assert.Throws<ErlangTermException>(() => ErlangTermFormat.Decode(Etf("131,97,1,97,2")));
        Assert.Contains("trailing", thrown.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Decode_WrongOrMissingVersionByte_Throws()
    {
        Assert.Throws<ErlangTermException>(() => ErlangTermFormat.Decode(Etf("130,97,1")));
        Assert.Throws<ErlangTermException>(() => ErlangTermFormat.Decode(Array.Empty<byte>()));
    }

    [Fact]
    public void Decode_BignumWithAnInvalidSignByte_Throws()
    {
        Assert.Throws<ErlangTermException>(() => ErlangTermFormat.Decode(Etf("131,110,1,2,5")));
    }

    [Fact]
    public void Decode_AtomWithInvalidUtf8_Throws()
    {
        Assert.Throws<ErlangTermException>(() => ErlangTermFormat.Decode(Etf("131,119,2,255,254")));
    }

    [Fact]
    public void Decode_InputOverTheSizeCap_ThrowsBeforeParsing()
    {
        byte[] oversized = new byte[ErlangTermFormat.MaxInputBytes + 1];
        oversized[0] = 131;
        oversized[1] = 97;

        var thrown = Assert.Throws<ErlangTermException>(() => ErlangTermFormat.Decode(oversized));
        Assert.Contains("exceeds", thrown.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Decode_MemoryAndArrayOverloads_AgreeWithTheSpanOverload()
    {
        byte[] vector = Etf(VectorTuplePair);
        AssertTerm(ErlangTermFormat.Decode(vector.AsSpan()), ErlangTermFormat.Decode(vector));
        AssertTerm(ErlangTermFormat.Decode(vector.AsSpan()), ErlangTermFormat.Decode(new ReadOnlyMemory<byte>(vector)));
    }

    private static byte[] Etf(string decimalCsv) =>
        decimalCsv.Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(part => byte.Parse(part.Trim(), CultureInfo.InvariantCulture))
            .ToArray();

    private static byte[] LargeBigVector()
    {
        var bytes = new List<byte>(Etf(VectorLargeBigHeader))
        {
            0
        };
        bytes.AddRange(new byte[375]);
        bytes.Add(1);
        return bytes.ToArray();
    }

    private static byte[] LongAtomVector()
    {
        var bytes = new List<byte>(Etf(VectorLongAtomHeader));
        bytes.AddRange(Encoding.UTF8.GetBytes(new string('é', 200)));
        return bytes.ToArray();
    }

    private static object?[] LargeTupleItems() =>
        Enumerable.Range(1, 300).Select(value => (object?)(long)value).ToArray();

    private static byte[] LargeTupleVector()
    {
        var bytes = new List<byte>(Etf(VectorLargeTupleHeader));
        for (int value = 1; value <= 300; value++)
        {
            if (value <= 255)
            {
                bytes.Add(97);
                bytes.Add((byte)value);
                continue;
            }

            bytes.Add(98);
            bytes.AddRange(new byte[] { 0, 0, (byte)(value >> 8), (byte)value });
        }

        return bytes.ToArray();
    }

    private static void AssertTerm(object? expected, object? actual)
    {
        if (!ErlangTermModel.DeepEquals(expected, actual))
        {
            Assert.Fail($"Expected {ErlangTermText.Print(expected)} but got {ErlangTermText.Print(actual)}.");
        }
    }
}
