using System.Numerics;
using System.Text;
using Dependably.Protocol.Hex;
using Xunit;

namespace Dependably.Tests.Unit.Hex;

/// <summary>
/// Coverage for the textual term codec, anchored on two kinds of real input: the verbatim
/// <c>metadata.config</c> of decimal 2.3.0 as published on repo.hex.pm, and rendering vectors
/// captured from a real Erlang node with
/// <c>io:format("~s|~tp|~ts~n", [Name, Term, io_lib_pretty:print(Term, [{encoding, utf8}])])</c>
/// under <c>docker run --rm erlang:latest escript …</c>. Where <see cref="ErlangTermText.Print"/>
/// deliberately differs from Erlang's pretty printer, the test says so and pins both sides.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ErlangTermTextTests
{
    private const string DecimalMetadataConfig = """
        {<<"links">>,[{<<"GitHub">>,<<"https://github.com/ericmj/decimal">>}]}.
        {<<"name">>,<<"decimal">>}.
        {<<"version">>,<<"2.3.0">>}.
        {<<"description">>,<<"Arbitrary precision decimal arithmetic.">>}.
        {<<"elixir">>,<<"~> 1.8">>}.
        {<<"app">>,<<"decimal">>}.
        {<<"licenses">>,[<<"Apache-2.0">>]}.
        {<<"requirements">>,[]}.
        {<<"files">>,
         [<<"lib">>,<<"lib/decimal">>,<<"lib/decimal/error.ex">>,
          <<"lib/decimal/context.ex">>,<<"lib/decimal/macros.ex">>,
          <<"lib/decimal.ex">>,<<".formatter.exs">>,<<"mix.exs">>,<<"README.md">>,
          <<"LICENSE.txt">>,<<"CHANGELOG.md">>]}.
        {<<"build_tools">>,[<<"mix">>]}.
        """;

    [Fact]
    public void Consult_DecimalMetadataConfig_ReadsEveryTerm()
    {
        var terms = ErlangTermText.Consult(DecimalMetadataConfig);

        Assert.Equal(10, terms.Count);
        AssertTerm(ErlangTermModel.Tuple("name", "decimal"), terms[1]);
        AssertTerm(ErlangTermModel.Tuple("build_tools", ErlangTermModel.List("mix")), terms[9]);
        AssertTerm(ErlangTermModel.Tuple("version", "2.3.0"), terms[2]);
        AssertTerm(ErlangTermModel.Tuple("elixir", "~> 1.8"), terms[4]);
        AssertTerm(ErlangTermModel.Tuple("licenses", ErlangTermModel.List("Apache-2.0")), terms[6]);
        AssertTerm(ErlangTermModel.Tuple("requirements", ErlangTermModel.List()), terms[7]);
        AssertTerm(
            ErlangTermModel.Tuple(
                "links",
                ErlangTermModel.List(ErlangTermModel.Tuple("GitHub", "https://github.com/ericmj/decimal"))),
            terms[0]);
    }

    [Fact]
    public void Consult_MetadataConfigFileList_KeepsOrderAcrossWrappedLines()
    {
        // The files entry is the one term the publisher wraps across four lines, so it is what
        // proves whitespace inside a term is insignificant.
        var files = Assert.IsType<ErlangTuple>(ErlangTermText.Consult(DecimalMetadataConfig)[8]);
        var entries = Assert.IsAssignableFrom<IReadOnlyList<object?>>(files[1]);

        Assert.Equal(11, entries.Count);
        Assert.Equal("lib", entries[0]);
        Assert.Equal(".formatter.exs", entries[6]);
        Assert.Equal("CHANGELOG.md", entries[10]);
    }

    [Fact]
    public void Consult_RequirementsAsTupleKeyedProplist_ReadsTheNestedShape()
    {
        const string Text =
            """{<<"requirements">>,[{<<"jason">>,[{<<"app">>,<<"jason">>},{<<"optional">>,false},{<<"requirement">>,<<"~> 1.0">>},{<<"repository">>,<<"hexpm">>}]}]}.""";

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
            Assert.Single(ErlangTermText.Consult(Text)));
    }

    [Fact]
    public void Consult_RequirementsAsLegacyListOfProplists_ReadsTheNestedShape()
    {
        const string Text =
            """{<<"requirements">>,[[{<<"name">>,<<"jason">>},{<<"app">>,<<"jason">>},{<<"optional">>,false},{<<"requirement">>,<<"~> 1.0">>}]]}.""";

        AssertTerm(
            ErlangTermModel.Tuple(
                "requirements",
                ErlangTermModel.List(ErlangTermModel.List(
                    ErlangTermModel.Tuple("name", "jason"),
                    ErlangTermModel.Tuple("app", "jason"),
                    ErlangTermModel.Tuple("optional", ErlangAtom.False),
                    ErlangTermModel.Tuple("requirement", "~> 1.0")))),
            Assert.Single(ErlangTermText.Consult(Text)));
    }

    [Fact]
    public void Consult_CommentsAndBlankLines_AreIgnored()
    {
        const string Text = """
            % the package name
            {<<"name">>,<<"decimal">>}.  % trailing comment

            {<<"version">>,<<"2.3.0">>}.
            """;

        var terms = ErlangTermText.Consult(Text);

        Assert.Equal(2, terms.Count);
        AssertTerm(ErlangTermModel.Tuple("version", "2.3.0"), terms[1]);
    }

    [Fact]
    public void Consult_EmptyOrCommentOnlyDocument_YieldsNoTerms()
    {
        Assert.Empty(ErlangTermText.Consult(string.Empty));
        Assert.Empty(ErlangTermText.Consult("   \n\t\n"));
        Assert.Empty(ErlangTermText.Consult("% nothing but a comment\n"));
    }

    [Fact]
    public void ParseTerm_BinaryForms_MaterializeToStringsOrBytes()
    {
        Assert.Equal("decimal", ErlangTermText.ParseTerm("""<<"decimal">>"""));
        Assert.Equal(string.Empty, ErlangTermText.ParseTerm("<<>>"));

        // A byte-segment binary whose bytes happen to be valid UTF-8 becomes a string, exactly as
        // the external term format decoder treats BINARY_EXT.
        Assert.Equal("abc", ErlangTermText.ParseTerm("<<97,98,99>>"));
        Assert.Equal("ab\u0001", ErlangTermText.ParseTerm("""<<"ab",1>>"""));
        Assert.Equal(new byte[] { 1, 2, 255 }, Assert.IsType<byte[]>(ErlangTermText.ParseTerm("<<1,2,255>>")));

        // With the /utf8 specifier the segment is UTF-8; without it the segment is Latin-1, which
        // is what Erlang itself does — and those bytes are not valid UTF-8.
        Assert.Equal("café", ErlangTermText.ParseTerm("""<<"café"/utf8>>"""));
        Assert.Equal(
            new byte[] { 99, 97, 102, 233 },
            Assert.IsType<byte[]>(ErlangTermText.ParseTerm("""<<"café">>""")));
    }

    [Fact]
    public void ParseTerm_StringEscapes_DecodeToTheirCodePoints()
    {
        var charlist = Assert.IsType<ErlangCharlist>(
            ErlangTermText.ParseTerm(@"""\n\t\r\v\f\b\e\s\d\\\""\0\101\x41\x{1F600}"""));

        Assert.Equal(
            "\n\t\r\v\f\b\u001b \u007f\\\"\0A" + "A" + char.ConvertFromUtf32(0x1F600),
            charlist.Value);
    }

    [Fact]
    public void ParseTerm_ControlEscape_DecodesToTheControlCharacter()
    {
        var charlist = Assert.IsType<ErlangCharlist>(ErlangTermText.ParseTerm(@"""\^a\^A"""));
        Assert.Equal("\u0001\u0001", charlist.Value);
    }

    [Fact]
    public void ParseTerm_Atoms_CoverBareQuotedAndUnicodeForms()
    {
        AssertTerm(new ErlangAtom("hexpm"), ErlangTermText.ParseTerm("hexpm"));
        AssertTerm(new ErlangAtom("mix_2@node"), ErlangTermText.ParseTerm("mix_2@node"));
        AssertTerm(new ErlangAtom("Elixir.Decimal"), ErlangTermText.ParseTerm("'Elixir.Decimal'"));
        AssertTerm(new ErlangAtom("has space"), ErlangTermText.ParseTerm("'has space'"));
        AssertTerm(new ErlangAtom("it's"), ErlangTermText.ParseTerm(@"'it\'s'"));
        AssertTerm(ErlangAtom.True, ErlangTermText.ParseTerm("true"));
        AssertTerm(ErlangAtom.False, ErlangTermText.ParseTerm("false"));
        AssertTerm(ErlangAtom.Nil, ErlangTermText.ParseTerm("nil"));
        AssertTerm(ErlangAtom.Undefined, ErlangTermText.ParseTerm("undefined"));

        // Erlang prints a Unicode atom bare under a UTF-8 device, so the reader accepts that form.
        AssertTerm(new ErlangAtom("él"), ErlangTermText.ParseTerm("él"));
    }

    [Fact]
    public void ParseTerm_Integers_CoverSignBaseAndCharacterForms()
    {
        Assert.Equal(42L, ErlangTermText.ParseTerm("42"));
        Assert.Equal(-42L, ErlangTermText.ParseTerm("-42"));
        Assert.Equal(42L, ErlangTermText.ParseTerm("+42"));
        Assert.Equal(255L, ErlangTermText.ParseTerm("16#FF"));
        Assert.Equal(255L, ErlangTermText.ParseTerm("16#ff"));
        Assert.Equal(-255L, ErlangTermText.ParseTerm("-16#FF"));
        Assert.Equal(10L, ErlangTermText.ParseTerm("2#1010"));
        Assert.Equal(97L, ErlangTermText.ParseTerm("$a"));
        Assert.Equal(10L, ErlangTermText.ParseTerm(@"$\n"));
        Assert.Equal(32L, ErlangTermText.ParseTerm(@"$\s"));
        Assert.Equal(92L, ErlangTermText.ParseTerm(@"$\\"));
        Assert.Equal(BigInteger.Pow(2, 70), ErlangTermText.ParseTerm("1180591620717411303424"));
    }

    [Fact]
    public void ParseTerm_Floats_ParseWithAndWithoutAnExponent()
    {
        Assert.Equal(1.0d, ErlangTermText.ParseTerm("1.0"));
        Assert.Equal(-2.5d, ErlangTermText.ParseTerm("-2.5"));
        Assert.Equal(1.0e-3d, ErlangTermText.ParseTerm("1.0e-3"));
        Assert.Equal(1.0e30d, ErlangTermText.ParseTerm("1.0e30"));
        Assert.Equal(0.001d, ErlangTermText.ParseTerm("0.001"));
    }

    [Fact]
    public void ParseTerm_Maps_ReadKeysAndValuesAsTerms()
    {
        var empty = Assert.IsAssignableFrom<IReadOnlyDictionary<object, object?>>(ErlangTermText.ParseTerm("#{}"));
        Assert.Empty(empty);

        var map = Assert.IsAssignableFrom<IReadOnlyDictionary<object, object?>>(
            ErlangTermText.ParseTerm("""#{<<"a">> => 1, b => [1,2,3], 3 => <<"c">>}"""));

        Assert.Equal(3, map.Count);
        Assert.Equal(1L, map["a"]);
        AssertTerm(ErlangTermModel.List(1L, 2L, 3L), map[new ErlangAtom("b")]);
        Assert.Equal("c", map[3L]);
    }

    [Fact]
    public void ParseTerm_LeadingAndTrailingTriviaAndAnOptionalTerminator_AreAccepted()
    {
        AssertTerm(new ErlangAtom("ok"), ErlangTermText.ParseTerm("  % comment\n ok . \n"));
        AssertTerm(new ErlangAtom("ok"), ErlangTermText.ParseTerm("ok"));
    }

    [Fact]
    public void Print_MatchesTheErlangRenderingForTheShapesHexWrites()
    {
        // Each expected string is what a real Erlang node printed with ~tp for the same term.
        Assert.Equal("""{<<"name">>,<<"decimal">>}""", ErlangTermText.Print(ErlangTermModel.Tuple("name", "decimal")));
        Assert.Equal(
            """{<<"description">>,<<"Décimal \"quoted\" \\ tail"/utf8>>}""",
            ErlangTermText.Print(ErlangTermModel.Tuple("description", "Décimal \"quoted\" \\ tail")));
        Assert.Equal("""<<"line1\nline2\ttab">>""", ErlangTermText.Print("line1\nline2\ttab"));
        Assert.Equal("""
            "a\"b\nc"
            """, ErlangTermText.Print(new ErlangCharlist("a\"b\nc")));
        Assert.Equal("hexpm", ErlangTermText.Print(new ErlangAtom("hexpm")));
        Assert.Equal("'Elixir.Decimal'", ErlangTermText.Print(new ErlangAtom("Elixir.Decimal")));
        Assert.Equal("'has space'", ErlangTermText.Print(new ErlangAtom("has space")));
        Assert.Equal("1.0", ErlangTermText.Print(1.0d));
        Assert.Equal("0.001", ErlangTermText.Print(1.0e-3d));
        Assert.Equal("1.0e30", ErlangTermText.Print(1.0e30d));
        Assert.Equal("-2.5", ErlangTermText.Print(-2.5d));
        Assert.Equal("-42", ErlangTermText.Print(-42L));
        Assert.Equal("[]", ErlangTermText.Print(ErlangTermModel.List()));
        Assert.Equal("<<>>", ErlangTermText.Print(string.Empty));
        Assert.Equal("<<>>", ErlangTermText.Print(Array.Empty<byte>()));
        Assert.Equal("#{}", ErlangTermText.Print(ErlangTermModel.Map()));
        Assert.Equal("<<1,2,255>>", ErlangTermText.Print(new byte[] { 1, 2, 255 }));
        Assert.Equal(
            "{true,false,nil,undefined}",
            ErlangTermText.Print(ErlangTermModel.Tuple(ErlangAtom.True, ErlangAtom.False, ErlangAtom.Nil, ErlangAtom.Undefined)));
        Assert.Equal(
            """{ok,[#{<<"deps">> => [{<<"jason">>,<<"~> 1.0">>}]}],3}""",
            ErlangTermText.Print(ErlangTermModel.Tuple(
                new ErlangAtom("ok"),
                ErlangTermModel.List(ErlangTermModel.Map(("deps", ErlangTermModel.List(ErlangTermModel.Tuple("jason", "~> 1.0"))))),
                3L)));
    }

    [Fact]
    public void Print_MultiKeyMap_OrdersByEncodedKeyBytesRatherThanErlangTermOrder()
    {
        // Erlang's own printer emits #{b => [1,2,3],<<"a">> => 1} because atoms sort before
        // binaries in Erlang term order. This printer orders by encoded key bytes instead, which
        // is stable for the same reason the byte encoder uses that rule; both texts describe the
        // same map, so the reader accepts Erlang's form and returns the same term.
        var term = new Dictionary<object, object?>(ErlangTermModel.TermComparer)
        {
            ["a"] = 1L,
            [new ErlangAtom("b")] = ErlangTermModel.List(1L, 2L, 3L),
        };

        Assert.Equal("""#{<<"a">> => 1,b => [1,2,3]}""", ErlangTermText.Print(term));
        AssertTerm(term, ErlangTermText.ParseTerm("""#{b => [1,2,3],<<"a">> => 1}"""));
    }

    [Fact]
    public void Print_BinaryWithNonPrintableBytes_EscapesRatherThanSwitchingToIntegerSegments()
    {
        // Erlang prints <<97,1,98,127,99>> for this binary. Escaping keeps the readable form and
        // parses back to the same bytes, which is what the round trip needs.
        const string Value = "a\u0001b\u007fc";

        Assert.Equal("""<<"a\x01b\x7Fc">>""", ErlangTermText.Print(Value));
        Assert.Equal(Value, ErlangTermText.ParseTerm(ErlangTermText.Print(Value)));
    }

    [Fact]
    public void Print_NonFiniteFloat_Throws()
    {
        Assert.Throws<ErlangTermException>(() => ErlangTermText.Print(double.NaN));
        Assert.Throws<ErlangTermException>(() => ErlangTermText.Print(double.PositiveInfinity));
    }

    [Fact]
    public void Print_UnsupportedType_Throws()
    {
        Assert.Throws<ErlangTermException>(() => ErlangTermText.Print(new object()));
    }

    [Fact]
    public void ConsultText_JoinsTermsWithATerminatorAndNewline()
    {
        string document = ErlangTermText.ConsultText(new object?[]
        {
            ErlangTermModel.Tuple("name", "decimal"),
            ErlangTermModel.Tuple("version", "2.3.0"),
        });

        Assert.Equal("{<<\"name\">>,<<\"decimal\">>}.\n{<<\"version\">>,<<\"2.3.0\">>}.\n", document);
    }

    [Fact]
    public void ConsultText_ThenConsult_RoundTripsEveryTermInTheMetadataConfig()
    {
        var original = ErlangTermText.Consult(DecimalMetadataConfig);
        var reparsed = ErlangTermText.Consult(ErlangTermText.ConsultText(original));

        Assert.Equal(original.Count, reparsed.Count);
        for (int i = 0; i < original.Count; i++)
        {
            AssertTerm(original[i], reparsed[i]);
        }
    }

    [Fact]
    public void ConsultText_ThenConsult_RoundTripsEveryTermShape()
    {
        object?[] terms = new object?[]
        {
            ErlangTermModel.Tuple("name", "decimal"),
            ErlangTermModel.List(1L, 2L, 3L),
            ErlangTermModel.Map(("deps", ErlangTermModel.List(ErlangTermModel.Tuple("jason", "~> 1.0")))),
            new ErlangCharlist("a charlist with \"quotes\" and a \\ backslash"),
            new ErlangAtom("Weird Atom"),
            new byte[] { 0, 128, 255 },
            "Décimal — unicode",
            BigInteger.Pow(2, 90),
            -7L,
            2.5d,
            1.0e30d,
            ErlangTermModel.List(),
        };

        var reparsed = ErlangTermText.Consult(ErlangTermText.ConsultText(terms));

        Assert.Equal(terms.Length, reparsed.Count);
        for (int i = 0; i < terms.Length; i++)
        {
            AssertTerm(terms[i], reparsed[i]);
        }
    }

    [Fact]
    public void Print_ThenParse_AgreesWithTheExternalTermFormatCodec()
    {
        var term = ErlangTermModel.Tuple(
            "requirements",
            ErlangTermModel.List(ErlangTermModel.Tuple(
                "jason",
                ErlangTermModel.List(
                    ErlangTermModel.Tuple("app", "jason"),
                    ErlangTermModel.Tuple("optional", ErlangAtom.False),
                    ErlangTermModel.Tuple("requirement", "~> 1.0")))));

        AssertTerm(
            ErlangTermFormat.Decode(ErlangTermFormat.Encode(term)),
            ErlangTermText.ParseTerm(ErlangTermText.Print(term)));
    }

    [Fact]
    public void Consult_UnterminatedBinary_Throws()
    {
        AssertPositionedError("""<<"decimal">""");
        AssertPositionedError("""<<"unterminated""");
        AssertPositionedError("<<1,2");
    }

    [Fact]
    public void Consult_UnterminatedStringOrAtom_Throws()
    {
        AssertPositionedError("""
            "no closing quote.
            """);
        AssertPositionedError("'no closing quote.");
    }

    [Fact]
    public void Consult_UnknownEscape_Throws()
    {
        // Erlang's scanner passes an unrecognised escape through as the bare character; refusing
        // it is deliberate, because a metadata file that carries one is not the file its author
        // believed they wrote.
        var thrown = Assert.Throws<ErlangTermException>(() => ErlangTermText.ParseTerm(@"<<""a\q"">>"));
        Assert.Contains("Unknown escape", thrown.Message, StringComparison.Ordinal);
        Assert.Contains("line 1", thrown.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Consult_ImproperList_Throws()
    {
        var thrown = Assert.Throws<ErlangTermException>(() => ErlangTermText.ParseTerm("[a|b]"));
        Assert.Contains("Improper", thrown.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Consult_DuplicateMapKey_Throws()
    {
        var thrown = Assert.Throws<ErlangTermException>(
            () => ErlangTermText.ParseTerm("""#{<<"a">> => 1, <<"a">> => 2}"""));
        Assert.Contains("Duplicate map key", thrown.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Consult_MapUpdateSyntax_Throws()
    {
        Assert.Throws<ErlangTermException>(() => ErlangTermText.ParseTerm("""#{<<"a">> := 1}"""));
    }

    [Fact]
    public void Consult_BinarySizeSpecifier_Throws()
    {
        Assert.Throws<ErlangTermException>(() => ErlangTermText.ParseTerm("<<1:8>>"));
    }

    [Fact]
    public void Consult_UnsupportedSegmentSpecifier_Throws()
    {
        Assert.Throws<ErlangTermException>(() => ErlangTermText.ParseTerm("""<<"a"/utf16>>"""));
    }

    [Fact]
    public void Consult_BinarySegmentOutOfByteRange_Throws()
    {
        Assert.Throws<ErlangTermException>(() => ErlangTermText.ParseTerm("<<256>>"));
        Assert.Throws<ErlangTermException>(() => ErlangTermText.ParseTerm("<<-1>>"));

        // The same value is fine once the segment says it is UTF-8.
        Assert.Equal("Ā", ErlangTermText.ParseTerm("<<256/utf8>>"));
    }

    [Fact]
    public void Consult_MissingOrMisplacedTerminator_Throws()
    {
        AssertPositionedError("""{<<"name">>,<<"decimal">>}""");
        AssertPositionedError("""{<<"name">>,<<"decimal">>}.{<<"a">>,1}.""");
    }

    [Fact]
    public void ParseTerm_TrailingContentAfterTheTerm_Throws()
    {
        Assert.Throws<ErlangTermException>(() => ErlangTermText.ParseTerm("ok ok"));
        Assert.Throws<ErlangTermException>(() => ErlangTermText.ParseTerm("ok. ok."));
        Assert.Throws<ErlangTermException>(() => ErlangTermText.ParseTerm(string.Empty));
    }

    [Fact]
    public void ParseTerm_MalformedNumbers_Throw()
    {
        Assert.Throws<ErlangTermException>(() => ErlangTermText.ParseTerm("1e3"));
        Assert.Throws<ErlangTermException>(() => ErlangTermText.ParseTerm("99#12"));
        Assert.Throws<ErlangTermException>(() => ErlangTermText.ParseTerm("16#"));
        Assert.Throws<ErlangTermException>(() => ErlangTermText.ParseTerm("2#12"));
        Assert.Throws<ErlangTermException>(() => ErlangTermText.ParseTerm("1.0e"));
        Assert.Throws<ErlangTermException>(() => ErlangTermText.ParseTerm("-"));
    }

    [Fact]
    public void ParseTerm_UnexpectedCharacter_Throws()
    {
        var thrown = Assert.Throws<ErlangTermException>(() => ErlangTermText.ParseTerm("Var"));
        Assert.Contains("Unexpected character", thrown.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Consult_DepthBomb_Throws()
    {
        string text = new string('[', 70) + new string(']', 70) + ".";
        Assert.Throws<ErlangTermException>(() => ErlangTermText.Consult(text));
    }

    [Fact]
    public void Consult_InputOverTheSizeCap_ThrowsBeforeParsing()
    {
        string oversized = new(' ', ErlangTermText.MaxInputChars + 1);

        var thrown = Assert.Throws<ErlangTermException>(() => ErlangTermText.Consult(oversized));
        Assert.Contains("exceeds", thrown.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Consult_ErrorMessages_CarryTheLineAndColumn()
    {
        var thrown = Assert.Throws<ErlangTermException>(() => ErlangTermText.Consult("ok.\nok.\n[a|b].\n"));
        Assert.Contains("line 3", thrown.Message, StringComparison.Ordinal);
        Assert.Contains("column 3", thrown.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Consult_AndTheByteCodecAgreeOnTheSameMetadata()
    {
        // The two codecs are separate readers of the same term model, so a metadata document read
        // from text must encode to bytes another Erlang node would read back as that document.
        var terms = ErlangTermText.Consult(DecimalMetadataConfig);
        foreach (object? term in terms)
        {
            AssertTerm(term, ErlangTermFormat.Decode(ErlangTermFormat.Encode(term)));
        }
    }

    [Fact]
    public void Consult_LargeButLegalDocument_IsAccepted()
    {
        var builder = new StringBuilder();
        for (int i = 0; i < 2000; i++)
        {
            builder.Append("{<<\"file\">>,<<\"lib/decimal/part_").Append(i).Append(".ex\">>}.\n");
        }

        Assert.Equal(2000, ErlangTermText.Consult(builder.ToString()).Count);
    }

    private static void AssertPositionedError(string text)
    {
        var thrown = Assert.Throws<ErlangTermException>(() => ErlangTermText.Consult(text));
        Assert.Contains("line ", thrown.Message, StringComparison.Ordinal);
    }

    private static void AssertTerm(object? expected, object? actual)
    {
        if (!ErlangTermModel.DeepEquals(expected, actual))
        {
            Assert.Fail($"Expected {ErlangTermText.Print(expected)} but got {ErlangTermText.Print(actual)}.");
        }
    }
}
