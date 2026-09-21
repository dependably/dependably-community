using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Unicode;

namespace Dependably.Protocol.Hex;

/// <summary>
/// Reader and writer for Erlang terms in their textual form — the <c>file:consult/1</c> format
/// a Hex package tarball carries in <c>metadata.config</c>: a sequence of terms, each ending in
/// a <c>.</c> followed by whitespace or the end of the file.
/// </summary>
/// <remarks>
/// <para>
/// The grammar covered is the one hex_core's writer can emit: binaries (<c>&lt;&lt;"…"&gt;&gt;</c>,
/// <c>&lt;&lt;"…"/utf8&gt;&gt;</c>, and the byte-segment form <c>&lt;&lt;1,2,3&gt;&gt;</c>),
/// charlists (<c>"…"</c>), bare and quoted atoms, integers (decimal, <c>Base#Digits</c>, and the
/// <c>$c</c> character literal), floats, tuples, proper lists, maps, and <c>%</c> comments.
/// Improper lists, binary size specifiers, and map-update syntax are refused with a positioned
/// error rather than silently reinterpreted.
/// </para>
/// <para>
/// A binary literal is materialized to the same shapes the external term format codec produces:
/// a <see cref="string"/> when its bytes are valid UTF-8 and a <see cref="byte"/>[] when they
/// are not. A segment without a <c>/utf8</c> specifier is Latin-1, as it is in Erlang, so
/// <c>&lt;&lt;"café"&gt;&gt;</c> yields the four Latin-1 bytes and therefore a
/// <see cref="byte"/>[], while <c>&lt;&lt;"café"/utf8&gt;&gt;</c> yields the string.
/// </para>
/// <para>
/// <see cref="Print"/> is the inverse and emits a single line per term. It differs from Erlang's
/// own pretty printer in three deliberate ways: it never wraps a long term across lines (the
/// reader treats whitespace as insignificant, so both forms read back identically), it escapes
/// non-printable characters inside a string binary rather than switching that binary to the
/// integer-segment form, and it orders map entries by their encoded key bytes so the output is
/// stable. Float literals are the shortest round-trip form with a decimal point forced in, which
/// need not match Erlang's own choice of exponent notation character for character.
/// </para>
/// </remarks>
public static class ErlangTermText
{
    /// <summary>
    /// The largest document <see cref="Consult"/> will parse, matching the cap hex_core places
    /// on package metadata.
    /// </summary>
    public const int MaxInputChars = 1024 * 1024;

    /// <summary>The deepest term nesting either direction of the codec will follow.</summary>
    public const int MaxDepth = 64;

    private const int MaxCodePoint = 0x10FFFF;

    private static readonly char[] ExponentMarkers = new char[] { 'e', 'E' };

    private static bool IsSurrogateCodePoint(int codePoint) => codePoint is >= 0xD800 and <= 0xDFFF;

    /// <summary>
    /// Parses a whole <c>file:consult/1</c> document into its terms, in file order.
    /// </summary>
    public static IReadOnlyList<object?> Consult(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        GuardSize(text);
        var parser = new Parser(text);
        return parser.ParseDocument();
    }

    /// <summary>
    /// Parses exactly one term, with an optional trailing <c>.</c>. Anything after it is an error.
    /// </summary>
    public static object? ParseTerm(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        GuardSize(text);
        var parser = new Parser(text);
        return parser.ParseSingle();
    }

    /// <summary>Renders one term as a single line of Erlang source.</summary>
    public static string Print(object? term)
    {
        var builder = new StringBuilder();
        WriteTerm(builder, term, 0);
        return builder.ToString();
    }

    /// <summary>
    /// Renders a sequence of terms as a <c>file:consult/1</c> document: each term on its own
    /// line, terminated by <c>.</c> and a newline.
    /// </summary>
    public static string ConsultText(IEnumerable<object?> terms)
    {
        ArgumentNullException.ThrowIfNull(terms);
        var builder = new StringBuilder();
        foreach (object? term in terms)
        {
            WriteTerm(builder, term, 0);
            builder.Append(".\n");
        }

        return builder.ToString();
    }

    private static void GuardSize(string text)
    {
        if (text.Length > MaxInputChars)
        {
            throw new ErlangTermException(
                $"Textual term input of {text.Length} characters exceeds the {MaxInputChars} character limit.");
        }
    }

    private static void WriteTerm(StringBuilder builder, object? term, int depth)
    {
        if (depth > MaxDepth)
        {
            throw new ErlangTermException($"Term nesting exceeds the maximum depth of {MaxDepth}.");
        }

        switch (term)
        {
            case null:
                builder.Append(ErlangAtom.Nil.Name);
                return;
            case bool flag:
                builder.Append(flag ? ErlangAtom.True.Name : ErlangAtom.False.Name);
                return;
            case ErlangAtom atom:
                WriteAtom(builder, atom.Name);
                return;
            case string text:
                WriteBinaryFromText(builder, text);
                return;
            case byte[] bytes:
                WriteBinaryFromBytes(builder, bytes);
                return;
            case ErlangCharlist charlist:
                WriteCharlist(builder, charlist.Value);
                return;
            case ErlangTuple tuple:
                WriteSequence(builder, tuple.Items, '{', '}', depth);
                return;
            case float single:
                WriteFloat(builder, single);
                return;
            case double value:
                WriteFloat(builder, value);
                return;
            default:
                WriteCompoundTerm(builder, term, depth);
                return;
        }
    }

    private static void WriteCompoundTerm(StringBuilder builder, object term, int depth)
    {
        if (ErlangTermModel.TryAsInteger(term, out var integer))
        {
            builder.Append(integer.ToString(CultureInfo.InvariantCulture));
            return;
        }

        if (ErlangTermFormat.TryGetMapEntries(term, out var entries))
        {
            WriteMap(builder, entries, depth);
            return;
        }

        if (term is IEnumerable<object?> sequence)
        {
            WriteSequence(builder, sequence as IReadOnlyList<object?> ?? sequence.ToList(), '[', ']', depth);
            return;
        }

        if (term is System.Collections.IEnumerable untyped)
        {
            WriteSequence(builder, untyped.Cast<object?>().ToList(), '[', ']', depth);
            return;
        }

        throw new ErlangTermException($"No textual rendering for values of type {term.GetType().FullName}.");
    }

    private static void WriteSequence(StringBuilder builder, IReadOnlyList<object?> items, char open, char close, int depth)
    {
        builder.Append(open);
        for (int i = 0; i < items.Count; i++)
        {
            if (i > 0)
            {
                builder.Append(',');
            }

            WriteTerm(builder, items[i], depth + 1);
        }

        builder.Append(close);
    }

    private static void WriteMap(StringBuilder builder, IEnumerable<KeyValuePair<object, object?>> entries, int depth)
    {
        // Entries are ordered by their encoded key bytes — the same rule the external term
        // format encoder uses — so a map prints the same way every time.
        var ordered = entries.ToList();
        ordered.Sort(static (left, right) =>
            ErlangTermFormat.Encode(left.Key).AsSpan().SequenceCompareTo(ErlangTermFormat.Encode(right.Key)));

        builder.Append("#{");
        for (int i = 0; i < ordered.Count; i++)
        {
            if (i > 0)
            {
                builder.Append(',');
            }

            WriteTerm(builder, ordered[i].Key, depth + 1);
            builder.Append(" => ");
            WriteTerm(builder, ordered[i].Value, depth + 1);
        }

        builder.Append('}');
    }

    private static void WriteAtom(StringBuilder builder, string name)
    {
        if (IsBareAtom(name))
        {
            builder.Append(name);
            return;
        }

        builder.Append('\'');
        AppendEscaped(builder, name, '\'');
        builder.Append('\'');
    }

    private static void WriteCharlist(StringBuilder builder, string value)
    {
        builder.Append('"');
        AppendEscaped(builder, value, '"');
        builder.Append('"');
    }

    private static void WriteBinaryFromText(StringBuilder builder, string text)
    {
        if (text.Length == 0)
        {
            builder.Append("<<>>");
            return;
        }

        builder.Append("<<\"");
        bool nonAscii = AppendEscaped(builder, text, '"');
        builder.Append('"');
        if (nonAscii)
        {
            // Without the specifier Erlang reads the segment as Latin-1, which would change the
            // bytes for every character above U+007F.
            builder.Append("/utf8");
        }

        builder.Append(">>");
    }

    private static void WriteBinaryFromBytes(StringBuilder builder, byte[] bytes)
    {
        if (bytes.Length == 0)
        {
            builder.Append("<<>>");
            return;
        }

        builder.Append("<<");
        for (int i = 0; i < bytes.Length; i++)
        {
            if (i > 0)
            {
                builder.Append(',');
            }

            builder.Append(bytes[i].ToString(CultureInfo.InvariantCulture));
        }

        builder.Append(">>");
    }

    private static void WriteFloat(StringBuilder builder, double value)
    {
        if (double.IsNaN(value) || double.IsInfinity(value))
        {
            throw new ErlangTermException($"Erlang has no float literal for {value}.");
        }

        string text = value.ToString("R", CultureInfo.InvariantCulture);
        int exponentIndex = text.IndexOfAny(ExponentMarkers);
        if (exponentIndex >= 0)
        {
            string mantissa = text[..exponentIndex];
            string exponent = text[(exponentIndex + 1)..];
            if (!mantissa.Contains('.', StringComparison.Ordinal))
            {
                mantissa += ".0";
            }

            bool negativeExponent = exponent.StartsWith('-');
            exponent = exponent.TrimStart('+', '-').TrimStart('0');
            if (exponent.Length == 0)
            {
                exponent = "0";
            }

            builder.Append(mantissa).Append('e');
            if (negativeExponent)
            {
                builder.Append('-');
            }

            builder.Append(exponent);
            return;
        }

        builder.Append(text);
        if (!text.Contains('.', StringComparison.Ordinal))
        {
            // Erlang has no literal for a float without a decimal point.
            builder.Append(".0");
        }
    }

    private static bool AppendEscaped(StringBuilder builder, string text, char quote)
    {
        bool nonAscii = false;
        foreach (char c in text)
        {
            switch (c)
            {
                case '\\':
                    builder.Append("\\\\");
                    break;
                case '\n':
                    builder.Append("\\n");
                    break;
                case '\r':
                    builder.Append("\\r");
                    break;
                case '\t':
                    builder.Append("\\t");
                    break;
                case '\v':
                    builder.Append("\\v");
                    break;
                case '\f':
                    builder.Append("\\f");
                    break;
                case '\b':
                    builder.Append("\\b");
                    break;
                case '\u001b':
                    builder.Append("\\e");
                    break;
                default:
                    if (c == quote)
                    {
                        builder.Append('\\').Append(c);
                    }
                    else if (c is < ' ' or '\u007f')
                    {
                        builder.Append(CultureInfo.InvariantCulture, $"\\x{(int)c:X2}");
                    }
                    else
                    {
                        nonAscii |= c > '\u007f';
                        builder.Append(c);
                    }

                    break;
            }
        }

        return nonAscii;
    }

    private static bool IsBareAtom(string name)
    {
        if (name.Length == 0 || name[0] is < 'a' or > 'z')
        {
            return false;
        }

        foreach (char c in name)
        {
            bool allowed = c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '_' or '@';
            if (!allowed)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// A hand-written tokenizer and recursive-descent parser. It is deliberately not a regex:
    /// escapes, comments, and the <c>.</c> terminator all depend on context that a pattern
    /// cannot carry, and every rejection has to name a position.
    /// </summary>
    private sealed class Parser
    {
        private readonly string _text;
        private int _position;

        public Parser(string text)
        {
            _text = text;
            _position = 0;
        }

        private bool AtEnd => _position >= _text.Length;

        private char Current => _text[_position];

        public IReadOnlyList<object?> ParseDocument()
        {
            var terms = new List<object?>();
            SkipTrivia();
            while (!AtEnd)
            {
                terms.Add(ParseTermInternal(0));
                ExpectTerminator();
                SkipTrivia();
            }

            return terms;
        }

        public object? ParseSingle()
        {
            SkipTrivia();
            if (AtEnd)
            {
                throw Error("Expected a term but found the end of the input");
            }

            object? term = ParseTermInternal(0);
            SkipTrivia();
            if (!AtEnd && Current == '.')
            {
                ExpectTerminator();
                SkipTrivia();
            }

            return !AtEnd ? throw Error($"Unexpected '{Current}' after the term") : term;
        }

        private void SkipTrivia()
        {
            while (!AtEnd)
            {
                if (char.IsWhiteSpace(Current))
                {
                    _position++;
                    continue;
                }

                if (Current == '%')
                {
                    while (!AtEnd && Current != '\n')
                    {
                        _position++;
                    }

                    continue;
                }

                return;
            }
        }

        private void ExpectTerminator()
        {
            SkipTrivia();
            if (AtEnd)
            {
                throw Error("Expected '.' to terminate the term but found the end of the input");
            }

            if (Current != '.')
            {
                throw Error($"Expected '.' to terminate the term but found '{Current}'");
            }

            _position++;
            if (!AtEnd && !char.IsWhiteSpace(Current) && Current != '%')
            {
                throw Error("A term terminator is a '.' followed by whitespace, a comment, or the end of the input");
            }
        }

        private object? ParseTermInternal(int depth)
        {
            if (depth > MaxDepth)
            {
                throw Error($"Term nesting exceeds the maximum depth of {MaxDepth}");
            }

            SkipTrivia();
            if (AtEnd)
            {
                throw Error("Expected a term but found the end of the input");
            }

            char c = Current;
            switch (c)
            {
                case '{':
                    return new ErlangTuple(ParseSequence(depth, '{', '}'));
                case '[':
                    return ParseSequence(depth, '[', ']');
                case '#':
                    return ParseMap(depth);
                case '<':
                    return ParseBinary(depth);
                case '"':
                    return new ErlangCharlist(ParseQuoted('"'));
                case '\'':
                    return new ErlangAtom(ParseQuoted('\''));
                case '$':
                    return ParseCharacterLiteral();
                default:
                    if (c is '-' or '+' || char.IsAsciiDigit(c))
                    {
                        return ParseNumber();
                    }

                    if (IsAtomStart(c))
                    {
                        return new ErlangAtom(ParseBareAtom());
                    }

                    throw Error($"Unexpected character '{c}'");
            }
        }

        private IReadOnlyList<object?> ParseSequence(int depth, char open, char close)
        {
            Advance(open);
            var items = new List<object?>();
            SkipTrivia();
            if (!AtEnd && Current == close)
            {
                _position++;
                return items;
            }

            while (true)
            {
                items.Add(ParseTermInternal(depth + 1));
                SkipTrivia();
                if (AtEnd)
                {
                    throw Error($"Expected '{close}' but found the end of the input");
                }

                if (Current == ',')
                {
                    _position++;
                    continue;
                }

                if (Current == close)
                {
                    _position++;
                    return items;
                }

                if (Current == '|')
                {
                    throw Error("Improper lists are not supported");
                }

                throw Error($"Expected ',' or '{close}' but found '{Current}'");
            }
        }

        [SuppressMessage("Major Code Smell", "S3776:Cognitive Complexity of methods should not be too high",
            Justification = "A hand-written recursive-descent scanner: the branches are the grammar's own alternatives over a shared "
                + "_position cursor, and every extraction would either thread that cursor through a helper or split one "
                + "production across two methods.")]
        private IReadOnlyDictionary<object, object?> ParseMap(int depth)
        {
            Advance('#');
            SkipTrivia();
            if (AtEnd || Current != '{')
            {
                throw Error("Expected '{' after '#' to open a map");
            }

            Advance('{');
            var map = new Dictionary<object, object?>(ErlangTermModel.TermComparer);
            SkipTrivia();
            if (!AtEnd && Current == '}')
            {
                _position++;
                return map;
            }

            while (true)
            {
                int keyPosition = _position;
                object? key = ParseTermInternal(depth + 1);
                SkipTrivia();
                if (!AtEnd && Current == ':')
                {
                    throw Error("Map update syntax ':=' is not supported in a literal term");
                }

                if (AtEnd || Current != '=' || _position + 1 >= _text.Length || _text[_position + 1] != '>')
                {
                    throw Error("Expected '=>' between a map key and its value");
                }

                _position += 2;
                object? value = ParseTermInternal(depth + 1);
                if (key is null)
                {
                    throw ErrorAt(keyPosition, "A map key must be a term");
                }

                if (!map.TryAdd(key, value))
                {
                    throw ErrorAt(keyPosition, "Duplicate map key");
                }

                SkipTrivia();
                if (AtEnd)
                {
                    throw Error("Expected '}' but found the end of the input");
                }

                if (Current == ',')
                {
                    _position++;
                    continue;
                }

                if (Current == '}')
                {
                    _position++;
                    return map;
                }

                throw Error($"Expected ',' or '}}' but found '{Current}'");
            }
        }

        private object ParseBinary(int depth)
        {
            if (depth > MaxDepth)
            {
                throw Error($"Term nesting exceeds the maximum depth of {MaxDepth}");
            }

            Advance('<');
            Advance('<');
            var bytes = new List<byte>();
            SkipTrivia();
            if (AtEndOfBinary())
            {
                _position += 2;
                return Materialize(bytes);
            }

            while (true)
            {
                ParseBinarySegment(bytes);
                SkipTrivia();
                if (AtEndOfBinary())
                {
                    _position += 2;
                    return Materialize(bytes);
                }

                if (AtEnd)
                {
                    throw Error("Expected '>>' but found the end of the input");
                }

                if (Current == ',')
                {
                    _position++;
                    SkipTrivia();
                    continue;
                }

                if (Current == ':')
                {
                    throw Error("Binary size specifiers are not supported");
                }

                throw Error($"Expected ',' or '>>' but found '{Current}'");
            }
        }

        private bool AtEndOfBinary() =>
            _position + 1 < _text.Length && _text[_position] == '>' && _text[_position + 1] == '>';

        [SuppressMessage("Major Code Smell", "S3776:Cognitive Complexity of methods should not be too high",
            Justification = "A hand-written recursive-descent scanner: the branches are the grammar's own alternatives over a shared "
                + "_position cursor, and every extraction would either thread that cursor through a helper or split one "
                + "production across two methods.")]
        private void ParseBinarySegment(List<byte> bytes)
        {
            if (AtEnd)
            {
                throw Error("Expected a binary segment but found the end of the input");
            }

            var codePoints = new List<int>();
            int segmentPosition = _position;
            if (Current == '"')
            {
                string text = ParseQuoted('"');
                for (int i = 0; i < text.Length; i++)
                {
                    if (char.IsHighSurrogate(text[i]) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
                    {
                        codePoints.Add(char.ConvertToUtf32(text[i], text[i + 1]));
                        i++;
                        continue;
                    }

                    codePoints.Add(text[i]);
                }
            }
            else
            {
                object value = ParseTermInternal(MaxDepth) ?? throw Error("Expected a binary segment");
                if (value is not long integer || integer is < 0 or > MaxCodePoint)
                {
                    throw ErrorAt(
                        segmentPosition,
                        "A binary segment is a quoted string or a non-negative integer code point");
                }

                codePoints.Add((int)integer);
            }

            bool utf8 = ParseSegmentSpecifier();
            foreach (int codePoint in codePoints)
            {
                if (utf8)
                {
                    if (codePoint > MaxCodePoint || IsSurrogateCodePoint(codePoint))
                    {
                        throw ErrorAt(segmentPosition, $"Code point {codePoint} cannot be encoded as UTF-8");
                    }

                    bytes.AddRange(Encoding.UTF8.GetBytes(char.ConvertFromUtf32(codePoint)));
                    continue;
                }

                if (codePoint > byte.MaxValue)
                {
                    throw ErrorAt(
                        segmentPosition,
                        $"Code point {codePoint} does not fit a byte; the segment needs a '/utf8' specifier");
                }

                bytes.Add((byte)codePoint);
            }
        }

        private bool ParseSegmentSpecifier()
        {
            if (AtEnd || Current != '/')
            {
                return false;
            }

            _position++;
            int start = _position;
            while (!AtEnd && char.IsAsciiLetterOrDigit(Current))
            {
                _position++;
            }

            string specifier = _text[start.._position];
            return specifier switch
            {
                "utf8" => true,
                "" => throw ErrorAt(start, "Expected a binary segment type specifier after '/'"),
                _ => throw ErrorAt(start, $"Binary segment type specifier '{specifier}' is not supported"),
            };
        }

        private static object Materialize(List<byte> bytes)
        {
            byte[] materialized = bytes.ToArray();
            return Utf8.IsValid(materialized) ? Encoding.UTF8.GetString(materialized) : materialized;
        }

        private string ParseQuoted(char quote)
        {
            Advance(quote);
            var builder = new StringBuilder();
            while (true)
            {
                if (AtEnd)
                {
                    throw Error($"Unterminated {(quote == '"' ? "string" : "quoted atom")}");
                }

                char c = Current;
                if (c == quote)
                {
                    _position++;
                    return builder.ToString();
                }

                if (c == '\\')
                {
                    int escapePosition = _position;
                    _position++;
                    int codePoint = ParseEscape();
                    if (codePoint > MaxCodePoint || IsSurrogateCodePoint(codePoint))
                    {
                        throw ErrorAt(escapePosition, $"Code point {codePoint} is not a character");
                    }

                    builder.Append(char.ConvertFromUtf32(codePoint));
                    continue;
                }

                builder.Append(c);
                _position++;
            }
        }

        private int ParseEscape()
        {
            if (AtEnd)
            {
                throw Error("Unterminated escape sequence");
            }

            int escapePosition = _position;
            char c = Current;
            _position++;
            switch (c)
            {
                case 'n':
                    return '\n';
                case 't':
                    return '\t';
                case 'r':
                    return '\r';
                case 'v':
                    return '\v';
                case 'b':
                    return '\b';
                case 'f':
                    return '\f';
                case 'e':
                    return 0x1b;
                case 's':
                    return ' ';
                case 'd':
                    return 0x7f;
                case '\\':
                case '"':
                case '\'':
                    return c;
                case 'x':
                    return ParseHexEscape(escapePosition);
                case '^':
                    {
                        if (AtEnd)
                        {
                            throw ErrorAt(escapePosition, "Unterminated control escape sequence");
                        }

                        char control = Current;
                        _position++;
                        return char.ToUpperInvariant(control) % 32;
                    }

                default:
                    if (c is >= '0' and <= '7')
                    {
                        return ParseOctalEscape(c);
                    }

                    throw ErrorAt(escapePosition, $"Unknown escape sequence '\\{c}'");
            }
        }

        private int ParseOctalEscape(char first)
        {
            int value = first - '0';
            for (int i = 0; i < 2 && !AtEnd && Current is >= '0' and <= '7'; i++)
            {
                value = (value * 8) + (Current - '0');
                _position++;
            }

            return value;
        }

        private int ParseHexEscape(int escapePosition)
        {
            if (AtEnd)
            {
                throw ErrorAt(escapePosition, "Unterminated '\\x' escape sequence");
            }

            if (Current == '{')
            {
                _position++;
                int start = _position;
                while (!AtEnd && Current != '}')
                {
                    _position++;
                }

                if (AtEnd)
                {
                    throw ErrorAt(escapePosition, "Unterminated '\\x{' escape sequence");
                }

                string digits = _text[start.._position];
                _position++;
                return digits.Length == 0 || digits.Length > 6 || !TryParseHex(digits, out int braced) || braced > MaxCodePoint
                    ? throw ErrorAt(escapePosition, $"Invalid '\\x{{{digits}}}' escape sequence")
                    : braced;
            }

            if (_position + 1 >= _text.Length)
            {
                throw ErrorAt(escapePosition, "An '\\x' escape sequence needs two hexadecimal digits");
            }

            string pair = _text.Substring(_position, 2);
            if (!TryParseHex(pair, out int value))
            {
                throw ErrorAt(escapePosition, $"Invalid '\\x{pair}' escape sequence");
            }

            _position += 2;
            return value;
        }

        private static bool TryParseHex(string digits, out int value) =>
            int.TryParse(digits, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);

        private object ParseCharacterLiteral()
        {
            Advance('$');
            if (AtEnd)
            {
                throw Error("Expected a character after '$'");
            }

            if (Current == '\\')
            {
                _position++;
                return (long)ParseEscape();
            }

            char c = Current;
            _position++;
            if (char.IsHighSurrogate(c) && !AtEnd && char.IsLowSurrogate(Current))
            {
                char low = Current;
                _position++;
                return (long)char.ConvertToUtf32(c, low);
            }

            return (long)c;
        }

        private string ParseBareAtom()
        {
            int start = _position;
            _position++;
            while (!AtEnd && IsAtomChar(Current))
            {
                _position++;
            }

            return _text[start.._position];
        }

        private object ParseNumber()
        {
            int start = _position;
            if (Current is '-' or '+')
            {
                _position++;
            }

            if (AtEnd || !char.IsAsciiDigit(Current))
            {
                throw ErrorAt(start, "Expected a digit after the sign");
            }

            int digitsStart = _position;
            while (!AtEnd && char.IsAsciiDigit(Current))
            {
                _position++;
            }

            bool negative = _text[start] == '-';
            string digits = _text[digitsStart.._position];

            RejectBarePointlessExponent(start);
            return !AtEnd && Current == '#'
                ? ParseBasedInteger(start, digits, negative)
                : AtFractionalPart()
                    ? ParseFloat(start)
                    : Narrow(SignedValue(BigInteger.Parse(digits, CultureInfo.InvariantCulture), negative));
        }

        private void RejectBarePointlessExponent(int start)
        {
            if (!AtEnd && Current is 'e' or 'E')
            {
                throw ErrorAt(start, "An Erlang float literal needs a decimal point before its exponent");
            }
        }

        private static BigInteger SignedValue(BigInteger magnitude, bool negative) => negative ? -magnitude : magnitude;

        private bool AtFractionalPart() =>
            !AtEnd && Current == '.' && _position + 1 < _text.Length && char.IsAsciiDigit(_text[_position + 1]);

        private object ParseBasedInteger(int start, string digits, bool negative)
        {
            if (!int.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out int radix) || radix is < 2 or > 36)
            {
                throw ErrorAt(start, $"Integer base '{digits}' is outside the supported range of 2 to 36");
            }

            _position++;
            int valueStart = _position;
            var value = BigInteger.Zero;
            while (!AtEnd && char.IsAsciiLetterOrDigit(Current))
            {
                int digit = char.IsAsciiDigit(Current) ? Current - '0' : char.ToLowerInvariant(Current) - 'a' + 10;
                if (digit >= radix)
                {
                    throw ErrorAt(_position, $"Digit '{Current}' is not valid in base {radix}");
                }

                value = (value * radix) + digit;
                _position++;
            }

            return _position == valueStart
                ? throw ErrorAt(start, $"Expected at least one base {radix} digit after '#'")
                : Narrow(negative ? -value : value);
        }

        [SuppressMessage("Major Code Smell", "S3776:Cognitive Complexity of methods should not be too high",
            Justification = "A hand-written recursive-descent scanner: the branches are the grammar's own alternatives over a shared "
                + "_position cursor, and every extraction would either thread that cursor through a helper or split one "
                + "production across two methods.")]
        private object ParseFloat(int start)
        {
            _position++;
            while (!AtEnd && char.IsAsciiDigit(Current))
            {
                _position++;
            }

            if (!AtEnd && Current is 'e' or 'E')
            {
                int exponentStart = _position;
                _position++;
                if (!AtEnd && Current is '-' or '+')
                {
                    _position++;
                }

                if (AtEnd || !char.IsAsciiDigit(Current))
                {
                    throw ErrorAt(exponentStart, "Expected at least one digit in the float exponent");
                }

                while (!AtEnd && char.IsAsciiDigit(Current))
                {
                    _position++;
                }
            }

            string literal = _text[start.._position];
            return !double.TryParse(literal, NumberStyles.Float, CultureInfo.InvariantCulture, out double value)
                || double.IsNaN(value)
                || double.IsInfinity(value)
                ? throw ErrorAt(start, $"Float literal '{literal}' is not a finite double")
                : (object)value;
        }

        private static object Narrow(BigInteger value) => ErlangTermModel.NarrowInteger(value);

        private void Advance(char expected)
        {
            if (AtEnd || Current != expected)
            {
                throw Error($"Expected '{expected}'");
            }

            _position++;
        }

        private static bool IsAtomStart(char c) => char.IsLower(c);

        private static bool IsAtomChar(char c) => char.IsLetterOrDigit(c) || c is '_' or '@';

        private ErlangTermException Error(string message) => ErrorAt(_position, message);

        private ErlangTermException ErrorAt(int position, string message)
        {
            int line = 1;
            int column = 1;
            for (int i = 0; i < position && i < _text.Length; i++)
            {
                if (_text[i] == '\n')
                {
                    line++;
                    column = 1;
                    continue;
                }

                column++;
            }

            return new ErlangTermException($"{message} at line {line}, column {column}.");
        }
    }
}
