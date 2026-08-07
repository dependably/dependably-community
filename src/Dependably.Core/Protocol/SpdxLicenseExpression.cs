namespace Dependably.Protocol;

/// <summary>
/// Parses an SPDX license expression (SPDX spec annex D grammar: <c>AND</c>/<c>OR</c>/<c>WITH</c>,
/// parentheses, and the <c>+</c> or-later idstring suffix) into an evaluable AST. Pure syntax —
/// no identifier normalization, no knowledge of which licenses exist. Never throws: malformed or
/// unparseable input falls back to a single opaque leaf wrapping the trimmed raw string, so this
/// stays safe to call on the hot serve path with arbitrary upstream-supplied text.
/// </summary>
public abstract class SpdxLicenseExpression
{
    /// <summary>
    /// Parses a raw SPDX expression string. Never throws — a malformed expression (dangling
    /// operator, unbalanced parentheses, empty input) yields a single <see cref="Leaf"/> wrapping
    /// the trimmed raw string, so the whole string is treated as one opaque identifier.
    /// </summary>
    public static SpdxLicenseExpression Parse(string raw)
    {
        string trimmed = raw?.Trim() ?? string.Empty;
        try
        {
            var tokens = Tokenizer.Tokenize(trimmed);
            var parser = new RecursiveDescentParser(tokens);
            var expr = parser.ParseOr();
            return parser.AtEnd ? expr : new Leaf(trimmed);
        }
        catch (SpdxParseException)
        {
            return new Leaf(trimmed);
        }
    }

    /// <summary>
    /// Distinct leaf tokens in this expression (OrdinalIgnoreCase dedup). A <see cref="WithException"/>
    /// node contributes the single atomic string <c>"&lt;baseId&gt; WITH &lt;exceptionId&gt;"</c>
    /// rather than its base and exception separately.
    /// </summary>
    public IReadOnlyList<string> Leaves()
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ordered = new List<string>();
        CollectLeaves(seen, ordered);
        return ordered;
    }

    /// <summary>
    /// Evaluates the expression against a leaf-satisfaction predicate. <c>Or</c> nodes are
    /// satisfied when either operand is; <c>And</c> nodes require both. This yields the desired
    /// policy semantics: OR = any-satisfied, AND = all-satisfied.
    /// </summary>
    public abstract bool Evaluate(Func<string, bool> leafSatisfied);

    /// <summary>True when the expression has more than one leaf, or contains an AND/OR node.</summary>
    public bool IsCompound => Leaves().Count > 1 || HasAndOr();

    internal abstract void CollectLeaves(HashSet<string> seen, List<string> ordered);

    internal abstract bool HasAndOr();

    /// <summary>A single SPDX identifier (may carry a trailing <c>+</c> or-later suffix).</summary>
    public sealed class Leaf : SpdxLicenseExpression
    {
        public string Id { get; }

        public Leaf(string id)
        {
            Id = id;
        }

        public override bool Evaluate(Func<string, bool> leafSatisfied) => leafSatisfied(Id);

        internal override void CollectLeaves(HashSet<string> seen, List<string> ordered)
        {
            if (seen.Add(Id))
            {
                ordered.Add(Id);
            }
        }

        internal override bool HasAndOr() => false;
    }

    /// <summary>
    /// <c>"&lt;baseId&gt; WITH &lt;exceptionId&gt;"</c> — treated as a single atomic leaf, since
    /// an exception only ever applies to its exact base license, not the base id alone.
    /// </summary>
    public sealed class WithException : SpdxLicenseExpression
    {
        public string BaseId { get; }
        public string ExceptionId { get; }

        public WithException(string baseId, string exceptionId)
        {
            BaseId = baseId;
            ExceptionId = exceptionId;
        }

        /// <summary>The single atomic leaf string this node contributes: <c>"BaseId WITH ExceptionId"</c>.</summary>
        public string LeafString => $"{BaseId} WITH {ExceptionId}";

        public override bool Evaluate(Func<string, bool> leafSatisfied) => leafSatisfied(LeafString);

        internal override void CollectLeaves(HashSet<string> seen, List<string> ordered)
        {
            if (seen.Add(LeafString))
            {
                ordered.Add(LeafString);
            }
        }

        internal override bool HasAndOr() => false;
    }

    public sealed class And : SpdxLicenseExpression
    {
        public SpdxLicenseExpression Left { get; }
        public SpdxLicenseExpression Right { get; }

        public And(SpdxLicenseExpression left, SpdxLicenseExpression right)
        {
            Left = left;
            Right = right;
        }

        public override bool Evaluate(Func<string, bool> leafSatisfied)
            => Left.Evaluate(leafSatisfied) && Right.Evaluate(leafSatisfied);

        internal override void CollectLeaves(HashSet<string> seen, List<string> ordered)
        {
            Left.CollectLeaves(seen, ordered);
            Right.CollectLeaves(seen, ordered);
        }

        internal override bool HasAndOr() => true;
    }

    public sealed class Or : SpdxLicenseExpression
    {
        public SpdxLicenseExpression Left { get; }
        public SpdxLicenseExpression Right { get; }

        public Or(SpdxLicenseExpression left, SpdxLicenseExpression right)
        {
            Left = left;
            Right = right;
        }

        public override bool Evaluate(Func<string, bool> leafSatisfied)
            => Left.Evaluate(leafSatisfied) || Right.Evaluate(leafSatisfied);

        internal override void CollectLeaves(HashSet<string> seen, List<string> ordered)
        {
            Left.CollectLeaves(seen, ordered);
            Right.CollectLeaves(seen, ordered);
        }

        internal override bool HasAndOr() => true;
    }

    // Internal-only: signals "give up, fall back to a single opaque leaf" to Parse. Never
    // escapes this file.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Critical Code Smell", "S3871:Exception types should be \"public\"",
        Justification = "Private, file-scoped control-flow signal used only within SpdxLicenseExpression's " +
            "own parser to trigger the opaque-leaf fallback in Parse; it never crosses this type's boundary, " +
            "so callers have no need to catch it by type.")]
    private sealed class SpdxParseException : Exception
    {
        public SpdxParseException(string message) : base(message)
        {
        }
    }

    private enum TokenKind { LParen, RParen, And, Or, With, Ident, End }

    private readonly record struct Token(TokenKind Kind, string Text);

    private static class Tokenizer
    {
        public static List<Token> Tokenize(string raw)
        {
            var tokens = new List<Token>();
            int i = 0;
            while (i < raw.Length)
            {
                i = ConsumeToken(raw, i, tokens);
            }
            tokens.Add(new Token(TokenKind.End, string.Empty));
            return tokens;
        }

        private static int ConsumeToken(string raw, int i, List<Token> tokens)
        {
            char c = raw[i];
            if (char.IsWhiteSpace(c))
            {
                return i + 1;
            }
            if (c == '(')
            {
                tokens.Add(new Token(TokenKind.LParen, "("));
                return i + 1;
            }
            if (c == ')')
            {
                tokens.Add(new Token(TokenKind.RParen, ")"));
                return i + 1;
            }
            if (IsIdentChar(c))
            {
                return ConsumeIdent(raw, i, tokens);
            }
            // Unrecognized character (e.g. a stray operator symbol) — bail out to the
            // whole-string fallback rather than guessing.
            throw new SpdxParseException($"Unexpected character '{c}' at position {i}.");
        }

        private static int ConsumeIdent(string raw, int i, List<Token> tokens)
        {
            int n = raw.Length;
            int start = i;
            while (i < n && IsIdentChar(raw[i]))
            {
                i++;
            }
            // Trailing '+' (or-later) is part of the idstring, not a separate token.
            if (i < n && raw[i] == '+')
            {
                i++;
            }
            string word = raw[start..i];
            tokens.Add(new Token(ClassifyWord(word), word));
            return i;
        }

        private static bool IsIdentChar(char c)
            => char.IsAsciiLetterOrDigit(c) || c is '.' or '-';

        private static TokenKind ClassifyWord(string word) => word switch
        {
            _ when word.Equals("AND", StringComparison.OrdinalIgnoreCase) => TokenKind.And,
            _ when word.Equals("OR", StringComparison.OrdinalIgnoreCase) => TokenKind.Or,
            _ when word.Equals("WITH", StringComparison.OrdinalIgnoreCase) => TokenKind.With,
            _ => TokenKind.Ident,
        };
    }

    // Recursive-descent, left-associative, precedence low-to-high: OR, AND, WITH
    // ('+' is already folded into the ident token by the tokenizer).
    private sealed class RecursiveDescentParser(List<Token> tokens)
    {
        private int _pos;

        public bool AtEnd => Current.Kind == TokenKind.End;

        private Token Current => tokens[_pos];

        public SpdxLicenseExpression ParseOr()
        {
            var left = ParseAnd();
            while (Current.Kind == TokenKind.Or)
            {
                Advance();
                var right = ParseAnd();
                left = new Or(left, right);
            }
            return left;
        }

        private SpdxLicenseExpression ParseAnd()
        {
            var left = ParseWith();
            while (Current.Kind == TokenKind.And)
            {
                Advance();
                var right = ParseWith();
                left = new And(left, right);
            }
            return left;
        }

        private SpdxLicenseExpression ParseWith()
        {
            var left = ParseAtom();
            if (Current.Kind == TokenKind.With)
            {
                Advance();
                if (Current.Kind != TokenKind.Ident || left is not Leaf baseLeaf)
                {
                    throw new SpdxParseException("Expected an identifier after WITH.");
                }
                string exceptionId = Current.Text;
                Advance();
                return new WithException(baseLeaf.Id, exceptionId);
            }
            return left;
        }

        private SpdxLicenseExpression ParseAtom()
        {
            if (Current.Kind == TokenKind.LParen)
            {
                Advance();
                var inner = ParseOr();
                if (Current.Kind != TokenKind.RParen)
                {
                    throw new SpdxParseException("Expected ')'.");
                }
                Advance();
                return inner;
            }
            if (Current.Kind == TokenKind.Ident)
            {
                string id = Current.Text;
                Advance();
                return new Leaf(id);
            }
            throw new SpdxParseException($"Unexpected token '{Current.Text}'.");
        }

        private void Advance() => _pos++;
    }
}
