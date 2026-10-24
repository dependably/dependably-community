using System.Numerics;
using Dependably.Protocol.Hex;

namespace Dependably.Tests.Unit.Hex;

/// <summary>
/// The term model's value semantics: atoms, structural tuple equality, deep equality and hashing
/// across every term kind, integer narrowing, and map lookup through the term comparer.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ErlangTermModelTests
{
    [Fact]
    public void Atoms_ExposeTheirWellKnownFlags()
    {
        Assert.True(ErlangAtom.True.IsTrue);
        Assert.False(ErlangAtom.True.IsFalse);
        Assert.True(ErlangAtom.False.IsFalse);
        Assert.False(ErlangAtom.False.IsTrue);
        Assert.True(ErlangAtom.Nil.IsNil);
        Assert.False(ErlangAtom.Undefined.IsNil);
        Assert.Equal("undefined", ErlangAtom.Undefined.Name);
        Assert.Equal("true", ErlangAtom.True.ToString());
        Assert.Equal("ok", new ErlangAtom("ok").ToString());
        Assert.False(new ErlangAtom("True").IsTrue);
    }

    [Fact]
    public void Charlist_ToString_IsItsText()
    {
        Assert.Equal("abc", new ErlangCharlist("abc").ToString());
    }

    [Fact]
    public void Tuple_ExposesArityAndItems_AndEmptyHasNone()
    {
        var tuple = ErlangTermModel.Tuple("ok", 1L);

        Assert.Equal(2, tuple.Arity);
        Assert.Equal("ok", tuple[0]);
        Assert.Equal(1L, tuple[1]);
        Assert.Equal(0, ErlangTuple.Empty.Arity);
    }

    [Fact]
    public void Tuples_CompareStructurally_AndHashAlike()
    {
        var left = ErlangTermModel.Tuple("a", ErlangTermModel.List(1L, 2L), ErlangTermModel.Tuple(ErlangAtom.True));
        var right = ErlangTermModel.Tuple("a", ErlangTermModel.List(1L, 2L), ErlangTermModel.Tuple(ErlangAtom.True));
        var different = ErlangTermModel.Tuple("a", ErlangTermModel.List(1L, 3L), ErlangTermModel.Tuple(ErlangAtom.True));

        Assert.Equal(left, right);
        Assert.Equal(left.GetHashCode(), right.GetHashCode());
        Assert.NotEqual(left, different);
        Assert.False(left.Equals(null));
        Assert.NotEqual(left, ErlangTermModel.Tuple("a"));
    }

    [Fact]
    public void DeepEquals_NullsAndReferences()
    {
        Assert.True(ErlangTermModel.DeepEquals(null, null));
        Assert.False(ErlangTermModel.DeepEquals(null, "x"));
        Assert.False(ErlangTermModel.DeepEquals("x", null));
        byte[] shared = new byte[] { 1, 2 };
        Assert.True(ErlangTermModel.DeepEquals(shared, shared));
    }

    [Fact]
    public void DeepEquals_ComparesEachKindByValue()
    {
        Assert.True(ErlangTermModel.DeepEquals(new ErlangAtom("ok"), new ErlangAtom("ok")));
        Assert.False(ErlangTermModel.DeepEquals(new ErlangAtom("ok"), new ErlangAtom("error")));
        Assert.False(ErlangTermModel.DeepEquals(new ErlangAtom("ok"), "ok"));

        Assert.True(ErlangTermModel.DeepEquals(new ErlangCharlist("ab"), new ErlangCharlist("ab")));
        Assert.False(ErlangTermModel.DeepEquals(new ErlangCharlist("ab"), new ErlangCharlist("ac")));
        Assert.False(ErlangTermModel.DeepEquals(new ErlangCharlist("ab"), "ab"));

        Assert.True(ErlangTermModel.DeepEquals("ab", "ab"));
        Assert.False(ErlangTermModel.DeepEquals("ab", new ErlangCharlist("ab")));

        Assert.True(ErlangTermModel.DeepEquals(new byte[] { 1, 2 }, new byte[] { 1, 2 }));
        Assert.False(ErlangTermModel.DeepEquals(new byte[] { 1, 2 }, new byte[] { 1, 3 }));
        Assert.False(ErlangTermModel.DeepEquals(new byte[] { 1, 2 }, "ab"));

        Assert.True(ErlangTermModel.DeepEquals(1.5, 1.5));
        Assert.False(ErlangTermModel.DeepEquals(1.5, 2.5));
        Assert.False(ErlangTermModel.DeepEquals(1.5, 1L));

        Assert.True(ErlangTermModel.DeepEquals(ErlangTermModel.Tuple(1L), ErlangTermModel.Tuple(1L)));
        Assert.False(ErlangTermModel.DeepEquals(ErlangTermModel.Tuple(1L), ErlangTermModel.List(1L)));

        Assert.True(ErlangTermModel.DeepEquals(ErlangTermModel.List(1L, "a"), ErlangTermModel.List(1L, "a")));
        Assert.False(ErlangTermModel.DeepEquals(ErlangTermModel.List(1L, "a"), ErlangTermModel.List(1L)));
        Assert.False(ErlangTermModel.DeepEquals(ErlangTermModel.List(1L, "a"), ErlangTermModel.List(1L, "b")));
        Assert.False(ErlangTermModel.DeepEquals(ErlangTermModel.List(1L), ErlangTermModel.Map(("k", 1L))));
    }

    [Fact]
    public void DeepEquals_IntegersCompareByValueAcrossWidths()
    {
        Assert.True(ErlangTermModel.DeepEquals(5L, new BigInteger(5)));
        Assert.True(ErlangTermModel.DeepEquals(5, 5L));
        Assert.True(ErlangTermModel.DeepEquals((byte)5, (short)5));
        Assert.True(ErlangTermModel.DeepEquals(ulong.MaxValue, new BigInteger(ulong.MaxValue)));
        Assert.False(ErlangTermModel.DeepEquals(5L, 6L));
        Assert.False(ErlangTermModel.DeepEquals(5L, "5"));
        Assert.False(ErlangTermModel.DeepEquals(5L, new object()));
    }

    [Fact]
    public void DeepEquals_NonTermObjectsFallBackToObjectEquality()
    {
        object token = new();

        Assert.True(ErlangTermModel.DeepEquals(token, token));
        Assert.False(ErlangTermModel.DeepEquals(token, new object()));
        Assert.False(ErlangTermModel.DeepEquals(new Guid("11111111-1111-1111-1111-111111111111"), "x"));
    }

    [Fact]
    public void DeepEquals_MapsCompareEntryWise_RegardlessOfComparer()
    {
        var left = ErlangTermModel.Map(("name", "plug"), ("tags", ErlangTermModel.List("web")));
        var right = ErlangTermModel.Map(("tags", ErlangTermModel.List("web")), ("name", "plug"));
        var ordinalKeyed = new Dictionary<object, object?>(EqualityComparer<object>.Default)
        {
            ["name"] = "plug",
            ["tags"] = ErlangTermModel.List("web"),
        };
        var otherValue = ErlangTermModel.Map(("name", "plug"), ("tags", ErlangTermModel.List("api")));
        var otherKey = ErlangTermModel.Map(("name", "plug"), ("labels", ErlangTermModel.List("web")));

        Assert.True(ErlangTermModel.DeepEquals(left, right));
        Assert.True(ErlangTermModel.DeepEquals(left, ordinalKeyed));
        Assert.False(ErlangTermModel.DeepEquals(left, otherValue));
        Assert.False(ErlangTermModel.DeepEquals(left, otherKey));
        Assert.False(ErlangTermModel.DeepEquals(left, ErlangTermModel.Map(("name", "plug"))));
    }

    [Fact]
    public void DeepEquals_MapWithTermKeys_FallsBackToAStructuralScan()
    {
        var tupleKeyed = new Dictionary<object, object?>(ReferenceEqualityComparer.Instance)
        {
            [ErlangTermModel.Tuple("k")] = "v",
        };
        var other = new Dictionary<object, object?>(ReferenceEqualityComparer.Instance)
        {
            [ErlangTermModel.Tuple("k")] = "v",
        };
        var mismatched = new Dictionary<object, object?>(ReferenceEqualityComparer.Instance)
        {
            [ErlangTermModel.Tuple("k")] = "w",
        };

        Assert.True(ErlangTermModel.DeepEquals(tupleKeyed, other));
        Assert.False(ErlangTermModel.DeepEquals(tupleKeyed, mismatched));
    }

    [Fact]
    public void DeepHash_EqualTermsHashEqual_ForEveryKind()
    {
        (object? Left, object? Right)[] pairs =
        {
            (null, null),
            (new ErlangAtom("ok"), new ErlangAtom("ok")),
            (new ErlangCharlist("abc"), new ErlangCharlist("abc")),
            ("abc", "abc"),
            (new byte[] { 1, 2, 3 }, new byte[] { 1, 2, 3 }),
            (ErlangTermModel.Tuple("a", 1L), ErlangTermModel.Tuple("a", 1L)),
            (2.5, 2.5),
            (ErlangTermModel.Map(("a", 1L), ("b", 2L)), ErlangTermModel.Map(("b", 2L), ("a", 1L))),
            (ErlangTermModel.List(1L, 2L), ErlangTermModel.List(1L, 2L)),
            (7L, new BigInteger(7)),
            (new Guid("22222222-2222-2222-2222-222222222222"), new Guid("22222222-2222-2222-2222-222222222222")),
        };

        foreach (var (left, right) in pairs)
        {
            Assert.True(ErlangTermModel.DeepEquals(left, right));
            Assert.Equal(ErlangTermModel.DeepHash(left), ErlangTermModel.DeepHash(right));
        }
    }

    [Fact]
    public void DeepHash_DistinguishesTheKindOfTerm()
    {
        Assert.Equal(0, ErlangTermModel.DeepHash(null));
        Assert.NotEqual(ErlangTermModel.DeepHash(new ErlangAtom("abc")), ErlangTermModel.DeepHash("abc"));
        Assert.NotEqual(ErlangTermModel.DeepHash(new ErlangCharlist("abc")), ErlangTermModel.DeepHash("abc"));
        Assert.NotEqual(ErlangTermModel.DeepHash(ErlangTermModel.List(1L)), ErlangTermModel.DeepHash(ErlangTermModel.Tuple(1L)));
        Assert.NotEqual(ErlangTermModel.DeepHash(ErlangTermModel.List(1L)), ErlangTermModel.DeepHash(ErlangTermModel.List(2L)));
    }

    [Fact]
    public void TermComparer_FindsDecodedMapEntriesByFreshKeys()
    {
        var map = new Dictionary<object, object?>(ErlangTermModel.TermComparer)
        {
            ["name"] = "plug",
            [ErlangTermModel.Tuple("k", 1L)] = "tuple-keyed",
            [10L] = "int-keyed",
        };

        Assert.Equal("plug", map["name"]);
        Assert.Equal("tuple-keyed", map[ErlangTermModel.Tuple("k", 1L)]);
        Assert.Equal("int-keyed", map[new BigInteger(10)]);
        Assert.False(map.ContainsKey("missing"));
        Assert.True(ErlangTermModel.TermComparer.Equals("a", "a"));
        Assert.False(ErlangTermModel.TermComparer.Equals(null, "a"));
    }

    [Fact]
    public void Map_LaterDuplicateKeyWins_AndNullValuesAreKept()
    {
        var map = ErlangTermModel.Map(("k", 1L), ("k", 2L), ("n", null));

        Assert.Equal(2, map.Count);
        Assert.Equal(2L, map["k"]);
        Assert.Null(map["n"]);
    }

    [Fact]
    public void Builders_RejectNullArguments()
    {
        Assert.Throws<ArgumentNullException>(() => ErlangTermModel.Map(null!));
        Assert.Throws<ArgumentNullException>(() => ErlangTermModel.List(null!));
        Assert.Throws<ArgumentNullException>(() => ErlangTermModel.Tuple(null!));
    }

    [Fact]
    public void NarrowInteger_UsesLongWhenItFits_AndBigIntegerAtTheEdges()
    {
        Assert.Equal(42L, Assert.IsType<long>(ErlangTermModel.NarrowInteger(42)));
        Assert.Equal(long.MaxValue, Assert.IsType<long>(ErlangTermModel.NarrowInteger(long.MaxValue)));
        Assert.Equal(long.MinValue, Assert.IsType<long>(ErlangTermModel.NarrowInteger(long.MinValue)));
        var above = (BigInteger)long.MaxValue + 1;
        var below = (BigInteger)long.MinValue - 1;
        Assert.Equal(above, Assert.IsType<BigInteger>(ErlangTermModel.NarrowInteger(above)));
        Assert.Equal(below, Assert.IsType<BigInteger>(ErlangTermModel.NarrowInteger(below)));
    }

    [Fact]
    public void TryAsInteger_AcceptsEveryIntegralWidth_AndRejectsEverythingElse()
    {
        object[] integral = { (sbyte)-3, (byte)3, (short)-3, (ushort)3, -3, -3L };
        foreach (object value in integral)
        {
            Assert.True(ErlangTermModel.TryAsInteger(value, out var integer));
            Assert.Equal(Math.Abs((int)Convert.ToInt64(value)), Math.Abs((int)integer));
        }

        Assert.True(ErlangTermModel.TryAsInteger(ulong.MaxValue, out var big));
        Assert.Equal(ulong.MaxValue, (ulong)big);
        Assert.True(ErlangTermModel.TryAsInteger(new BigInteger(99), out var wrapped));
        Assert.Equal(99, (int)wrapped);
        Assert.False(ErlangTermModel.TryAsInteger("5", out var none));
        Assert.Equal(BigInteger.Zero, none);
        Assert.False(ErlangTermModel.TryAsInteger(5.0, out _));
    }

    [Fact]
    public void ErlangTermException_CarriesMessageAndInnerException()
    {
        var inner = new InvalidOperationException("boom");

        Assert.Equal("bad term", new ErlangTermException("bad term").Message);
        var wrapped = new ErlangTermException("bad term", inner);
        Assert.Same(inner, wrapped.InnerException);
        Assert.NotNull(new ErlangTermException().Message);
    }
}
