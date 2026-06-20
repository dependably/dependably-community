using System.Security.Cryptography;
using Dependably.Protocol.Provenance;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Direct unit tests for <see cref="RekorMerkle.VerifyInclusion"/> and
/// <see cref="RekorMerkle.LeafHash"/>. These exercise the RFC 6962 §2.1 Merkle math in
/// isolation so any regression in the algorithm is caught independently of the full verifier
/// path.
///
/// All trees are built from self-consistent byte values: each "leaf body" is a short byte
/// sequence that the test controls, leaf hashes are computed with <see cref="RekorMerkle.LeafHash"/>,
/// and interior hashes follow SHA256(0x01 || left || right). No external fixtures needed.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RekorMerkleTests
{
    // ── LeafHash ──────────────────────────────────────────────────────────────

    [Fact]
    public void LeafHash_IsSha256Of0x00Prefix()
    {
        byte[] body = "hello"u8.ToArray();
        byte[] input = new byte[1 + body.Length];
        input[0] = 0x00;
        body.CopyTo(input, 1);
        byte[] expected = SHA256.HashData(input);

        byte[] actual = RekorMerkle.LeafHash(body);

        Assert.Equal(expected, actual);
    }

    // ── tree_size=1: root equals the single leaf hash, empty proof ────────────

    [Fact]
    public void TreeSize1_EmptyProof_RootEqualsLeafHash()
    {
        byte[] body = "entry-body"u8.ToArray();
        byte[] leaf = RekorMerkle.LeafHash(body);

        bool ok = RekorMerkle.VerifyInclusion(leafIndex: 0, treeSize: 1, leaf, hashes: [], expectedRoot: leaf);

        Assert.True(ok);
    }

    [Fact]
    public void TreeSize1_WrongRoot_Fails()
    {
        byte[] body = "entry-body"u8.ToArray();
        byte[] leaf = RekorMerkle.LeafHash(body);
        byte[] wrongRoot = new byte[32]; // all zeros

        bool ok = RekorMerkle.VerifyInclusion(0, 1, leaf, [], wrongRoot);

        Assert.False(ok);
    }

    // ── tree_size=2: root = H(0x01 || leaf0 || leaf1) ─────────────────────────

    [Fact]
    public void TreeSize2_LeafIndex0_ProofIsLeaf1()
    {
        byte[] leaf0 = RekorMerkle.LeafHash("body-0"u8.ToArray());
        byte[] leaf1 = RekorMerkle.LeafHash("body-1"u8.ToArray());
        byte[] root = InternalHash(leaf0, leaf1);

        // To prove leaf0: the sibling proof element is leaf1 (right).
        bool ok = RekorMerkle.VerifyInclusion(0, 2, leaf0, [leaf1], root);

        Assert.True(ok);
    }

    [Fact]
    public void TreeSize2_LeafIndex1_ProofIsLeaf0()
    {
        byte[] leaf0 = RekorMerkle.LeafHash("body-0"u8.ToArray());
        byte[] leaf1 = RekorMerkle.LeafHash("body-1"u8.ToArray());
        byte[] root = InternalHash(leaf0, leaf1);

        // To prove leaf1: the sibling proof element is leaf0 (left).
        bool ok = RekorMerkle.VerifyInclusion(1, 2, leaf1, [leaf0], root);

        Assert.True(ok);
    }

    // ── tree_size=4: two-element proof ────────────────────────────────────────
    //
    //       root
    //      /    \
    //    n01    n23
    //   /   \   /  \
    //  L0  L1  L2  L3

    [Fact]
    public void TreeSize4_LeafIndex0_TwoElementProof()
    {
        byte[] l0 = RekorMerkle.LeafHash("b0"u8.ToArray());
        byte[] l1 = RekorMerkle.LeafHash("b1"u8.ToArray());
        byte[] l2 = RekorMerkle.LeafHash("b2"u8.ToArray());
        byte[] l3 = RekorMerkle.LeafHash("b3"u8.ToArray());
        byte[] n01 = InternalHash(l0, l1);
        byte[] n23 = InternalHash(l2, l3);
        byte[] root = InternalHash(n01, n23);

        // Proof for L0: [L1, n23]
        bool ok = RekorMerkle.VerifyInclusion(0, 4, l0, [l1, n23], root);

        Assert.True(ok);
    }

    [Fact]
    public void TreeSize4_LeafIndex2_TwoElementProof()
    {
        byte[] l0 = RekorMerkle.LeafHash("b0"u8.ToArray());
        byte[] l1 = RekorMerkle.LeafHash("b1"u8.ToArray());
        byte[] l2 = RekorMerkle.LeafHash("b2"u8.ToArray());
        byte[] l3 = RekorMerkle.LeafHash("b3"u8.ToArray());
        byte[] n01 = InternalHash(l0, l1);
        byte[] n23 = InternalHash(l2, l3);
        byte[] root = InternalHash(n01, n23);

        // Proof for L2: [L3, n01]
        bool ok = RekorMerkle.VerifyInclusion(2, 4, l2, [l3, n01], root);

        Assert.True(ok);
    }

    // ── tampered proof → false ────────────────────────────────────────────────

    [Fact]
    public void TamperedProofElement_Fails()
    {
        byte[] l0 = RekorMerkle.LeafHash("b0"u8.ToArray());
        byte[] l1 = RekorMerkle.LeafHash("b1"u8.ToArray());
        byte[] root = InternalHash(l0, l1);

        // Flip a byte in the proof element.
        byte[] tampered = (byte[])l1.Clone();
        tampered[0] ^= 0xFF;

        bool ok = RekorMerkle.VerifyInclusion(0, 2, l0, [tampered], root);

        Assert.False(ok);
    }

    [Fact]
    public void WrongLeafHash_Fails()
    {
        byte[] l0 = RekorMerkle.LeafHash("b0"u8.ToArray());
        byte[] l1 = RekorMerkle.LeafHash("b1"u8.ToArray());
        byte[] root = InternalHash(l0, l1);

        // Provide the wrong leaf hash for the index.
        bool ok = RekorMerkle.VerifyInclusion(0, 2, l1, [l1], root);

        Assert.False(ok);
    }

    [Fact]
    public void WrongLeafIndex_Fails()
    {
        byte[] l0 = RekorMerkle.LeafHash("b0"u8.ToArray());
        byte[] l1 = RekorMerkle.LeafHash("b1"u8.ToArray());
        byte[] root = InternalHash(l0, l1);

        // Claim leaf is at index 1 but provide leaf0's hash and leaf1's proof — wrong combination.
        bool ok = RekorMerkle.VerifyInclusion(1, 2, l0, [l0], root);

        Assert.False(ok);
    }

    // ── degenerate inputs ─────────────────────────────────────────────────────

    [Fact]
    public void LeafIndexOutOfRange_Fails()
    {
        byte[] leaf = RekorMerkle.LeafHash("x"u8.ToArray());
        bool ok = RekorMerkle.VerifyInclusion(1, 1, leaf, [], leaf);
        Assert.False(ok);
    }

    [Fact]
    public void TreeSizeZero_Fails()
    {
        byte[] leaf = RekorMerkle.LeafHash("x"u8.ToArray());
        bool ok = RekorMerkle.VerifyInclusion(0, 0, leaf, [], leaf);
        Assert.False(ok);
    }

    [Fact]
    public void TooManyProofElements_Fails()
    {
        // tree_size=1: no sibling can exist; a non-empty proof must be rejected.
        byte[] body = "body"u8.ToArray();
        byte[] leaf = RekorMerkle.LeafHash(body);
        byte[] bogus = new byte[32];

        bool ok = RekorMerkle.VerifyInclusion(0, 1, leaf, [bogus], leaf);

        Assert.False(ok);
    }

    // Computes the RFC 6962 interior node hash: SHA256(0x01 || left || right).
    private static byte[] InternalHash(byte[] left, byte[] right)
    {
        byte[] input = new byte[1 + left.Length + right.Length];
        input[0] = 0x01;
        left.CopyTo(input, 1);
        right.CopyTo(input, 1 + left.Length);
        return SHA256.HashData(input);
    }
}
