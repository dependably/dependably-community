using System.Security.Cryptography;

namespace Dependably.Protocol.Provenance;

/// <summary>
/// RFC 6962 §2.1 Merkle tree helper for Rekor inclusion-proof verification. The tree uses
/// SHA-256 with domain-separated prefixes: leaf nodes are hashed as <c>SHA256(0x00 || body)</c>;
/// interior nodes as <c>SHA256(0x01 || left || right)</c>.
/// </summary>
internal static class RekorMerkle
{
    // RFC 6962 §2.1 domain-separation prefixes for leaf and interior hashes.
    private const byte LeafPrefix = 0x00;
    private const byte InternalPrefix = 0x01;

    /// <summary>
    /// Computes the leaf hash for the given <paramref name="body"/> bytes: SHA256(0x00 || body).
    /// </summary>
    public static byte[] LeafHash(byte[] body)
    {
        byte[] input = new byte[1 + body.Length];
        input[0] = LeafPrefix;
        Buffer.BlockCopy(body, 0, input, 1, body.Length);
        return SHA256.HashData(input);
    }

    /// <summary>
    /// Verifies an RFC 6962 inclusion proof.
    /// </summary>
    /// <param name="leafIndex">Zero-based index of the leaf whose membership is being proven.</param>
    /// <param name="treeSize">Total number of leaves in the tree at the time the proof was generated.</param>
    /// <param name="leafHash">The leaf hash (SHA256(0x00 || canonicalized_body)).</param>
    /// <param name="hashes">Proof path hashes, left to right from leaf to root.</param>
    /// <param name="expectedRoot">The root hash that the proof should reconstruct.</param>
    /// <returns>True when the proof reconstructs exactly <paramref name="expectedRoot"/>.</returns>
    public static bool VerifyInclusion(
        long leafIndex,
        long treeSize,
        byte[] leafHash,
        IReadOnlyList<byte[]> hashes,
        byte[] expectedRoot)
    {
        if (leafIndex < 0 || treeSize <= 0 || leafIndex >= treeSize)
        {
            return false;
        }

        long fn = leafIndex;
        long sn = treeSize - 1;
        byte[] r = leafHash;
        int proofIdx = 0;

        while (proofIdx < hashes.Count)
        {
            if (sn == 0)
            {
                // More proof elements than the tree depth allows.
                return false;
            }

            byte[] p = hashes[proofIdx++];

            if ((fn & 1) == 1 || fn == sn)
            {
                // Current node is a right child (or the rightmost node): combine p || r.
                r = InternalHash(p, r);
                // Collapse the path while current node is a left child of the next level.
                while ((fn & 1) == 0 && fn != 0)
                {
                    fn >>= 1;
                    sn >>= 1;
                }
            }
            else
            {
                // Current node is a left child: combine r || p.
                r = InternalHash(r, p);
            }

            fn >>= 1;
            sn >>= 1;
        }

        if (sn != 0)
        {
            // Proof was too short — did not reach the root.
            return false;
        }

        return r.AsSpan().SequenceEqual(expectedRoot.AsSpan());
    }

    // SHA256(0x01 || left || right) for interior nodes.
    private static byte[] InternalHash(byte[] left, byte[] right)
    {
        byte[] input = new byte[1 + left.Length + right.Length];
        input[0] = InternalPrefix;
        Buffer.BlockCopy(left, 0, input, 1, left.Length);
        Buffer.BlockCopy(right, 0, input, 1 + left.Length, right.Length);
        return SHA256.HashData(input);
    }
}
