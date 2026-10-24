#!/usr/bin/env python3
"""Regenerates the hand-built npm tarball fixtures in npm/ that node-tar and System.Formats.Tar
read differently. Each archive carries a clean top-level manifest that a TarReader-based scan
sees, plus a scripted manifest that npm (node-tar under pacote's strip:1 extraction) installs.

Run:   python3 -I npm-tar-fixtures.py <output-dir>
Check: node npm-tar-differential.mjs <output-dir>/<fixture>.tgz
"""
import gzip
import os
import sys

CLEAN = b'{"name":"x","version":"1.0.0"}'
EVIL = b'{"name":"x","version":"1.0.0","scripts":{"postinstall":"echo pwned"},"license":"AGPL-3.0"}'
END = b"\0" * 1024


def octal(value, width):
    return format(value, "o").rjust(width - 1, "0").encode() + b"\0"


def header(name, size, typeflag=b"0", linkname=b"", checksum_delta=0):
    block = bytearray(512)
    block[0:len(name)] = name
    block[100:108] = octal(0o644, 8)
    block[108:116] = octal(0, 8)
    block[116:124] = octal(0, 8)
    block[124:136] = octal(size, 12)
    block[136:148] = octal(0, 12)
    block[148:156] = b" " * 8
    block[156:157] = typeflag
    block[157:157 + len(linkname)] = linkname
    block[257:263] = b"ustar\0"
    block[263:265] = b"00"
    checksum = sum(block) + checksum_delta
    block[148:156] = format(checksum, "o").rjust(6, "0").encode() + b"\0 "
    return bytes(block)


def pad(data):
    return data + b"\0" * (-len(data) % 512)


def entry(name, data, **kwargs):
    return header(name, len(data), **kwargs) + pad(data)


def pax_record(key, value):
    body = b" " + key + b"=" + value + b"\n"
    length = len(body) + 1
    while len(str(length).encode()) + len(body) != length:
        length += 1
    return str(length).encode() + body


def pax(records):
    return entry(b"PaxHeader/x", b"".join(pax_record(k, v) for k, v in records), typeflag=b"x")


def readme_hiding(hidden, **kwargs):
    """A README header whose declared body is exactly the hidden entries."""
    return header(b"package/README.md", len(hidden), **kwargs) + hidden


def write(out_dir, name, tar):
    path = os.path.join(out_dir, name)
    with open(path, "wb") as f:
        f.write(gzip.compress(tar, mtime=0))
    print(path)


def main(out_dir):
    clean = entry(b"package/package.json", CLEAN)
    hidden = entry(b"package/package.json", EVIL)

    # node-tar skips a header whose checksum does not verify and parses the next block.
    write(out_dir, "npm-hidden-header-bad-checksum.tgz",
          clean + readme_hiding(hidden, checksum_delta=-21) + END)

    # node-tar skips a regular-file header that carries a link name.
    write(out_dir, "npm-hidden-header-linkpath.tgz",
          clean + readme_hiding(hidden, linkname=b"x") + END)

    # node-tar skips a header whose path is empty once the pending PAX record is applied. That
    # record stays pending, so the hidden entry carries a PAX path of its own to replace it.
    write(out_dir, "npm-hidden-header-empty-pax-path.tgz",
          clean + pax([(b"path", b"")])
          + readme_hiding(pax([(b"path", b"package/package.json")]) + hidden) + END)

    # node-tar forces a directory's size to zero, so the next block is a header, not its body.
    hidden_dir = hidden
    write(out_dir, "npm-hidden-header-directory-size.tgz",
          clean + header(b"package/docs/", len(hidden_dir), typeflag=b"5") + hidden_dir + END)

    # A regular-file header whose name ends in `/` is a directory to node-tar, so the same applies.
    write(out_dir, "npm-hidden-header-trailing-slash-file.tgz",
          clean + header(b"package/docs/", len(hidden), typeflag=b"0") + hidden + END)

    # On posix a backslash is an ordinary filename character, so strip:1 removes all of `x\y`.
    write(out_dir, "npm-backslash-in-wrapper.tgz",
          clean + entry(b"x\\y/package.json", EVIL) + END)

    # path.win32.parse reads `\\server\share\` as a UNC root, which stripAbsolutePath removes.
    write(out_dir, "npm-backslash-unc-root.tgz",
          clean + entry(b"package/\\\\server\\share\\package.json", EVIL) + END)


def write_hidden_member(out_dir):
    # A first gzip member with no end-of-archive blocks, zero padding to 64 KiB, then a second
    # member. .NET's GZipStream stops at the padding; node's zlib reads the second member when
    # it starts a write chunk (npm-tar-differential.mjs --chunk 65536).
    first = gzip.compress(entry(b"package/package.json", CLEAN), mtime=0)
    second = gzip.compress(entry(b"package/package.json", EVIL) + END, mtime=0)
    path = os.path.join(out_dir, "npm-hidden-member-after-zero-padding.tgz")
    with open(path, "wb") as f:
        f.write(first + b"\0" * (65536 - len(first)) + second)
    print(path)


if __name__ == "__main__":
    write_hidden_member(sys.argv[1] if len(sys.argv) > 1 else ".")
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
