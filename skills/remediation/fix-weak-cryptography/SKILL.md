---
name: fix-weak-cryptography
description: Remediate weak/broken cryptographic primitive findings (CWE-319/321/322/323/324/325/326/327/328/330/331/338/340/347/916/1240 — OWASP A04:2025 Cryptographic Failures) by replacing outdated algorithms, hardcoded keys, and non-cryptographic randomness with vetted, current alternatives.
category: remediation
cwe:
  - CWE-319
  - CWE-321
  - CWE-326
  - CWE-327
  - CWE-328
  - CWE-330
  - CWE-338
  - CWE-347
  - CWE-916
inputs:
  - OSV_ID
  - PACKAGE_PURL
  - FIXED_VERSION
---

## When to use this

The code uses cryptography incorrectly in a way that undermines the protection it's meant to
provide: a broken or outdated algorithm (MD5/SHA-1 for integrity, DES/RC4 for encryption), a
non-cryptographic random-number generator used where unpredictability matters (a session token, a
password-reset code, a nonce), a cryptographic key or credential hardcoded in source, sensitive
data sent or stored in cleartext, an encryption key reused across contexts where it must be
unique, or a signature/MAC that is computed but never actually checked before the data is trusted.

This is not about implementing cryptographic primitives yourself — it's the opposite: identify
where the code rolled its own choice (an algorithm, a key, a random source) and replace it with
the platform/library's current vetted default instead.

If the finding is in a third-party dependency and `FIXED_VERSION` is set, apply the
`fix-vulnerable-dependency` skill first — many crypto CVEs are a library shipping a broken default
that a newer version corrects. Use this skill when the weak cryptography is in your own code, or
the fixed dependency version still needs its call sites reviewed (e.g. it added a stronger
algorithm option but keeps the old one for compatibility, and your code needs to opt in).

## Core principle

Never choose a cryptographic algorithm, key, or random source yourself when the platform offers a
vetted current default — use the standard library's/framework's recommended primitive, and treat
"we picked MD5/DES/a fixed seed because it was simpler" as the bug, not an implementation detail.

## Replace broken/outdated algorithms

```python
# Unsafe: MD5/SHA-1 are broken for collision resistance — don't use for integrity or signatures.
digest = hashlib.md5(data).hexdigest()
# Safe: a current, collision-resistant hash.
digest = hashlib.sha256(data).hexdigest()
```

```csharp
// Unsafe: DES and RC4 are broken ciphers.
using var des = DES.Create();
// Safe: AES-GCM — authenticated encryption, not just confidentiality.
using var aes = new AesGcm(key, tagSizeInBytes: 16);
```

Symmetric encryption should use an authenticated mode (AES-GCM, ChaCha20-Poly1305) rather than an
unauthenticated mode (AES-CBC/ECB alone) — an unauthenticated cipher lets an attacker tamper with
ciphertext without detection, even though the content itself stays confidential.

## Use a cryptographically secure random source

A non-cryptographic PRNG (`Random`/`math.random()`/`rand()`) is predictable from its seed and
output history — safe for shuffling a UI list, unsafe for anything an attacker must not be able to
guess: session tokens, password-reset codes, API keys, nonces/IVs.

```python
# Unsafe: not cryptographically secure — predictable given other outputs.
token = str(random.randint(100000, 999999))
# Safe: os.urandom-backed, meant for security-sensitive values.
token = secrets.token_urlsafe(32)
```

```javascript
// Unsafe: Math.random() is not cryptographically secure.
const token = Math.random().toString(36).slice(2);
// Safe: crypto.randomBytes / crypto.getRandomValues.
const token = crypto.randomBytes(32).toString("hex");
```

```csharp
// Safe: RandomNumberGenerator, not System.Random, for security-sensitive values.
byte[] token = RandomNumberGenerator.GetBytes(32);
```

## Never hardcode keys or credentials

A cryptographic key, API secret, or password hardcoded in source is visible to anyone with read
access to the repository (including its full git history, even after a later commit removes it) —
load it from a secrets manager or environment variable injected at deploy time instead, and rotate
the key that was exposed.

```python
# Unsafe: key baked into source, and in every clone/fork of the repo forever.
SECRET_KEY = "a1b2c3d4e5f6..."
# Safe: read from environment/secrets manager at startup; fail closed if unset.
SECRET_KEY = os.environ["SECRET_KEY"]
```

## Don't reuse a key or nonce across contexts

A nonce/IV must be unique per encryption operation under the same key — reusing one (a fixed IV, a
counter that resets, a nonce derived from non-unique input) breaks the confidentiality guarantee
of stream ciphers and GCM alike. Generate a fresh, random nonce for every encryption call and store
it alongside the ciphertext (it does not need to be secret, only unique).

## Verify signatures and password hashes before trusting them

A signature or MAC that is computed but whose result is never checked (or is checked with a
non-constant-time comparison, or against an attacker-controlled expected value) provides no
protection at all:

```python
# Unsafe: computed but never compared against anything.
signature = hmac.new(key, payload, hashlib.sha256).hexdigest()
process(payload)   # nothing checked signature against expected_signature

# Safe: constant-time comparison against the expected value, checked before trusting the payload.
expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
if not hmac.compare_digest(signature, expected):
    raise ValueError("Invalid signature.")
process(payload)
```

Passwords must go through a dedicated slow, salted password-hashing function (bcrypt, scrypt,
Argon2, PBKDF2 with a high iteration count) — never a general-purpose fast hash (SHA-256/MD5 alone),
which is deliberately fast and therefore cheap to brute-force offline.

## Verify

1. Reproduce the original finding: confirm the vulnerable algorithm/random source/hardcoded key is
   gone from the fixed code path, not just supplemented by a stronger option that's still opt-in.
2. If a key was hardcoded and exposed, rotate it — removing it from new commits does not remove it
   from git history or from anyone who already cloned the repository.
3. Run the project's test suite.
4. Re-run whatever SAST/DAST tool originally flagged the finding, or re-scan the dependency
   through dependably if the weak cryptography was in a third-party package (`OSV_ID`,
   `PACKAGE_PURL`).
