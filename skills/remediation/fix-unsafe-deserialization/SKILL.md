---
name: fix-unsafe-deserialization
description: Remediate unsafe deserialization and mass-assignment findings (CWE-502/915 — OWASP A08:2025 Software or Data Integrity Failures) by moving to safe data formats, allowlisted types, and explicit field binding.
category: remediation
cwe:
  - CWE-502
  - CWE-915
inputs:
  - OSV_ID
  - PACKAGE_PURL
  - FIXED_VERSION
---

## When to use this

Untrusted bytes (a request body, a cookie, a cached blob, a message-queue payload) are
deserialized using a format whose deserializer can be made to construct arbitrary types or invoke
arbitrary code as a side effect of parsing — not just populate plain data fields. This includes
native serialization formats (Java serialization, .NET `BinaryFormatter`/`NetDataContractSerializer`,
Python `pickle`, PHP `unserialize`, Ruby `Marshal`) and polymorphic JSON/YAML deserialization with
type information embedded in the payload. It also covers mass assignment (CWE-915): binding an
entire untrusted payload onto a model object without restricting which fields can be set,
letting an attacker set fields the API was never meant to expose (`isAdmin`, `role`, an internal
id).

If the finding is in a third-party dependency and `FIXED_VERSION` is set, apply the
`fix-vulnerable-dependency` skill first — many deserialization CVEs are gadget-chain
vulnerabilities in a specific library version, fixed by upgrading past it. Use this skill when the
unsafe deserialization is in your own code, or the fixed dependency version still needs its call
sites reviewed for the underlying pattern.

## Core principle

Never deserialize untrusted data with a format/API that can construct types or execute code as a
side effect of parsing. Prefer data-only formats (JSON, protobuf with a fixed schema) validated
against an explicit schema, and treat any "restore arbitrary object graph" deserializer as
equivalent to `eval()` on the input bytes.

## Stop using native/polymorphic deserializers on untrusted input

```python
# Unsafe: pickle can execute arbitrary code during unpickling.
data = pickle.loads(untrusted_bytes)
# Safe: a schema-validated data format instead.
data = MySchema.model_validate_json(untrusted_bytes)   # pydantic, or equivalent
```

```csharp
// Unsafe: BinaryFormatter is a known gadget-chain target — deprecated for exactly this reason.
var obj = new BinaryFormatter().Deserialize(untrustedStream);
// Safe: System.Text.Json with a known, non-polymorphic target type.
var obj = JsonSerializer.Deserialize<KnownDto>(untrustedJson);
```

```java
// Unsafe: ObjectInputStream on untrusted bytes without a filter.
Object obj = new ObjectInputStream(untrustedStream).readObject();
// Safer if native serialization can't be avoided: an allowlist filter restricting
// which classes may be constructed during deserialization.
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter("com.example.dto.*;!*");
ois.setObjectInputFilter(filter);
```

If polymorphic JSON deserialization is required (Jackson `@JsonTypeInfo`, Newtonsoft
`TypeNameHandling`), restrict the accepted types to an explicit allowlist rather than trusting a
type name embedded in the payload — an unrestricted polymorphic deserializer is exploitable the
same way native serialization is, even though the wire format is "just JSON".

## If native deserialization genuinely can't be removed

- **Verify integrity before deserializing**: an HMAC or signature over the serialized bytes,
  checked with a secret the sender doesn't control, means a tampered payload never reaches the
  deserializer at all.
- **Allowlist types**, not denylist — an allowlist of the specific classes the deserializer may
  construct is safe by construction; a denylist of "known dangerous gadget classes" is a losing
  race against newly discovered gadgets.
- **Run the deserializer with reduced privileges** (a sandboxed process, a restricted user) so a
  successful exploit's blast radius is bounded.

## Mass assignment (CWE-915)

Bind requests onto an explicit input DTO that only contains the fields the endpoint is meant to
accept — never bind directly onto the persistence/domain model, which usually has more fields
than the API should expose for writing:

```csharp
// Unsafe: binds every property the client sends, including ones never meant to be settable.
[HttpPost] public IActionResult Update(User user) { _db.Update(user); ... }
// Safe: an explicit DTO with only the fields this endpoint should accept.
[HttpPost] public IActionResult Update(UpdateUserRequest req) {
    user.DisplayName = req.DisplayName;   // explicit, field-by-field
    ...
}
```

If the framework supports it, an explicit allowlist/`[Bind(include: ...)]` attribute on the
binding target is an acceptable alternative to a separate DTO, but a DTO is harder to accidentally
widen later (a new field added to the domain model does not silently become bindable).

## Verify

1. Reproduce the original finding: for native deserialization, a payload built with the reported
   gadget chain (or the advisory's PoC) should now fail to deserialize/execute rather than
   succeed. For mass assignment, a request that sets a restricted field should be rejected or
   silently ignore that field, not apply it.
2. Run the project's test suite, including a negative test asserting the restricted field(s) can't
   be set through the public endpoint.
3. Re-run whatever SAST/DAST tool originally flagged the finding, or re-scan the dependency
   through dependably if the issue was in a third-party package (`OSV_ID`, `PACKAGE_PURL`).
