---
name: fix-injection
description: Remediate SQL, command, LDAP, XPath, and code-injection findings (CWE-20/74/77/78/89/90/91/94/95/... — OWASP A05:2025 Injection, excluding XSS) by moving to parameterized/safe APIs and validating input server-side.
category: remediation
cwe:
  - CWE-20
  - CWE-77
  - CWE-78
  - CWE-88
  - CWE-89
  - CWE-90
  - CWE-91
  - CWE-93
  - CWE-94
  - CWE-95
  - CWE-99
  - CWE-113
  - CWE-470
  - CWE-643
  - CWE-917
inputs:
  - OSV_ID
  - PACKAGE_PURL
  - FIXED_VERSION
---

## When to use this

The advisory or finding is a non-XSS injection class: untrusted input reaches an interpreter
(SQL, a shell, an LDAP or XPath query, a template/eval engine, a header-writing API) and changes
that interpreter's behavior instead of being treated as inert data. Use `fix-xss` instead for
cross-site scripting (CWE-79/80/83/86) — the injection mechanism is the same shape, but the
sink and fix (output encoding, not query parameterization) are different.

If the finding is in a third-party dependency and `FIXED_VERSION` is set, apply the
`fix-vulnerable-dependency` skill first — upgrading past the vulnerable version is almost always
the fastest fix when the injection bug is inside a library you consume rather than your own code.
Use this skill when the injection is in your own code, or when no fixed version exists yet and
you need to harden the call site regardless.

## Core principle

Keep data separate from commands and queries. Every recipe below is a version of that: never
build a query/command string by concatenating or interpolating untrusted input into it.

## SQL injection (CWE-89)

Use parameterized queries / prepared statements — never string-build SQL with user input, even
through an ORM's raw-query escape hatch.

```csharp
// C# / Dapper — parameters, not interpolation
await conn.QueryAsync<Order>(
    "SELECT * FROM orders WHERE customer_id = @id", new { id = customerId });
```

```python
# Python / psycopg2 — placeholders, not f-strings
cur.execute("SELECT * FROM orders WHERE customer_id = %s", (customer_id,))
```

```javascript
// Node / pg — placeholders, not template literals
await pool.query("SELECT * FROM orders WHERE customer_id = $1", [customerId]);
```

```java
// Java — PreparedStatement, not Statement + string concat
PreparedStatement ps = conn.prepareStatement("SELECT * FROM orders WHERE customer_id = ?");
ps.setLong(1, customerId);
```

Table names, column names, and `ORDER BY` directions cannot be parameterized — they are structure,
not data. If one must be dynamic, validate it against a hardcoded allowlist of known-safe values
before use; never pass the raw user string through, even escaped.

Hibernate/HQL, JPQL, and other query-language wrappers are not automatically safe — they support
the same parameter-binding syntax as raw SQL and must use it (`:param`, not string-concatenated
HQL).

## OS command injection (CWE-77/78/88)

Prefer an API that never invokes a shell: pass the program and its arguments as a list/array, not
a single string a shell re-parses.

```python
# Safe: argument array, no shell
subprocess.run(["nslookup", domain], check=True)
# Unsafe: shell=True re-interprets shell metacharacters in `domain`
subprocess.run(f"nslookup {domain}", shell=True)
```

```csharp
// Safe: ProcessStartInfo.ArgumentList, not a single Arguments string
var psi = new ProcessStartInfo("nslookup") { };
psi.ArgumentList.Add(domain);
```

If a shell is unavoidable, validate the input against a strict allowlist (e.g., a hostname regex)
before it reaches the command line — escaping shell metacharacters yourself is error-prone and not
robust to platform differences.

## LDAP injection (CWE-90) and XPath injection (CWE-643)

Use the parameterized/escaping API your LDAP or XML library provides for filter construction
(e.g., `LdapName`/`Rdn` builders, `javax.naming` escape helpers, XPath variable bindings) instead
of building filter/query strings by hand. As with SQL, if the library exposes a "build filter from
raw string" path, treat that as equivalent to raw SQL concatenation and avoid it for
untrusted input.

## Code/template/eval injection (CWE-94/95/96/917)

Never pass untrusted input to `eval`, dynamic `exec`, a template engine's raw-expression mode
(EL, OGNL, SpEL, Jinja2 `Template(user_string)`), or any deserializer/interpreter that executes
code as a side effect of parsing. If dynamic behavior is genuinely required, restrict it to a
closed, hardcoded set of operations selected by an enum/allowlist — never let the user string
itself become the code.

## CRLF / header injection (CWE-93/113)

Reject or strip `\r`/`\n` from any user-controlled value written into an HTTP header, log line, or
redirect target before writing it — a raw newline lets an attacker inject additional headers or
split the response. Most modern HTTP frameworks reject embedded CRLF in header values by default;
confirm yours does rather than assuming it.

## Defense in depth

- **Positive (allowlist) validation** on the server side for every untrusted input, even where a
  safe API is also used — belt and suspenders, and the only option for structural values (table
  names, sort directions) that can't be parameterized.
- **Least-privilege database accounts**: the app's DB user should not have permissions (DROP,
  cross-schema SELECT, etc.) beyond what the application actually needs, so a successful injection
  has a smaller blast radius.
- **Static/dynamic analysis in CI** (SAST/DAST/IAST) catches concatenated-query patterns before
  they reach production; it is a backstop, not a replacement for parameterization.

## Verify

1. Reproduce the original finding's payload against the fixed code path — the interpreter must
   receive the payload as inert data, not execute it.
2. Run the project's test suite, including any negative/security-focused tests for the endpoint.
3. Re-run whatever SAST/DAST tool originally flagged the finding, or re-scan the dependency
   through dependably if the injection was in a third-party package (`OSV_ID`, `PACKAGE_PURL`).
