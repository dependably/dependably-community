---
name: fix-xss
description: Remediate Cross-Site Scripting findings (CWE-79/80/83/86 — OWASP A05:2025 Injection) with context-aware output encoding, auto-escaping templates, DOM-sink sanitization, and a Content-Security-Policy.
category: remediation
cwe:
  - CWE-79
  - CWE-80
  - CWE-83
  - CWE-86
inputs:
  - OSV_ID
  - PACKAGE_PURL
  - FIXED_VERSION
---

## When to use this

Untrusted input is rendered into a web page (server-rendered HTML, a client-side template, or a
raw DOM write) and the browser executes it as markup or script instead of displaying it as text.
XSS is reflected (input echoed straight back in the response), stored (input saved and rendered
later for other users), or DOM-based (client-side JavaScript writes untrusted data into the DOM
without going through the server at all).

If the finding is in a third-party dependency and `FIXED_VERSION` is set, apply the
`fix-vulnerable-dependency` skill first. Use this skill when the XSS is in your own rendering
code, or the fixed dependency version still needs its output-encoding call sites reviewed.

## Core principle

Encode output for the context it lands in, at the point it is written — not once, generically, on
the way in. HTML-body text, HTML attributes, JavaScript string literals, and URLs each have
different characters that need escaping; encoding for the wrong context (e.g., HTML-encoding
something written into a `<script>` block) does not prevent the attack.

## Prefer an auto-escaping template engine

Every mainstream server-side template engine escapes interpolated values by default — the fix is
almost always to stop bypassing that default, not to hand-roll encoding:

```jinja2
{# Jinja2/Django: autoescape is on by default — don't do this: #}
{{ user_bio | safe }}
{# Do this — let the default escaping apply: #}
{{ user_bio }}
```

```jsx
// React/JSX escapes {expression} content by default — avoid the raw-HTML escape hatch:
<div>{userBio}</div>              {/* safe: escaped */}
<div dangerouslySetInnerHTML={{ __html: userBio }} />   {/* unsafe unless userBio is sanitized */}
```

```svelte
<!-- Svelte escapes {expression} by default: -->
<p>{userBio}</p>          <!-- safe: escaped -->
<p>{@html userBio}</p>    <!-- unsafe unless userBio is sanitized -->
```

If the raw-HTML escape hatch (`| safe`, `dangerouslySetInnerHTML`, `{@html ...}`,
`v-html`, `innerHTML =`) is genuinely required because the value legitimately contains HTML
(a rich-text field), sanitize it through an allowlist HTML sanitizer immediately before render —
DOMPurify on the client, or an equivalent allowlist-based sanitizer server-side. Never sanitize by
denylisting tags/attributes; allowlist what's permitted and strip everything else.

## Context-specific encoding when a template engine isn't in play

- **HTML body**: encode `< > & " '` (HTML entity encoding).
- **HTML attribute value**: HTML-entity-encode, and always quote the attribute — unquoted
  attributes are exploitable with just a space character.
- **Inside a `<script>` block or inline event handler**: do not interpolate untrusted data here at
  all if avoidable; if unavoidable, JSON-encode the value and JS-string-escape it, then verify the
  result can't close out of the string literal.
- **URL context** (`href`, `src`, `action`): percent-encode the value, and validate the scheme
  against an allowlist (`http`/`https`) — `javascript:` and `data:` URLs are a common XSS vector
  when a user controls a link target.

## DOM-based XSS

Treat the same sinks as dangerous when written to from client-side JavaScript, not just from
server templates: `element.innerHTML =`, `document.write()`, `eval()`, `setTimeout(string)`,
`location.href =` with unvalidated schemes. Prefer `textContent`/`innerText` for plain text, and
DOM APIs (`createElement`, `setAttribute` with a validated value) for structured content instead
of building HTML strings.

## Content-Security-Policy as defense in depth

A strict CSP (`script-src 'self'`, no `unsafe-inline`, no `unsafe-eval`) does not fix the
underlying encoding bug, but it stops many XSS payloads from executing even if one slips through —
add it if the app doesn't already send one. Cookie flags (`HttpOnly`, `Secure`, `SameSite`) limit
the blast radius of a successful XSS by keeping session cookies out of reach of injected script.

## Verify

1. Reproduce the original payload (e.g., `<script>alert(1)</script>`, or an attribute-breakout
   payload like `" onmouseover="alert(1)`) against the fixed render path and confirm it renders as
   inert text, not executable markup.
2. If a sanitizer was added, confirm it strips `<script>`, event-handler attributes (`onerror`,
   `onload`, ...), and `javascript:`/`data:` URLs, while preserving the legitimate rich-text
   subset the feature needs.
3. Run the project's test suite, including any existing XSS regression tests for the endpoint.
4. Re-run whatever SAST/DAST tool originally flagged the finding, or re-scan the dependency
   through dependably if the XSS was in a third-party package (`OSV_ID`, `PACKAGE_PURL`).
