---
name: hex-configure-global
description: Point Mix or Rebar3 at a dependably Hex repository, with origin verification against its public key
ecosystem: hex
scope: global
inputs:
  - DEPENDABLY_BASE_URL
  - DEPENDABLY_TOKEN
---

## When to use this

You want `mix deps.get` or `rebar3 get-deps` to resolve BEAM packages through
your dependably instance. Both clients register a repository in the user's own
configuration (`~/.hex` for Mix, `~/.config/rebar3/rebar.config` for Rebar3), so
there is no per-repository file — this one recipe covers every project on the
machine.

## Inputs

Ask the user for:

1. **DEPENDABLY_BASE_URL** — the base URL of your dependably org, e.g.
   `https://repo.example.com`. Tenancy is host-resolved: single-tenant
   deployments use the bare host; multi-tenant deployments put the org in the
   subdomain (`https://my-org.repo.example.com`). The Hex read plane is at
   `/hex` and the API plane at `/hex/api`.
2. **DEPENDABLY_TOKEN** — created in dependably under **Tokens**. Resolving
   needs the **pull** preset; publishing needs **push**.

## The repository must be named `dependably`

Every Hex client verifies two things about each registry resource: the RSA
signature against the public key the repository was registered with, and the
repository **name** embedded in the signed payload against the name it was
registered under. Dependably signs under the fixed name `dependably`, so
registering it locally under any other name fails origin verification on every
single fetch. Do not rename it.

## Configure — Mix (Elixir)

```bash
curl -sSf https://repo.example.com/hex/public_key -o dependably-hex.pem
mix hex.repo add dependably https://repo.example.com/hex \
  --public-key dependably-hex.pem \
  --auth-key <token>
```

Then declare a dependency against the repo in `mix.exs`:

```elixir
{:my_dep, "~> 1.0", repo: :dependably}
```

Publishing additionally needs the API plane and an API key in the environment:

```bash
export HEX_API_URL=https://repo.example.com/hex/api
export HEX_API_KEY=<token>
mix hex.publish
```

## Configure — Rebar3 (Erlang)

Add to `~/.config/rebar3/rebar.config`:

```erlang
{hex, [{repos, [
  #{name => <<"dependably">>,
    repo_url => <<"https://repo.example.com/hex">>,
    api_url => <<"https://repo.example.com/hex/api">>,
    repo_key => <<"<token>">>,
    api_key => <<"<token>">>,
    repo_public_key => <<"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----">>}
]}]}.
```

Fetch the public key to paste in with:

```bash
curl -sSf https://repo.example.com/hex/public_key
```

Substitutions for both clients:
- Replace `https://repo.example.com` with `DEPENDABLY_BASE_URL`.
- Replace `<token>` with `DEPENDABLY_TOKEN`.

The Rebar3 file **holds the token in clear text**. It lives in your home
directory, not a repository — keep it that way and restrict it:

```bash
chmod 600 ~/.config/rebar3/rebar.config
```

> **HTTP gotcha.** Both clients will talk to a plain-`http://` repository, so the
> token travels in clear text on every request. Use it only on a trusted network,
> or terminate TLS in front of dependably.

## Verify it works

Mix:

```bash
mix hex.repo list      # dependably appears with its URL and public key
mix deps.get
```

Rebar3:

```bash
rebar3 update
rebar3 get-deps
```

Publishing: `mix hex.publish` or `rebar3 hex publish --repo dependably`.

A `mismatched repository name` or signature error on the first fetch means the
repository was registered under a name other than `dependably`, or against the
wrong public key — re-add it with the two values above.

## Reverting

Mix:

```bash
mix hex.repo remove dependably
```

Rebar3: delete the `{hex, [{repos, ...}]}.` block from
`~/.config/rebar3/rebar.config`.
