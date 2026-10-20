# Proposal: SQRL for APIs (phase 2, P4.1)

Status: draft for discussion. Nothing in this document is implemented; the protocol core
was shaped so that it can be, as a new transport in `sqrl-client` and a middleware in
`sqrl-rack`, without touching the existing flows.

## Problem

SQRL authenticates a *browser session*: the outcome of a transaction is a logged-in cookie.
Machine clients (bots, mobile apps calling a JSON API, service-to-service calls) want a
credential they can present on each request, with no browser and no cookie jar.

## Goals

- Reuse the existing identity, keys and signatures unchanged: the same `idk` identifies
  the caller, the same `ids` proves possession.
- Replay-safe: every signed request is bound to a server-issued, single-use challenge, or
  to a short-lived token obtained from one.
- No new cryptography. Ed25519 over data the server can reconstruct.
- Works through the existing stores and the `Handler` verification order.

## Two layers

### Layer 1 – signed challenge per call (stateless clients)

```
GET  /sqrl/api/nut                      → { "nut": "…", "server": "<b64u>", "expires_in": 60 }
POST /api/anything
     Authorization: SQRL client="<b64u>", server="<b64u>", ids="<b64u>"
```

The `client` list is the normal one with `cmd=query`… no: a new command would break
existing servers' `FUNCTION_NOT_SUPPORTED` rule only on this endpoint, so the proposal uses
`cmd=api` **only** on the API endpoint, never on `/sqrl/cli`. `server` is the challenge the
server issued (its own base64url string, which it stores against the nut as
`expected_server`, exactly like a login page URL). The server verifies the header with the
existing nut/echo/signature checks, consumes the nut, and resolves `idk` to an account.
Every call needs a fresh nut, so this layer costs one extra round trip per request and is
meant for low-volume automation.

### Layer 2 – token exchange (sessions for machines)

```
POST /sqrl/api/token     (body: the Layer-1 signed challenge)
     → { "access_token": "…", "token_type": "Bearer", "expires_in": 3600, "idk": "…" }
Authorization: Bearer …  on subsequent calls
```

The token is opaque to the client, random (≥ 256 bits), stored hashed with its `idk`,
expiry and scope, revocable, and rotated by repeating the exchange. This is ordinary
bearer-token hygiene; what SQRL adds is that *obtaining* the token needs no shared secret.

## Account mapping and policy

Identity → account resolution is the same as for logins (`IdentityStore#find`, `user_ref`).
Unknown identities are refused on the API (no account creation without a browser), unless
the site opts in. `sqrlonly`/`hardlock` have no meaning here. `disabled` identities are
refused. Superseded identities are refused; re-keying stays a browser flow.

## Open questions for the community

1. Should the challenge be the response of a `query` on `/sqrl/cli` (reusing the existing
   endpoint and a `cps`-like `url=` carrying the API token), or a separate endpoint as
   above? The separate endpoint keeps browser semantics untouched; reusing `cli` keeps one
   verification path.
2. Should the signed header include the request method and path (and a body hash), making
   the signature a request signature rather than a login proof? That prevents a captured
   header being replayed within its nut lifetime against a different route.
3. Nut lifetime for API challenges (60 s proposed) and whether one nut may authorise a
   small burst of requests (a counter) for bulk clients.

## Prototype plan (after agreement)

- `sqrl-core`: `Command::API` recognised only when `Config#api_enabled`; `Handler#handle_api`
  returning the resolved identity without pending-login side effects.
- `sqrl-rack`: `SQRL::Rack::API` middleware exposing `/sqrl/api/nut`, `/sqrl/api/token`, and
  an `env["sqrl.api.identity"]` for downstream apps; token store interface + memory/AR/Redis.
- `sqrl-client`: `Agent#api_challenge(url)`, `Agent#api_token(url)`, a transport decorator
  that signs or bears automatically; CLI `sqrl-client api-token URL`.
- Conformance cases for the API layer.
