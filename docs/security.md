# Security notes

This document is the threat model and deployment checklist for the `sqrl-*` gems. The
protocol-level requirements are enforced in `sqrl-core`; the items under "Deployment" are
the operator's responsibility.

## What SQRL protects against, and what it does not

SQRL replaces passwords with per-site Ed25519 key pairs derived from one master secret.
A site never receives anything it could replay against another site, there is nothing to
phish in the usual sense, and a breach of the site's database yields public keys only.

SQRL does **not** protect against malicious software on the user's own device, nor
against a user who is tricked into authenticating a login page they did not open. The
second case is the one the server-side design works hardest on; see "Login binding".

## Protocol enforcement in `sqrl-core`

Every request to the SQRL endpoint goes through `SQRL::Server::Handler#handle`, which
checks, in this order and before any state change:

1. The nut exists, has not expired, and has not been used. Consumption is atomic in every
   store implementation (compare-and-set in memory, `UPDATE … WHERE used_at IS NULL` in
   ActiveRecord, `GETDEL` or Lua in Redis).
2. The form carries `client`, `server` and `ids`; `server` equals, byte for byte, the value
   this server issued for that nut (the original `sqrl://` URL or the previous response).
3. `client` decodes, declares a supported version, a known command and a 32-byte `idk`.
4. `ids` verifies under `idk` over `client || server`; when `pidk` is present, `pids` must
   be present and verify too.
5. The identity matches the one bound to this transaction (`BAD_ID_ASSOCIATION` otherwise).
6. The request IP equals the IP that requested the login page, unless the client sent
   `noiptest`; a mismatch without `noiptest` answers a bare `COMMAND_FAILED`.
7. The identity is not superseded by a re-key (`IDENTITY_SUPERSEDED` otherwise).

Only then is the command executed. `urs` is verified under the stored VUK (or the previous
identity's VUK during a re-key) for `enable`, `remove` and re-keying. All comparisons of
secrets and signatures are constant time.

On the client side (`SQRL::Session` and `sqrl-client`): TIF bits outside protocol version 1
abort the transaction; `qry` must be a server-relative path; the CPS `url=` and any
`can=` must point at the site's host over HTTPS; `ask` button URLs are forced onto the
site's origin. Plain HTTP is refused unless the caller opts into the loopback-only
`insecure` testing mode (see "Plain HTTP" below).

## Login binding

A *pending login* is created when a login page is rendered. Its id lives only in the
browser's session cookie. The SQRL client never sees it; the nut maps to it server-side.

Completing a login requires one of two things:

- **CPS (same device).** The server hands the client a one-time, 32-byte random token in
  `url=`; the client sends the browser there. The token is claimed exactly once, expires
  after `cps_token_ttl` (60 s), and must belong to the pending login in *that browser's*
  session. A token stolen from one browser cannot log in another. A login the client flagged
  `cps` is *never* completed through the poll below: the specification says the server "MUST
  NOT authenticate the browser session" in that case, because the page that showed the login
  link may be a spoof. Only the browser the client redirects to the token gets in.
- **Poll (other device).** The browser's script polls a cookie-bound status endpoint. The
  pending login completes once, from the browser that owns it. The protocol's own IP check
  applies (`require_ip_match`: a client whose IP differs from the browser's is refused
  unless it sends `noiptest`). The pending login also records whether the IPs matched
  (`ip_matched`); the optional `poll_requires_ip_match: true` refuses poll completions
  when they did not, which blocks a relayed-QR attack against a `noiptest` client but
  also blocks legitimate phone logins from another network. It is off by default.

Unknown identities follow `on_unknown_identity`: `:create` an account (SQRL's default
story), `:link` to the already signed-in user, or `:refuse`.

## Stores

The three store interfaces (`NutStore`, `IdentityStore`, `PendingLoginStore`) carry the
single-use guarantees. Implementations must make `consume` and `claim_cps_token` atomic
under concurrency; the shared store-contract spec in `sqrl-core` exercises exactly that.
The in-memory stores are for development and tests only: they are per process and lose
every association on restart.

## Deployment checklist

- Set `host` explicitly in production. It is the string every identity key is derived
  from; a change (or a spoofed `Host` header) breaks or misdirects associations.
- Serve the site over HTTPS. SQRL URLs are always `sqrl://`, which means HTTPS; the gems
  never derive a scheme from the request.
- Use a persistent, atomic store (ActiveRecord, Redis, or an `ActiveSupport::Cache` store
  with atomic delete). Never the memory stores.
- Keep `require_ip_match` on (it is the protocol's check). Turn `poll_requires_ip_match`
  on only if your users log in from the same network as their browser.
- Prune: run `sqrl:prune` (Rails) or `Handler#prune!` regularly, or set `prune_every`.
- Rate-limit the login page and the SQRL endpoint (`before_issue` / `before_handle`
  hooks, Rails `rate_limit`, or Rack::Attack). Each login page view creates a nut and a
  pending login.
- The SQRL endpoint is exempt from CSRF protection by design (it is authenticated by
  signatures). Keep every other route protected.
- When a user's identity requested `sqrlonly` or `hardlock`, disable password login and
  password recovery for that account (see the Rails and Devise guides). The client sends
  these flags because the user asked for them.
- Log protocol failures (TIF values are safe to log); never log nuts, tokens, `server=`
  echoes or key material. The gems' `inspect` output is redacted for that reason.

## Plain HTTP

Final SQRL has one scheme, `sqrl://`, and it means HTTPS. Early drafts also had `qrl://`
for plain HTTP; that was dropped, and GRC's client does not honour it. The gems keep a
loopback-only testing mode for the browser extension's local flow: `insecure_http: true`
on the server (issues `qrl://` for `localhost`/`127.0.0.1` only, logs a warning, refuses any
other host) and `insecure: true` on the client. Nothing enables it implicitly. The example
applications and the integration suite run over HTTPS with a self-signed certificate.

## Reporting

Security issues: open a private report to the repository owner rather than a public issue.
