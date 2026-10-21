# Changelog

## 0.1.1 — 2026-10-20

- Fixed: Ed25519 and X25519 keys are built from their DER encodings when the openssl gem
  has no `OpenSSL::PKey.new_raw_private_key` / `new_raw_public_key` (openssl 3.0 and 3.1,
  bundled with Ruby 3.1 and 3.2). 0.1.0 raised `NoMethodError` on those Rubies as soon as
  an identity was derived, signed or verified.

## 0.1.0 — 2026-10-20

First release.

- Complete SQRL wire protocol: `query`, `ident`, `disable`, `enable`, `remove`, every TIF
  bit, `ask`/`btn` with a server-side accept-list, `sin`/`ins`/`pins`, previous identities
  and re-keying, `x=` path extension, Alt-IDs, `can=`, Client Provided Session.
- Cryptography on OpenSSL only: EnHash, EnScrypt, AES-256-GCM, Ed25519, X25519.
- S4 identity files (type 1/2/3, binary and text), rescue codes, password changes,
  re-keying, base56 textual identities; all published test vectors pass and GRC's reference
  client request bodies are reproduced byte for byte.
- `SQRL::Session`: the client transaction state machine; `sqrl://` (HTTPS) only unless
  `insecure: true` (loopback testing mode).
- `SQRL::Server::Handler` with `Config`, three store interfaces, in-memory and Redis store
  sets, one-time CPS tokens, nut single use, `server=` echo verification, IP matching
  (`require_ip_match`, on by default), `allowed_hosts`, `prune_every`, `before_issue` /
  `before_handle` hooks and `SQRL::Server::RateLimited`.
- A shared store-contract spec for store implementations.
- Requires Ruby 3.1 or newer.
