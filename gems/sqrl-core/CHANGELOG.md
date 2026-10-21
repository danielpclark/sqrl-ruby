# Changelog

All notable changes to `sqrl-core` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Every gem in
the family shares one version number and is released in lockstep.

## [Unreleased]

## [0.1.2] - 2026-10-21

The server side now follows Steve Gibson's final specification (*SQRL On The Wire* v1.07,
December 2019) and his latest rulings in the `grc.sqrl` newsgroup (cited as
`grc.sqrl:<article>`); see `docs/protocol.md`.

### Changed

- The server returns `suk=` in the reply to every command when the client sends `opt=suk`,
  and always for a disabled account or a previous-identity match. It used to be returned on
  `query` only (a MUST: grc.sqrl:12289).
- A successful re-key replies with 0x01 set and 0x02 clear (the post-update state) and
  clears a disabled state along with the key update (grc.sqrl:20273; On The Wire p. 17).
- `disable` in CPS mode returns `url=` like every other non-query command.
- `sqrlonly` / `hardlock` are copied from every successful non-query command (`ident`,
  `enable`, `disable`), not from `ident` alone.
- A superseded identity is refused with exactly `0x240`.
- An unknown, expired or reused nut draws a transient error whose fresh nut is not
  registered, so the retry fails identically, which is the client's cue to have the user
  refresh the page (grc.sqrl:23543). Previously the retry "succeeded" against an anonymous
  pending login that no browser could ever complete.
- `PendingLogin#cps?` is new.

### Fixed

- Binary `sqrldata` files whose final byte happened to be an ASCII whitespace character
  (one in about forty, since the last block ends with a random AES-GCM tag) lost that byte on
  parse and failed with "block ... claims N bytes but only N-1 remain". Only leading
  whitespace is skipped before the header now; the `SQRLDATA` text form is still trimmed.

### Security

- `Handler#status` reports `authenticated: false` for a login the client completed in CPS
  mode, so a polling page can no longer be signed in on the strength of a same-device
  login: the specification requires that only the browser holding the one-time `url=`
  token is signed in.

## [0.1.1] - 2026-10-20

### Fixed

- Ed25519 and X25519 keys are built from their DER encodings when the openssl gem has no
  `OpenSSL::PKey.new_raw_private_key` / `new_raw_public_key` (openssl 3.0 and 3.1, bundled
  with Ruby 3.1 and 3.2). 0.1.0 raised `NoMethodError` on those Rubies as soon as an
  identity was derived, signed or verified.

## [0.1.0] - 2026-10-20

First release.

### Added

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

[Unreleased]: https://github.com/danielpclark/sqrl-ruby/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/danielpclark/sqrl-ruby/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/danielpclark/sqrl-ruby/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/danielpclark/sqrl-ruby/releases/tag/v0.1.0
