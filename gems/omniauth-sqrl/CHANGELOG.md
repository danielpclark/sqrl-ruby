# Changelog

## 0.1.2 — 2026-10-21

- No changes; released in lockstep with sqrl-core 0.1.2 (fixes binary S4 identity files whose last byte is whitespace being truncated on parse).

## 0.1.1 — 2026-10-20

- No changes. Released with sqrl-core 0.1.1, which fixes the `NoMethodError` on Ruby 3.1
  and 3.2; every gem in the family shares one version.

## 0.1.0 — 2026-10-20

First release.

- `provider :sqrl`: request phase renders the login page; the strategy serves the SQRL
  endpoint, status poll, script and refresh routes itself; the callback builds an auth hash
  keyed by the identity key with `extra["sqrl"]` facts (created, re-keyed from, options,
  disabled, via).
- Failure keys `invalid_credentials` and `sqrl_disabled`; `link_user_ref` for account
  linking; `info:` callable; test mode supported.
- Host handling (`allowed_hosts`, bounded cache), rate-limit hooks, `insecure_http`
  testing mode, `poll_requires_ip_match` (off by default).
- Works with `devise :omniauthable`.
- Requires Ruby 3.1+, OmniAuth 2.x.
