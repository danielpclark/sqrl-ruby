# Changelog

All notable changes to `omniauth-sqrl` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Every gem in
the family shares one version number and is released in lockstep.

## [Unreleased]

## [0.1.2] - 2026-10-21

### Changed

- Requires sqrl-core and sqrl-rack 0.1.2. sqrl-core fixes binary S4 identity files whose
  last byte is whitespace being truncated on parse and brings the server into line with
  Steve Gibson's final specification (`suk=` on every command, the post-update TIF after a
  re-key, `url=` on a CPS `disable`, and more). No code changes in this gem.

### Security

- Through sqrl-rack 0.1.2, a login the SQRL client completed in CPS mode can no longer be
  completed through the browser's status poll; only the browser holding the one-time
  `url=` token is signed in, as the specification requires.

## [0.1.1] - 2026-10-20

### Changed

- Requires sqrl-core 0.1.1, which fixes the `NoMethodError` on Ruby 3.1 and 3.2. No other
  changes.

## [0.1.0] - 2026-10-20

First release.

### Added

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

[Unreleased]: https://github.com/danielpclark/sqrl-ruby/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/danielpclark/sqrl-ruby/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/danielpclark/sqrl-ruby/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/danielpclark/sqrl-ruby/releases/tag/v0.1.0
