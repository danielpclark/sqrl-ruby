# Changelog

All notable changes to `sqrl-rails` are documented in this file.

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

- Isolated engine serving the SQRL endpoint, status poll, CPS/poll callback, login page,
  script, refresh endpoint and identity-management pages.
- ActiveRecord stores (`sqrl_identities`, `sqrl_nuts`, `sqrl_pending_logins`) with atomic
  single use, plus an `ActiveSupport::Cache` store set.
- `bin/rails generate sqrl:install`: migration, mount, initializer, user association,
  login block in `sessions/new`, password-policy includes.
- Sign-in adapter for the Rails 8 `generate authentication` concern, with Warden and plain
  session fallbacks; `:create` / `:link` / `:refuse` policies for unknown identities.
- `sqrlonly` / `hardlock` enforcement for password login and reset; identity management;
  per-IP rate limiting; `ask` with deny button; `allowed_hosts`, hooks, `prune` task.
- `insecure_http` testing mode; `poll_requires_ip_match` off by default.
- Requires Ruby 3.2+ and Rails 7.1, 7.2, 8.0 or 8.1.

[Unreleased]: https://github.com/danielpclark/sqrl-ruby/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/danielpclark/sqrl-ruby/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/danielpclark/sqrl-ruby/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/danielpclark/sqrl-ruby/releases/tag/v0.1.0
