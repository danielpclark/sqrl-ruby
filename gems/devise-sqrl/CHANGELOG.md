# Changelog

All notable changes to `devise-sqrl` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Every gem in
the family shares one version number and is released in lockstep.

## [Unreleased]

## [0.1.2] - 2026-10-21

### Changed

- Requires sqrl-rails 0.1.2, and through it sqrl-core and sqrl-rack 0.1.2. sqrl-core fixes
  binary S4 identity files whose last byte is whitespace being truncated on parse and brings
  the server into line with Steve Gibson's final specification (`suk=` on every command, the
  post-update TIF after a re-key, `url=` on a CPS `disable`, and more). No code changes in
  this gem.

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

- `devise :sqrl_authenticatable`: routes under the mapping (`/users/sqrl`, `cli`, `status`,
  `callback`, `sqrl.js`, `refresh`, `identities`), a Warden strategy that signs in through
  Devise's own hooks (trackable, rememberable, activatable), a controller, views and a
  shared partial for `sessions/new`.
- `bin/rails generate devise:sqrl:install`.
- `sqrlonly` users cannot log in with a password (configurable blocked strategies);
  `hardlock` users cannot reset passwords.
- Identity management under the mapping; `ask` with deny button; 429/400 handling for
  rate-limit hooks and disallowed hosts.
- Requires Ruby 3.2+, Devise 4.9 or 5.0, Rails 7.1 to 8.1, and `sqrl-rails`.

[Unreleased]: https://github.com/danielpclark/sqrl-ruby/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/danielpclark/sqrl-ruby/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/danielpclark/sqrl-ruby/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/danielpclark/sqrl-ruby/releases/tag/v0.1.0
