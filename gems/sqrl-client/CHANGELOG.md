# Changelog

All notable changes to `sqrl-client` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Every gem in
the family shares one version number and is released in lockstep.

## [Unreleased]

## [0.1.2] - 2026-10-21

### Changed

- After a transient error the agent retries with the fresh nut and stops as soon as two
  successive replies carry the identical TIF, raising `LoginFailed` (reason `:transient`)
  with GRC's "The SQRL login page has expired" message, as Gibson specified
  (grc.sqrl:23543). `max_transient_retries` remains as an upper bound.
- The conformance runner's `transient_recovery` case accepts both conforming server
  behaviours: recovery on retry, or the identical repeated transient error.
- Requires sqrl-core 0.1.2.

## [0.1.1] - 2026-10-20

### Changed

- Requires sqrl-core 0.1.1, which fixes the `NoMethodError` on Ruby 3.1 and 3.2. No other
  changes.

## [0.1.0] - 2026-10-20

First release.

### Added

- `SQRL::Client::Agent`: login, query, disable, enable, remove against any SQRL site, with
  login-page discovery, previous-identity handling, `ask` and `sin` answering, transient
  retry and CPS handoff on the same cookie jar.
- Identities: S4 files, textual identities, ephemeral identities, environment loading,
  rekey and password change.
- `SQRL::Client::Transport` (Net::HTTP, cookie jar, TLS options; plain HTTP refused unless
  `insecure: true`), `SQRL::Client::Capybara` helper, and the `sqrl-client` executable with
  Netscape/JSON cookie export.
- A 23-case server conformance suite usable from Ruby, RSpec (`it_behaves_like "a SQRL
  server"`) and the command line, with JUnit output.
- Requires Ruby 3.1+ and `http-cookie`.

[Unreleased]: https://github.com/danielpclark/sqrl-ruby/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/danielpclark/sqrl-ruby/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/danielpclark/sqrl-ruby/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/danielpclark/sqrl-ruby/releases/tag/v0.1.0
