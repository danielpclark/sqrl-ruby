# Changelog

All notable changes to `sqrl-rack` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Every gem in
the family shares one version number and is released in lockstep.

## [Unreleased]

## [0.1.2] - 2026-10-21

### Changed

- Requires sqrl-core 0.1.2 (protocol conformance fixes and the S4 trailing-byte fix; see its
  changelog).

### Security

- A login the SQRL client completed in CPS mode (`opt=cps`) can no longer be completed
  through the browser's status poll or a token-less callback. The specification requires the
  server not to sign in the browser that displayed the login page in that case, because that
  page may be a spoof; only the browser the client redirects to the one-time `url=` token is
  signed in.

## [0.1.1] - 2026-10-20

### Changed

- Requires sqrl-core 0.1.1, which fixes the `NoMethodError` on Ruby 3.1 and 3.2. No other
  changes.

## [0.1.0] - 2026-10-20

First release.

### Added

- `SQRL::Rack::Middleware`: the SQRL endpoint, cookie-bound status poll, CPS and poll
  callbacks, `sqrl.js` and a refresh endpoint, with a request facade (`env["sqrl.server"]`).
- `Sinatra::SQRL` extension and a Roda `plugin :sqrl` with the same helpers.
- `SQRL::Rack::LoginBlock` (accessible markup with a server-side SVG QR code) and
  `sqrl.js` (same-device probe on `localhost:25519`, polling with back-off, DOM events,
  `SQRL.refresh`).
- `SQRL::Rack::HostResolver`: explicit `host`, `allowed_hosts`, a bounded per-host cache.
- Always issues `sqrl://`; `insecure_http: true` is a loopback-only testing mode.
- `poll_requires_ip_match` (off by default) and 429 handling for rate-limit hooks.
- Requires Ruby 3.1+, Rack 2.2 or 3.x, `rqrcode`.

[Unreleased]: https://github.com/danielpclark/sqrl-ruby/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/danielpclark/sqrl-ruby/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/danielpclark/sqrl-ruby/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/danielpclark/sqrl-ruby/releases/tag/v0.1.0
