# Changelog

## 0.1.1 — 2026-10-20

- No changes. Released with sqrl-core 0.1.1, which fixes the `NoMethodError` on Ruby 3.1
  and 3.2; every gem in the family shares one version.

## 0.1.0 — 2026-10-20

First release.

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
