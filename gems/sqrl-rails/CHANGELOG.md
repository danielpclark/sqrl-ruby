# Changelog

## 0.1.2 — 2026-10-21

- No changes; released in lockstep with sqrl-core 0.1.2 (fixes binary S4 identity files whose last byte is whitespace being truncated on parse).

## 0.1.1 — 2026-10-20

- No changes. Released with sqrl-core 0.1.1, which fixes the `NoMethodError` on Ruby 3.1
  and 3.2; every gem in the family shares one version.

## 0.1.0 — 2026-10-20

First release.

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
