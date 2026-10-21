# Changelog

## 0.1.2 — 2026-10-21

- No changes; released in lockstep with sqrl-core 0.1.2 (fixes binary S4 identity files whose last byte is whitespace being truncated on parse).

## 0.1.1 — 2026-10-20

- No changes. Released with sqrl-core 0.1.1, which fixes the `NoMethodError` on Ruby 3.1
  and 3.2; every gem in the family shares one version.

## 0.1.0 — 2026-10-20

First release.

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
