# Changelog

## 0.1.1 — 2026-10-20

- No changes. Released with sqrl-core 0.1.1, which fixes the `NoMethodError` on Ruby 3.1
  and 3.2; every gem in the family shares one version.

## 0.1.0 — 2026-10-20

First release.

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
