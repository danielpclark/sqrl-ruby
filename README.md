# SQRL Login for Ruby

[SQRL](https://www.grc.com/sqrl/sqrl.htm) (Secure Quick Reliable Login) for the Ruby
ecosystem: a pure-Ruby protocol core, server-side integrations that give existing login
systems SQRL support with one gem and one line of configuration, and a bot-capable client
that logs in to SQRL-enabled websites from scripts and test suites.

| Gem | Require | Use it when | Quick start |
| --- | --- | --- | --- |
| [`sqrl-core`](gems/sqrl-core) | `require "sqrl/core"` (or `"sqrl"`) | you need the protocol, the cryptography or the identity formats directly | `SQRL::Session`, `SQRL::Server::Handler`, `SQRL::S4Identity` |
| [`sqrl-rack`](gems/sqrl-rack) | `require "sqrl/rack"` | a Rack application or Sinatra | `use SQRL::Rack::Middleware` / `register Sinatra::SQRL` |
| [`omniauth-sqrl`](gems/omniauth-sqrl) | `require "omniauth/sqrl"` | you already use OmniAuth | `provider :sqrl` |
| [`sqrl-rails`](gems/sqrl-rails) | `require "sqrl/rails"` | Rails, including the Rails 8 `generate authentication` stack | `bin/rails generate sqrl:install` |
| [`devise-sqrl`](gems/devise-sqrl) | `require "devise/sqrl"` | Devise | `devise :sqrl_authenticatable` |
| [`sqrl-client`](gems/sqrl-client) | `require "sqrl/client"` | bots, automation, tests; checking a server's conformance | `SQRL::Client::Agent.new(identity:).login(url)` |

Names follow the RubyGems convention: the dash marks a gem that extends another library or
namespace and maps to the require path (`sqrl-rack` is `sqrl/rack`, `SQRL::Rack`). Bundler's
auto-require resolves each of them that way, so a plain `gem "..."` line is enough.

All six gems share one version and live in this repository. The implementation plan is in
[docs/PLAN.md](docs/PLAN.md); per-framework guides are in [docs/integrations](docs/integrations);
the threat model and deployment checklist are in [docs/security.md](docs/security.md) and the
protocol summary in [docs/protocol.md](docs/protocol.md).

## What is implemented

- The complete SQRL client/server wire protocol (`query`, `ident`, `disable`, `enable`,
  `remove`, `ids`/`pids`/`urs` signatures, every TIF bit, `ask`/`btn`, `sin`/`ins`,
  previous identities and re-keying, the `x=` path extension, Alt-IDs, `can=`, Client
  Provided Session), following GRC's final specification and reproducing GRC's reference
  client request bodies byte for byte.
- EnScrypt, EnHash, the identity lock (SUK/VUK/URSK), S4 identity files (type 1, 2 and 3
  blocks), rescue codes and the base56 textual identity, verified against every published
  test vector. Everything is built on Ruby's bundled `openssl` gem; the core has no other
  runtime dependency.
- A server engine whose state sits behind nut, identity and pending-login store interfaces
  (in-memory and ActiveRecord implementations), with nut single use, IP matching, browser
  session binding and one-time CPS tokens.
- A browser script (`sqrl.js`) that performs the standard same-device probe on
  `localhost:25519` and polls for logins from another device, plus server-side QR codes.
- A bot client with login-page discovery, a cookie-carrying transport, a Capybara helper, a
  command-line tool and a 23-case conformance suite.

## Development

```sh
bundle install
bundle exec rake spec:gems          # every gem's specs
bundle exec rake spec:integration   # boots each example app and drives it with the bot client and a headless browser
bundle exec rspec spec/interop      # the conformance suite against the Rust reference server (needs its binary)
```

Each application under [`examples/`](examples) is a complete, independently bundled
application of its framework (`bin/dev` starts it). The integration specs start every one of
them on a free port and run the conformance suite, bot flows and browser flows against it.

Ruby 3.1 or newer for `sqrl-core`, `sqrl-rack`, `omniauth-sqrl` and `sqrl-client`;
Ruby 3.2 or newer for `sqrl-rails` and `devise-sqrl`. One EnScrypt iteration takes about
45 ms with OpenSSL 3, so unlocking a real identity file takes a few seconds; tests use
ephemeral identities that skip EnScrypt.

## Credits and license

SQRL was designed by Steve Gibson of Gibson Research Corporation, who published the
specification into the public domain. The protocol and cryptography here are a port of the
Rust implementation in [SQRL-extension](https://github.com/danielpclark/SQRL-extension).

MIT License, Copyright (c) 2026 Daniel P. Clark. See [LICENSE](LICENSE).
