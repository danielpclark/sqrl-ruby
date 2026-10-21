# Rack, Sinatra and Roda

Gem: `sqrl-rack`. Examples: `examples/rack-app`, `examples/sinatra-app`, `examples/roda-app`.

## Rack

```ruby
use Rack::Session::Cookie, secret: ENV.fetch("SESSION_SECRET"), same_site: :lax
use SQRL::Rack::Middleware,
    stores: SQRL::Server::Memory.stores,
    host: "example.com",
    on_login: ->(env, identity, pending_login) { env["rack.session"]["user_id"] = identity.idk_b64 },
    after_login: "/"
```

The middleware owns `POST /sqrl/cli`, `GET /sqrl/status`, `GET /sqrl/callback`,
`GET /sqrl/refresh` and `GET /sqrl/sqrl.js`. Every other request receives
`env["sqrl.server"]`, a facade with `login_url`, `login_block`, `script_tag`, `qr_svg`,
`refresh_url`, `identity`, `authenticated?` and `logout!`. Without `on_login`, the identity
key is stored in the session under `sqrl.identity` and `authenticated?` reads it back.

Every `SQRL::Server::Config` option passes through (`ask`, `sin`, `require_ip_match`,
`allowed_hosts`, `before_issue`, `before_handle`, `prune_every`, …), plus the middleware's
own `poll_requires_ip_match` (default off), `host_cache_limit`, `failure_path` and
`insecure_http`. The gem README has the full tables.

## Sinatra

```ruby
class App < Sinatra::Base
  enable :sessions
  register Sinatra::SQRL
  set :sqrl, host: "example.com", stores: SQRL::Server::Memory.stores

  sqrl_on_login { |identity, env| env["rack.session"]["user"] = identity.idk_b64 }

  get("/login") { erb :login }   # <%= sqrl_login_block %>
end
```

Helpers: `sqrl_login_url`, `sqrl_qr_svg`, `sqrl_script_tag`, `sqrl_login_block`,
`sqrl_authenticated?`, `current_sqrl_identity`, `sqrl_logout!` and `sqrl` (the facade).
Sessions must be enabled; `set :sqrl` may come before or after `register` because the
options are read on the first request.

## Roda

```ruby
require "roda/plugins/sqrl"

class App < Roda
  use Rack::Session::Cookie, secret: ENV.fetch("SESSION_SECRET"), same_site: :lax
  plugin :sqrl, host: "example.com", stores: SQRL::Server::Memory.stores

  sqrl_on_login { |identity, env| env["rack.session"]["user"] = identity.idk_b64 }

  route do |r|
    r.get("login") { sqrl_login_block }
    r.root { sqrl_authenticated? ? "Hello #{current_sqrl_identity.idk_b64}" : r.redirect("/login") }
  end
end
```

`plugin :sqrl` takes every middleware option and adds the same helpers as the Sinatra
extension. The session must come from a Rack session middleware added with `use` before the
plugin; Roda's own `sessions` plugin runs inside the routing tree, after the middleware, and
cannot be used for this. `roda` itself is not a dependency of `sqrl-rack`.

## Notes

- Sinatra's `Rack::Protection` lets the token-less SQRL POST through (the request has no
  Referer and no session-changing effect at the app level); the middleware rebuilds the
  form body if a protection layer consumed `rack.input`.
- URLs are always `sqrl://` (HTTPS). For local development either terminate TLS in front
  of the app (the examples and the integration suite use a self-signed certificate) or opt
  into the non-standard loopback-only plain-HTTP mode with `insecure_http: true`, which
  only the browser extension's test flow understands.
