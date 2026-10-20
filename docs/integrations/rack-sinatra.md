# Rack and Sinatra

Gem: `sqrl-rack`. Examples: `examples/rack-app`, `examples/sinatra-app`.

## Rack

```ruby
use Rack::Session::Cookie, secret: ENV.fetch("SESSION_SECRET"), same_site: :lax
use SQRL::Rack::Middleware,
    stores: SQRL::Server::Memory.stores,
    host: "example.com",
    on_login: ->(env, identity, pending_login) { env["rack.session"]["user_id"] = identity.idk_b64 },
    after_login: "/"
```

The middleware owns `POST /sqrl/cli`, `GET /sqrl/status`, `GET /sqrl/callback` and
`GET /sqrl/sqrl.js`. Every other request receives `env["sqrl.server"]`, a facade with
`login_url`, `login_block`, `script_tag`, `qr_svg`, `identity`, `authenticated?` and
`logout!`. Without `on_login`, the identity key is stored in the session under
`sqrl.identity` and `authenticated?` reads it back.

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
`sqrl_authenticated?`, `current_sqrl_identity`, `sqrl_logout!`. `enable :sessions` must
come before `register`.

## Notes

- Sinatra's `Rack::Protection` lets the token-less SQRL POST through (the request has no
  Referer and no session-changing effect at the app level); the middleware rebuilds the
  form body if a protection layer consumed `rack.input`.
- URLs are always `sqrl://` (HTTPS). For local development either terminate TLS in front
  of the app (the examples and the integration suite use a self-signed certificate) or opt
  into the non-standard loopback-only plain-HTTP mode with `insecure_http: true`, which
  only the browser extension's test flow understands.
