# sqrl-rack

SQRL login for Rack applications and Sinatra: a middleware that mounts the SQRL endpoint,
the browser's status poll and the login callback; a Sinatra extension with view helpers;
the browser-side `sqrl.js`; and QR code rendering. Built on
[`sqrl-core`](../sqrl-core).

## Rack

```ruby
require "rack/session"
require "sqrl/rack"

use Rack::Session::Cookie, secret: ENV.fetch("SESSION_SECRET"), same_site: :lax
use SQRL::Rack::Middleware,
    stores: SQRL::Server::Memory.stores,     # swap for a persistent implementation
    host: "example.com",                     # the public host that ends up in sqrl:// URLs
    on_login: ->(env, identity, pending_login) { env["rack.session"]["user_id"] = identity.idk_b64 },
    after_login: "/"

run ->(env) {
  sqrl = env["sqrl.server"]
  [200, { "content-type" => "text/html" }, [sqrl.login_block]]
}
```

The middleware serves `POST /sqrl/cli` (the SQRL protocol endpoint), `GET /sqrl/status`
(cookie-bound JSON poll), `GET /sqrl/callback` (login completion, with or without a CPS
token) and `GET /sqrl/sqrl.js`. Everything else gets `env["sqrl.server"]`, a
`SQRL::Rack::Facade` with `login_url`, `login_block`, `script_tag`, `qr_svg`,
`identity`, `authenticated?` and `logout!`.

Every `SQRL::Server::Config` option is accepted (`on_unknown_identity`, `ask`, `sin`,
`require_ip_match`, `nut_ttl`, `cps_token_ttl`, ...). Without `host:` the request host is
used, and plain-http loopback requests get `qrl://` URLs for development.

## Sinatra

```ruby
require "sinatra/sqrl"

class App < Sinatra::Base
  enable :sessions
  register Sinatra::SQRL
  set :sqrl, host: "example.com", stores: SQRL::Server::Memory.stores

  sqrl_on_login { |identity, env| env["rack.session"]["user"] = identity.idk_b64 }

  get("/login") { erb :login }   # <%= sqrl_login_block %>
  get("/")      { sqrl_authenticated? ? "Hello #{current_sqrl_identity.idk_b64}" : redirect("/login") }
  post("/logout") { sqrl_logout!; redirect "/" }
end
```

Helpers: `sqrl_login_url`, `sqrl_qr_svg`, `sqrl_script_tag`, `sqrl_login_block`,
`sqrl_authenticated?`, `current_sqrl_identity`, `sqrl_logout!`, and `sqrl` (the facade).

## How a login completes

1. The login page calls `login_url`, which issues a nut and stores a pending-login id in
   the browser session; `login_block` renders the `sqrl://` link, the QR code and
   `sqrl.js`.
2. The SQRL client POSTs `query` then `ident` to `/sqrl/cli`.
3. Same device (CPS): the client receives a one-time `url=` and sends the browser to
   `/sqrl/callback?t=TOKEN`. The token is claimed once and must belong to the pending
   login in that browser's session.
4. Other device: `sqrl.js` polls `/sqrl/status`; once authenticated it navigates to
   `/sqrl/callback`, which completes the browser's own pending login once.
5. The middleware stores the identity in the session, runs `on_login`, and redirects to the
   pending login's `return_to` or `after_login`.

See [`examples/rack-app`](../../examples/rack-app) and
[`examples/sinatra-app`](../../examples/sinatra-app).
