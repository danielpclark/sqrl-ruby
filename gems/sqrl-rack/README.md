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
extension (`sqrl`, `sqrl_login_block`, `sqrl_login_url`, `sqrl_qr_svg`, `sqrl_script_tag`,
`sqrl_authenticated?`, `current_sqrl_identity`, `sqrl_logout!`, class-level
`sqrl_on_login`). The session must come from a Rack session middleware added with `use`
before the plugin; Roda's own `sessions` plugin lives inside the routing tree, after the
middleware, and cannot be used for this. The `roda` gem is not a dependency of
`sqrl-rack`; add it yourself. See [`examples/roda-app`](../../examples/roda-app).

## Hosts

The host in a `sqrl://` URL is the string every identity key is derived from, so configure
it (`host: "example.com"`) in production. Without it the middleware uses the request's
`Host` header: it warns once, accepts only hosts matching `allowed_hosts:` when that list
is given (strings, with or without port, or regexps), and keeps per-host state for at most
`host_cache_limit:` (default 16) distinct hosts; requests for further hosts get `400`.

```ruby
use SQRL::Rack::Middleware, stores: stores, allowed_hosts: ["example.com", /\A[a-z0-9-]+\.example\.com\z/]
```

Plain-http loopback requests (`localhost`, `127.0.0.0/8`, `[::1]`) get `qrl://` URLs for
development; anything else is always `sqrl://`.

## Rate limiting and pruning

Two hooks let you refuse abusive traffic before any state is written. Raise
`SQRL::Server::RateLimited` (optionally with `retry_after:`) and the middleware answers
`429`: the SQRL client sees it on `POST /sqrl/cli`, the page's refresh call gets a JSON
error, and `login_block` degrades to a short "temporarily unavailable" message.

```ruby
use SQRL::Rack::Middleware,
    stores: stores, host: "example.com",
    before_issue: ->(ctx) { raise SQRL::Server::RateLimited.new(retry_after: 30) if LoginPages.too_many?(ctx[:ip]) },
    before_handle: ->(ctx) { raise SQRL::Server::RateLimited if ctx[:phase] == :request && Cli.too_many?(ctx[:ip]) },
    prune_every: 500      # run Handler#prune! every 500 requests (default 1000, nil to disable)
```

`before_handle` runs twice per POST: once as soon as the request arrives
(`phase: :request`, with `ip` and `nut`) and again when the command is known
(`phase: :command`, adding `command` and `idk`). With [Rack::Attack](https://github.com/rack/rack-attack)
the same limits can sit in front of the middleware instead:

```ruby
Rack::Attack.throttle("sqrl/cli", limit: 60, period: 60) { |req| req.ip if req.post? && req.path == "/sqrl/cli" }
Rack::Attack.throttle("sqrl/login-page", limit: 20, period: 60) { |req| req.ip if req.get? && req.path == "/login" }
```

Expired nuts and pending logins are deleted opportunistically every `prune_every`
requests; call `handler.prune!` from a scheduler if you would rather control it.

## The browser script

`sqrl.js` probes for a local client on `localhost:25519`, polls `/sqrl/status` with
exponential back-off after errors (capped at 10 s), and when the server reports the login
code as expired shows a "Get a new code" button that calls `GET /sqrl/refresh`. That
endpoint issues a new pending login and nut for the browser session and returns
`{"sqrl_url", "status_url", "refresh_url", "qr_svg"}`, which the script swaps into the
page without a reload (`SQRL.refresh(rootElement)` does the same from your code). The root
element dispatches `sqrl:cps-detected`, `sqrl:authenticated` (`detail.next`),
`sqrl:expired`, `sqrl:refreshed` (`detail.sqrlUrl`) and `sqrl:error` events.

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
