# Integration guides

Each guide is short on purpose: the gem READMEs hold the option tables and the example
applications hold runnable code.

| Framework | Guide | Gem README | Example application |
| --- | --- | --- | --- |
| Rack, Sinatra and Roda | [rack-sinatra.md](rack-sinatra.md) | [gems/sqrl-rack](../../gems/sqrl-rack/README.md) | [examples/rack-app](../../examples/rack-app), [examples/sinatra-app](../../examples/sinatra-app), [examples/roda-app](../../examples/roda-app) |
| OmniAuth | [omniauth.md](omniauth.md) | [gems/omniauth-sqrl](../../gems/omniauth-sqrl/README.md) | [examples/omniauth-app](../../examples/omniauth-app) |
| Rails and Rails 8 Authentication | [rails.md](rails.md) | [gems/sqrl-rails](../../gems/sqrl-rails/README.md) | [examples/rails-auth-app](../../examples/rails-auth-app) |
| Devise | [devise.md](devise.md) | [gems/devise-sqrl](../../gems/devise-sqrl/README.md) | [examples/devise-app](../../examples/devise-app) |
| Bots and test suites | [client.md](client.md) | [gems/sqrl-client](../../gems/sqrl-client/README.md) | the integration specs under [spec/integration](../../spec/integration) |

## How every integration completes a login

1. The login page issues a `sqrl://host/<endpoint>?nut=…` URL. The nut is single use and
   bound to a *pending login* whose id is kept in the browser's session cookie.
2. The SQRL client (a phone app, the browser extension, or `sqrl-client`) POSTs a signed
   `query` and then `ident` to the endpoint. The server verifies the signatures, the echoed
   `server=` value, the IP and the identity binding, then marks the pending login
   authenticated.
3. Same device (Client Provided Session): the server hands the client a one-time `url=`
   carrying a token; the client sends the browser there; the token is claimed once and must
   belong to the pending login in that browser's session.
4. Another device: `sqrl.js` polls the cookie-bound status endpoint and, once authenticated,
   navigates to the callback, which completes that browser's own pending login once.
5. The framework adapter turns the authenticated identity into its own notion of a signed-in
   user: a session key (Rack, Sinatra, Roda), an auth hash (OmniAuth),
   `start_new_session_for` (Rails 8), or `sign_in` (Devise). Unknown identities create an
   account, link to the signed-in user, or are refused, according to `on_unknown_identity`.

When a nut expires before the user acts, the page's "Get a new code" button calls the
refresh endpoint and swaps in a fresh URL and QR code without a reload.

## Deployment notes that apply everywhere

- Set the public `host` explicitly in production; it is the string identities are derived
  from, so a change breaks every existing SQRL association.
- Use a persistent, atomic store in production: ActiveRecord or `ActiveSupport::Cache`
  (`sqrl-rails`), Redis (`SQRL::Server::Redis` in `sqrl-core`), or your own implementation
  of the three interfaces in `SQRL::Server`. The in-memory stores are for development and
  tests.
- Serve HTTPS. SQRL URLs are always `sqrl://`; plain HTTP exists only as the loopback-only
  `insecure_http` testing mode.
- The SQRL endpoint is exempt from CSRF protection by design: it is authenticated by
  signatures. Nothing else is.
- Keep `require_ip_match` on. Clients behind a different egress than the browser must send
  `noiptest`, which the user has to opt into. `poll_requires_ip_match` is a separate,
  off-by-default hardening; see [docs/security.md](../security.md) before turning it on.
- Rate-limit the login page and the endpoint (`before_issue` / `before_handle` hooks,
  Rails `rate_limit`, or Rack::Attack).
- Prune expired nuts and pending logins: `prune_every` does it opportunistically;
  `sqrl:prune` (Rails) or `Handler#prune!` from a scheduler otherwise.
