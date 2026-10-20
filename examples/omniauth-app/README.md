# examples/omniauth-app

A Sinatra application that signs users in through OmniAuth's `:sqrl` provider
(`gems/omniauth-sqrl`).

```sh
bundle install
bin/dev            # http://localhost:9494/
```

Routes: `/` (home with a *Sign in with SQRL* button that POSTs to `/auth/sqrl`),
`/auth/sqrl` (OmniAuth request phase: the SQRL login page), `/auth/sqrl/cli` (the SQRL
endpoint), `/auth/sqrl/status` (poll), `/auth/sqrl/callback` (OmniAuth callback; the app
stores the `uid`), `/auth/failure`, `/protected` (403 until logged in), `POST /logout`.

OmniAuth 2 accepts only `POST` on `/auth/sqrl` and verifies an authenticity token; this
app renders the token from Rack::Protection (enabled by Sinatra's sessions) into the login
form, so the default protection stays on. Rails applications get the same from the
`omniauth-rails_csrf_protection` gem.

Environment: `SQRL_TLS_KEY`/`SQRL_TLS_CERT`, `SQRL_INSECURE_HTTP`, `SQRL_HOST` (public host placed in `sqrl://` URLs; defaults to the request
host), `SESSION_SECRET`, `SQRL_UNKNOWN_IDENTITY` (`create`, `link` or `refuse`),
`SQRL_IGNORE_IP`. Identities are kept in memory.

## TLS, `sqrl://` and plain http

SQRL login URLs are `sqrl://…` and always mean HTTPS, so a real SQRL client only works
when this app is served over TLS. `bin/dev` does that when `SQRL_TLS_KEY` and
`SQRL_TLS_CERT` point at a key and certificate (a self-signed one is fine locally; the
integration suite generates its own), or run it behind a TLS proxy. The integration specs
boot this app over HTTPS exactly that way.

`SQRL_INSECURE_HTTP=1` switches a loopback host to the non-standard `qrl://` (plain http)
form that GRC's early drafts defined and only the browser extension's local test flow still
accepts. It exists for that one purpose; it is not part of SQRL as specified and must never
be used outside local testing.
