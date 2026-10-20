# examples/rack-app

The smallest possible SQRL-enabled site: plain Rack, `Rack::Session::Cookie` and
`SQRL::Rack::Middleware`. It proves the middleware alone is enough.

```sh
bundle install
bin/dev            # http://localhost:9292/
```

Routes: `/` (home, shows login state), `/login` (QR, link and `sqrl.js`), `/protected`
(403 until logged in), `POST /logout`. On `localhost` over plain http the middleware

Environment: `SQRL_TLS_KEY`/`SQRL_TLS_CERT`, `SQRL_INSECURE_HTTP`, `SQRL_HOST` (public host in `sqrl://` URLs), `SESSION_SECRET`,
`SQRL_UNKNOWN_IDENTITY` (`create`, `link` or `refuse`), `SQRL_IGNORE_IP` (set to disable
the IP match check, for proxies in development). Identities live in memory and vanish
when the process stops.

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
