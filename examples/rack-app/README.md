# examples/rack-app

The smallest possible SQRL-enabled site: plain Rack, `Rack::Session::Cookie` and
`SQRL::Rack::Middleware`. It proves the middleware alone is enough.

```sh
bundle install
bin/dev            # http://localhost:9292/
```

Routes: `/` (home, shows login state), `/login` (QR, link and `sqrl.js`), `/protected`
(403 until logged in), `POST /logout`. The middleware serves `/sqrl/cli`, `/sqrl/status`,
`/sqrl/callback`, `/sqrl/refresh` and `/sqrl/sqrl.js`.

Environment: `SQRL_TLS_KEY`/`SQRL_TLS_CERT`, `SQRL_INSECURE_HTTP`, `SQRL_HOST` (public host
in `sqrl://` URLs), `SESSION_SECRET`, `SQRL_UNKNOWN_IDENTITY` (`create`, `link` or
`refuse`), `SQRL_IGNORE_IP` (set to disable the IP match check, for proxies in
development), `SQRL_ASK=1` (pose an Allow/Deny question; Deny refuses the login),
`SQRL_SIN=1` (send a secret-index challenge). Identities live in memory and vanish when
the process stops.

## Logging in with the browser extension

Install the [SQRL Login extension](https://github.com/danielpclark/SQRL-extension) (Chrome
Web Store or Firefox Add-ons), create an identity, open the login page and click "Sign in
with SQRL". The extension needs either HTTPS (`SQRL_TLS_KEY`/`SQRL_TLS_CERT`; accept the
self-signed certificate in the browser once) or, on `localhost` only, `SQRL_INSECURE_HTTP=1`.

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
