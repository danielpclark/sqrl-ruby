# Roda example

A [Roda](https://roda.jeremyevans.net/) application signing users in with SQRL through
the `sqrl` plugin that ships inside the `sqrl-rack` gem.

```sh
bundle install
bin/dev            # http://localhost:9292
```

Routes: `/` (home, shows the login state), `/login` (the SQRL login block), `/protected`
(403 until logged in), `POST /logout`. The SQRL endpoint, status poll, callback and
script are served by the middleware under `/sqrl/`.

Environment: `SQRL_TLS_KEY`/`SQRL_TLS_CERT`, `SQRL_INSECURE_HTTP`, `SQRL_HOST` (public host for `sqrl://` URLs), `SQRL_ASK=1`, `SQRL_SIN=1`,
`SQRL_UNKNOWN_IDENTITY=create|link|refuse`, `SQRL_IGNORE_IP=1`.

Roda's own `sessions` plugin is not used because the SQRL middleware runs before the
routing tree; a Rack session middleware (`Rack::Session::Cookie` here) provides the
session the middleware binds logins to.

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
