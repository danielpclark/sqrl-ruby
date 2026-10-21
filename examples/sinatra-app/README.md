# examples/sinatra-app

A Sinatra application using `register Sinatra::SQRL` and its view helpers.

```sh
bundle install
bin/dev            # http://localhost:9393/
```

Routes: `/`, `/login`, `/protected` (403 until logged in), `POST /logout`. The same
environment variables as `examples/rack-app` apply (`SQRL_HOST`, `SESSION_SECRET`,
`SQRL_UNKNOWN_IDENTITY`, `SQRL_IGNORE_IP`, `SQRL_ASK`, `SQRL_SIN`,
`SQRL_TLS_KEY`/`SQRL_TLS_CERT`, `SQRL_INSECURE_HTTP`). Identities are kept in memory.

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
