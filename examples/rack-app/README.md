# examples/rack-app

The smallest possible SQRL-enabled site: plain Rack, `Rack::Session::Cookie` and
`SQRL::Rack::Middleware`. It proves the middleware alone is enough.

```sh
bundle install
bin/dev            # http://localhost:9292/
```

Routes: `/` (home, shows login state), `/login` (QR, link and `sqrl.js`), `/protected`
(403 until logged in), `POST /logout`. On `localhost` over plain http the middleware
issues `qrl://` URLs, which SQRL clients accept for loopback hosts only.

Environment: `SQRL_HOST` (public host in `sqrl://` URLs), `SESSION_SECRET`,
`SQRL_UNKNOWN_IDENTITY` (`create`, `link` or `refuse`), `SQRL_IGNORE_IP` (set to disable
the IP match check, for proxies in development). Identities live in memory and vanish
when the process stops.
