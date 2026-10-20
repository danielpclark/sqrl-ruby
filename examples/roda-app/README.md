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

Environment: `SQRL_HOST` (public host for `sqrl://` URLs), `SQRL_ASK=1`, `SQRL_SIN=1`,
`SQRL_UNKNOWN_IDENTITY=create|link|refuse`, `SQRL_IGNORE_IP=1`.

Roda's own `sessions` plugin is not used because the SQRL middleware runs before the
routing tree; a Rack session middleware (`Rack::Session::Cookie` here) provides the
session the middleware binds logins to.
