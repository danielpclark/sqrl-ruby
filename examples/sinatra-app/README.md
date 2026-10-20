# examples/sinatra-app

A Sinatra application using `register Sinatra::SQRL` and its view helpers.

```sh
bundle install
bin/dev            # http://localhost:9393/
```

Routes: `/`, `/login`, `/protected` (403 until logged in), `POST /logout`. The same
environment variables as `examples/rack-app` apply (`SQRL_HOST`, `SESSION_SECRET`,
`SQRL_UNKNOWN_IDENTITY`, `SQRL_IGNORE_IP`). Identities are kept in memory.
