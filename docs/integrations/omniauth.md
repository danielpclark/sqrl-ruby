# OmniAuth

Gem: `omniauth-sqrl`. Example: `examples/omniauth-app` (Sinatra + OmniAuth).

```ruby
use OmniAuth::Builder do
  provider :sqrl, stores: SQRL::Rails::Stores.active_record, host: "example.com"
end
```

- `POST /auth/sqrl` (the request phase) renders the login page. OmniAuth 2 requires POST and
  an authenticity token here: Rails apps get it from `omniauth-rails_csrf_protection`,
  Sinatra apps render `Rack::Protection::AuthenticityToken.token(session)` in the form.
- `POST /auth/sqrl/cli`, `GET /auth/sqrl/status`, `GET /auth/sqrl/refresh` and
  `GET /auth/sqrl/sqrl.js` are served by the strategy itself (OmniAuth's `other_phase`), so
  they never reach your controllers.
- `GET /auth/sqrl/callback` builds the auth hash: `uid` is the identity key (base64url),
  `info` is empty by design, and `extra["sqrl"]` carries `suk`, `vuk`, `created`,
  `rekeyed_from`, `options`, `disabled`, `via` (`cps` or `poll`) and `user_ref`.
- Failures: `invalid_credentials` (missing, reused, expired or foreign token) and
  `sqrl_disabled`.
- Account linking: pass `link_user_ref: ->(env) { ... }` and `on_unknown_identity: :link`.
- With Devise, `devise :omniauthable, omniauth_providers: [:sqrl]` works as with any other
  provider; `devise-sqrl` is the native alternative.

Always pass `stores:` in production. The default in-memory stores are process-wide and
exist only so development works without configuration. The strategy takes the same
protocol and hardening options as the Rack middleware (`require_ip_match`,
`poll_requires_ip_match`, `allowed_hosts`, `host_cache_limit`, `before_issue`,
`before_handle`, `prune_every`, `insecure_http`); the gem README lists them.
