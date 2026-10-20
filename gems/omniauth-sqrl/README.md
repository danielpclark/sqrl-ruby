# omniauth-sqrl

An [OmniAuth](https://github.com/omniauth/omniauth) strategy for **SQRL** (Secure Quick
Reliable Login). Add the provider and your application gets password-less SQRL login with
the same `/auth/:provider` flow as every other OmniAuth strategy.

```ruby
# Gemfile
gem "omniauth-sqrl"

# config/initializers/omniauth.rb (Rails) or your Rack config
use OmniAuth::Builder do
  provider :sqrl,
           stores: SQRL::Rails::Stores.active_record,   # or SQRL::Server::Memory.stores for development
           host: "example.com"                          # the public host placed in sqrl:// URLs
end
```

## How it works

| Request | Handled by | Purpose |
| --- | --- | --- |
| `POST /auth/sqrl` | request phase | issues a login nut bound to the browser session and renders the login page (link, QR code, `sqrl.js`) |
| `POST /auth/sqrl/cli` | other phase | the SQRL client's protocol endpoint (`query`, `ident`, `disable`, `enable`, `remove`) |
| `GET /auth/sqrl/status` | other phase | cookie-bound JSON poll used by `sqrl.js` for logins from another device |
| `GET /auth/sqrl/sqrl.js` | other phase | the browser script |
| `GET /auth/sqrl/callback?t=TOKEN` | callback phase | Client Provided Session landing: the one-time token is claimed and the auth hash is built |
| `GET /auth/sqrl/callback` | callback phase | completion from the poller (the browser's own pending login) |

All of these are served by the OmniAuth middleware itself, so the SQRL endpoint never
reaches your controllers and needs no CSRF exemption.

## The auth hash

```ruby
request.env["omniauth.auth"]
# => {
#   "provider" => "sqrl",
#   "uid" => "<identity key, base64url>",
#   "info" => {},                      # SQRL carries no profile data; see the info: option
#   "credentials" => {},
#   "extra" => { "sqrl" => {
#     "idk" => "...", "suk" => "...", "vuk" => "...",
#     "created" => true,               # this ident created the account
#     "rekeyed_from" => nil,           # previous identity key when the account was re-keyed
#     "options" => { "sqrlonly" => false, "hardlock" => false },
#     "disabled" => false, "logins" => 1,
#     "via" => "cps",                  # or "poll"
#     "user_ref" => nil                # the ref given through link_user_ref:, if any
#   } }
# }
```

Failures redirect to `/auth/failure?message=…` with `invalid_credentials` (missing,
foreign, reused or expired token) or `sqrl_disabled`.

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `stores:` | process-wide in-memory stores (development only) | `SQRL::Server::Stores` (nuts, identities, pending logins) |
| `host:` | request host | host (with port) placed in `sqrl://` URLs |
| `insecure_http:` | `false` | loopback-only testing mode issuing `qrl://` (plain http) URLs; not part of SQRL, refused for other hosts |
| `poll_requires_ip_match:` | `false` | optional hardening: refuse poll (cookie) completions when the client's IP did not match the browser's |
| `path_extension:` | `nil` | `x=N` to scope identities to a path prefix |
| `nut_ttl:` / `cps_token_ttl:` | 300 / 60 seconds | lifetimes |
| `require_ip_match:` | `true` | refuse clients whose IP differs from the browser's unless they send `noiptest` |
| `ask:` / `sin:` | `nil` | `SQRL::Ask` (or callable) and secret-index challenge |
| `on_unknown_identity:` | `:create` | `:create`, `:link` (requires `link_user_ref:`) or `:refuse` |
| `link_user_ref:` | `nil` | callable `(env) -> ref` naming the signed-in user to link a new identity to |
| `login_block:` | `{}` | options of `SQRL::Rack::LoginBlock.render` (`qr:`, `link_text:`, `texts:`, …) |
| `title:` / `cancel_url:` | "Sign in with SQRL" / the origin | login page title and cancel link |
| `info:` | `nil` | callable `(identity) -> Hash` to fill `info` |
| `ip:` | `Rack::Request#ip` | callable resolving the client IP (trusted proxies) |
| `cli_path:` / `status_path:` / `script_path:` | under the provider prefix | endpoint paths |

## Devise

`devise-sqrl` gives Devise a native `:sqrl_authenticatable` module. If you prefer the
OmniAuth route, the strategy works with Devise's `:omniauthable` as usual:

```ruby
devise :database_authenticatable, :omniauthable, omniauth_providers: [:sqrl]
# config/initializers/devise.rb
config.omniauth :sqrl, stores: SQRL::Rails::Stores.active_record, host: "example.com"
```

and in `Users::OmniauthCallbacksController#sqrl`, find or create the user by
`request.env["omniauth.auth"]["uid"]`.

## Request-phase CSRF

OmniAuth 2 accepts only `POST` on `/auth/sqrl` and validates an authenticity token. Rails
applications keep using `omniauth-rails_csrf_protection`; a Sinatra application can render
`Rack::Protection::AuthenticityToken.token(session)` into the login form, as
`examples/omniauth-app` does. Nothing about SQRL requires disabling this protection.

## Test mode

`OmniAuth.config.test_mode = true` with `OmniAuth.config.mock_auth[:sqrl]` short-circuits
the flow exactly like any other strategy.

## Example and testing

[`examples/omniauth-app`](../../examples/omniauth-app) is a Sinatra application using the
strategy; the repository's integration suite boots it over HTTPS and runs the conformance
suite against it. `bundle exec rake spec:omniauth-sqrl` runs the strategy specs with
Rack::Test.

## License

MIT. See [LICENSE](LICENSE).
