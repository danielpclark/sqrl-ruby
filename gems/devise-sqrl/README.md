# devise-sqrl

SQRL (Secure Quick Reliable Login) for [Devise](https://github.com/heartcombo/devise):
one module, and your Devise models can sign in with SQRL next to (or instead of) a
password.

```ruby
# Gemfile
gem "devise-sqrl"
```

```sh
bin/rails generate devise:sqrl:install        # or: devise:sqrl:install Admin
bin/rails db:migrate
```

The generator

- copies the `sqrl_identities` / `sqrl_nuts` / `sqrl_pending_logins` migration (shared
  with [sqrl-rails](../sqrl-rails)),
- adds `:sqrl_authenticatable` to the model's `devise` call,
- writes `config/initializers/devise_sqrl.rb`,
- appends `<%= render "devise/shared/sqrl", resource_name: resource_name %>` to
  `app/views/devise/sessions/new.html.erb` when you have generated Devise's views.

```ruby
class User < ApplicationRecord
  devise :database_authenticatable, :registerable, :rememberable, :sqrl_authenticatable
end
```

`devise_for :users` then routes:

| Route | Purpose |
| --- | --- |
| `GET  /users/sqrl` | stand-alone SQRL login page (`new_user_sqrl_path`); `.json` gives the URL |
| `POST /users/sqrl/cli` | the SQRL protocol endpoint (no CSRF token: authenticated by signatures) |
| `GET  /users/sqrl/status` | cookie-bound poll for logins made from another device |
| `GET  /users/sqrl/callback` | login completion (CPS `url=` or poll), signs the user in |
| `GET  /users/sqrl/sqrl.js` | the browser-side script |
| `GET  /users/sqrl/refresh` | a fresh login URL for the page (JSON) |
| `GET  /users/sqrl/identities` | the signed-in user's identities, with Unlink |
| `DELETE /users/sqrl/identities/:id` | unlink one identity |

## How a login completes

The callback runs the `:sqrl_authenticatable` Warden strategy, which claims the one-time
CPS token (or the browser's own pending login after the poller saw it authenticated),
finds the resource the identity belongs to, applies the unknown-identity policy, checks
`active_for_authentication?` and calls `success!`. The controller then does
`sign_in_and_redirect(resource_name, resource, event: :authentication)`, so
`:trackable`, `:rememberable`, `:confirmable`, `:lockable` and your
`after_sign_in_path_for` all behave exactly as with a password login.

## Views

Inside your own sign-in page:

```erb
<%= render "devise/shared/sqrl", resource_name: resource_name %>
```

or directly:

```erb
<%= sqrl_login_block_for(resource_name, return_to: "/dashboard", link_text: "Use SQRL") %>
```

`sqrl_login_url_for(:user)` and `sqrl_script_tag_for(:user)` are available for custom
markup. The markup follows the `sqrl.js` contract of `sqrl-rack`.

## Configuration

Protocol and storage settings live in `Rails.application.config.sqrl` (see
[sqrl-rails](../sqrl-rails): `host`, `insecure_http`, `require_ip_match`, `poll_requires_ip_match`, `nut_ttl`, `cps_token_ttl`,
`ask`, `sin`, `stores`). The Devise-specific options go in `Devise.setup`:

```ruby
Devise.setup do |config|
  config.sqrl_on_unknown_identity = :create   # :create, :link or :refuse; nil (default) defers to config.sqrl (:create)
  config.sqrl_create_resource = ->(identity, klass) { klass.new(email: "...", password: SecureRandom.hex(32)) }
  config.sqrl_remember_me = false             # treat SQRL logins as "remember me"
  config.sqrl_login_block = { link_text: "Sign in with SQRL" }
  config.sqrl_failure_path = nil              # default: the scope's SQRL login page
  config.sqrl_only_blocked_strategies = [:database_authenticatable]   # refused for sqrlonly users
end
```

- `:create` builds a record with `SQRL::Rails::UserFactory` (placeholder email, random
  password, so `:validatable` passes) and links the identity to it.
- `:link` only accepts unknown identities while a user of that scope is signed in, and
  attaches the identity to them (`user.link_sqrl_identity!`). Use it for "add SQRL to my
  account" pages.
- `:refuse` rejects unknown identities at the protocol level.

Model API: `user.sqrl_identities`, `user.sqrl_linked?`, `user.sqrl_identity_for(idk)`,
`user.link_sqrl_identity!(identity)`, `user.unlink_sqrl_identity!(idk)`,
`User.find_for_sqrl(identity)`, `User.create_for_sqrl!(identity)`.

Failure messages are Devise translations under `devise.failure`: `sqrl_invalid`,
`sqrl_disabled`, `sqrl_unknown`, `sqrl_link_required`.

## Account policies: `sqrlonly` and `hardlock`

An identity that asked for `sqrlonly` makes `user.sqrl_only?` true: Devise's password
strategy (and any strategy in `Devise.sqrl_only_blocked_strategies`) is then refused
with the `devise.failure.sqrl_only` message, while SQRL logins, remember-me cookies and
restored sessions keep working. An identity that asked for `hardlock` makes
`user.hard_locked?` true: `send_reset_password_instructions` and `reset_password`
(`:recoverable`) add the `errors.messages.sqrl_hard_locked` error instead of acting.

## Identity management

`GET /users/sqrl/identities` (`identities_user_sqrl_path`) lists the signed-in user's
identities with an Unlink button (`DELETE /users/sqrl/identities/:id`,
`unlink_identity_user_sqrl_path`). Unlinking calls `unlink_sqrl_identity!`.

## `ask`, `sin`, hooks and the refresh route

Protocol settings come from `Rails.application.config.sqrl` exactly as in `sqrl-rails`:
`ask` (with `accept:` and `ask_deny_button`), `sin`, `rate_limit`, `before_issue`,
`before_handle`, `allowed_hosts`, `host_cache_limit`, `prune_every`. A hook that raises
`SQRL::Server::RateLimited` gets a 429; a disallowed host a 400. `GET /users/sqrl/refresh`
hands the page a fresh login URL when a nut expires.

## Custom controller

```ruby
devise_for :users, controllers: { sqrl: "users/sqrl" }

class Users::SQRLController < Devise::SQRLController
  def callback
    super
  end
end
```

## OmniAuth instead?

If you already route social logins through OmniAuth, `devise :omniauthable,
omniauth_providers: [:sqrl]` with the [omniauth-sqrl](../omniauth-sqrl) gem works too.
`devise-sqrl` is the lighter path: no OmniAuth middleware, and the SQRL endpoint lives
under the Devise scope.

## Testing your app

The [sqrl-client](../sqrl-client) gem logs in without a browser:

```ruby
transport = SQRL::Client::Transport.new(ca_file: "cert.pem")   # the certificate you gave bin/dev via SQRL_TLS_CERT
agent  = SQRL::Client::Agent.new(identity: SQRL::Client::Identity.ephemeral, transport: transport)
result = agent.login("https://127.0.0.1:3000/users/sign_in")
result.authenticated? # => true; result.cookies carries the Devise session
```

Against a server started with `SQRL_INSECURE_HTTP=1` (plain http on localhost), use
`Agent.new(identity:, insecure: true)` and an `http://` URL instead.

See [`examples/devise-app`](../../examples/devise-app) for a complete application;
`bundle exec rake spec:devise-sqrl` runs this gem's specs against an in-gem dummy app.

## License

MIT. See [LICENSE](LICENSE).
