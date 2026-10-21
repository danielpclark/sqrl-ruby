# Devise

Gem: `devise-sqrl` (builds on `sqrl-rails`). Example: `examples/devise-app`.

```ruby
# Gemfile
gem "devise-sqrl"

# app/models/user.rb
devise :database_authenticatable, :registerable, :sqrl_authenticatable
```

```sh
bin/rails generate devise:sqrl:install   # migration, initializer, model module, sessions/new partial
bin/rails db:migrate
```

`devise_for :users` then provides `GET /users/sqrl` (a stand-alone login page),
`POST /users/sqrl/cli` (the SQRL endpoint, exempt from forgery protection),
`GET /users/sqrl/status`, `GET /users/sqrl/callback`, `GET /users/sqrl/refresh`,
`GET /users/sqrl/sqrl.js`, and `GET /users/sqrl/identities` with
`DELETE /users/sqrl/identities/:id` for managing linked identities.
The generator appends `<%= render "devise/shared/sqrl", resource_name: resource_name %>`
to `devise/sessions/new.html.erb`, so the password form and the SQRL block live on the
same page.

## How sign-in happens

The callback runs the `:sqrl_authenticatable` Warden strategy, which claims the one-time
CPS token (or the browser's own pending login after a poll), resolves the resource through
`find_for_sqrl`, applies the unknown-identity policy, checks `active_for_authentication?`,
and finishes with `sign_in_and_redirect(resource, event: :authentication)`. Trackable,
rememberable and the other Devise hooks therefore behave exactly as for a password login.

## Options (`config/initializers/devise_sqrl.rb`)

| Option | Default | Meaning |
| --- | --- | --- |
| `config.sqrl_on_unknown_identity` | `nil` (defers to `config.sqrl.on_unknown_identity`, `:create`) | `:create` a resource, `:link` to the signed-in resource, or `:refuse` |
| `config.sqrl_create_resource` | `SQRL::Rails::UserFactory` | `(identity, resource_class) -> resource` |
| `config.sqrl_remember_me` | `false` | set the remember-me cookie on SQRL sign-in |
| `config.sqrl_login_block` | `{}` | options for the rendered login block |
| `config.sqrl_failure_path` | the SQRL login page | where a refused callback redirects |
| `config.sqrl_only_blocked_strategies` | `[:database_authenticatable]` | Warden strategies refused for `sqrlonly` users |

Protocol options (`host`, `insecure_http`, `require_ip_match`, `poll_requires_ip_match`,
`ask`, `sin`, `rate_limit`, hooks, stores) come from `Rails.application.config.sqrl`,
exactly as for `sqrl-rails`.

## Account policies

A user whose identity asked for `sqrlonly` can no longer sign in through Devise's password
strategy (`devise.failure.sqrl_only`); one whose identity asked for `hardlock` cannot
request or perform a password reset (`errors.messages.sqrl_hard_locked`). SQRL logins,
remember-me cookies and restored sessions are unaffected.

## Model API

`has_many :sqrl_identities`, `sqrl_identity_for(idk)`, `sqrl_linked?`,
`link_sqrl_identity!(identity)`, `unlink_sqrl_identity!(idk)`, and the class methods
`find_for_sqrl(identity)` and `create_for_sqrl!(identity)`. A user may hold several SQRL
identities (for example one per Alt-ID).
