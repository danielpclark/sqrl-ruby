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
`GET /users/sqrl/status`, `GET /users/sqrl/callback` and `GET /users/sqrl/sqrl.js`.
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
| `config.sqrl_on_unknown_identity` | `:create` | `:create` a resource, `:link` to the signed-in resource, or `:refuse` |
| `config.sqrl_create_resource` | `SQRL::Rails::UserFactory` | `(identity, mapping) -> resource` |
| `config.sqrl_remember_me` | `false` | set the remember-me cookie on SQRL sign-in |
| `config.sqrl_login_block` | `{}` | options for the rendered login block |
| `config.sqrl_failure_path` | the SQRL login page | where a refused callback redirects |

Protocol options (`host`, `require_ip_match`, `ask`, `sin`, stores) come from
`Rails.application.config.sqrl`, exactly as for `sqrl-rails`.

## Model API

`has_many :sqrl_identities`, `sqrl_identity_for(idk)`, `sqrl_linked?`,
`link_sqrl_identity!(identity)`, `unlink_sqrl_identity!(idk)`, and the class methods
`find_for_sqrl(identity)` and `create_for_sqrl!(identity)`. A user may hold several SQRL
identities (for example one per Alt-ID).
